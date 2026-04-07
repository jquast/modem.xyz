"""Discover new BBS and MUD servers via Shodan search.

Queries Shodan for known BBS/MUD software signatures, cross-references
against existing server lists, and saves new discoveries for moderation
review.
"""

import json
import os
import re
import socket
import subprocess
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .util import _HERE

_DISCOVERY_DIR = _HERE / 'nmap' / 'data' / 'shodan'

# Shodan search queries for BBS software.
# Combined queries to minimize Shodan API credits (1 credit per search).
BBS_QUERIES = [
    ('Synchronet OR Mystic OR MajorBBS OR Enigma OR WWIV OR BinkTermPHP', 'bbs'),
    ('BBS OR ATASCII OR PETSCII OR ATARI OR COMMODORE', 'bbs'),
]

# General queries for ANSI/terminal services — catches BBS, MUD, and
# other interesting telnet services by their escape sequences.
# Top 9 sequences covering 96% of ANSI banners, one per query.
GENERAL_QUERIES = [
    (r'\x1b[0m', 'general'),
    (r'\x1b[2J', 'general'),
    (r'\x1b[1;33m', 'general'),
    (r'\x1b[7z', 'general'),
    (r'\x1b[0;37m', 'general'),
    (r'\x1b[6n', 'general'),
    (r'\x1b[6z', 'general'),
    (r'\x1b[1m', 'general'),
]

MUD_QUERIES = [
    ('DikuMUD OR CircleMUD OR SMAUG OR FluffOS OR LPMud',
     'mud'),
    ('LambdaMOO OR PennMUSH OR TinyMUSH OR Pueblo',
     'mud'),
]


def _parse_server_list(path):
    """Parse a server list into a set of (host_lower, port) tuples.

    :param path: path to bbslist.txt or mudlist.txt
    :returns: set of (host, port) tuples, plus set of known IPs
    """
    entries = set()
    ips = set()
    if not os.path.isfile(path):
        return entries, ips
    with open(path) as f:
        for line in f:
            stripped = line.split('#')[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                host = parts[0].lower()
                entries.add(host)
                try:
                    socket.inet_aton(parts[0])
                    ips.add(parts[0])
                except OSError:
                    pass
    return entries, ips


def _shodan_search(query, limit=10000):
    """Run a Shodan search via download+parse and return results.

    Uses ``shodan download`` + ``shodan parse`` to handle large
    result sets that exceed the ``shodan search`` limit of 1000.

    :param query: Shodan search query string
    :param limit: maximum results to fetch (-1 for unlimited)
    :returns: list of dicts with ip, port, hostnames, banner
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        dl_path = os.path.join(tmpdir, 'results')
        gz_path = dl_path + '.json.gz'

        # Step 1: download.
        dl_cmd = [
            'shodan', 'download', '--limit', str(limit), dl_path, query,
        ]
        try:
            proc = subprocess.run(
                dl_cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            print("Error: 'shodan' CLI not found. Install with:"
                  " pip install shodan", file=sys.stderr)
            return []
        except subprocess.TimeoutExpired:
            print(f"Warning: Shodan download timed out for: {query}",
                  file=sys.stderr)
            return []

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            # Filter out pkg_resources deprecation noise.
            lines = [l for l in stderr.splitlines()
                     if 'pkg_resources' not in l and 'UserWarning' not in l
                     and 'import pkg' not in l and 'Refrain' not in l
                     and 'Setuptools' not in l]
            msg = '\n'.join(lines).strip()
            if msg:
                print(f"Warning: Shodan download error for '{query}':"
                      f" {msg}", file=sys.stderr)
            if not os.path.isfile(gz_path):
                return []

        if not os.path.isfile(gz_path):
            return []

        # Step 2: parse.
        parse_cmd = [
            'shodan', 'parse', '--fields', 'ip_str,port,hostnames,data',
            '--separator', '\t', gz_path,
        ]
        try:
            proc = subprocess.run(
                parse_cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            print(f"Warning: Shodan parse timed out for: {query}",
                  file=sys.stderr)
            return []

        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t', 3)
            if len(parts) < 2:
                continue
            ip = parts[0].strip()
            port = parts[1].strip()
            hostnames = parts[2].strip() if len(parts) > 2 else ''
            banner = parts[3].strip() if len(parts) > 3 else ''

            if not port.isdigit():
                continue

            hn_list = [h.strip().lower() for h in hostnames.split(';')
                       if h.strip()]

            results.append({
                'ip': ip,
                'port': int(port),
                'hostnames': hn_list,
                'banner': banner,
            })

        return results


def _best_hostname(ip, hostnames):
    """Pick the best hostname for a server entry.

    Prefers real domain names over ISP PTR records.

    :param ip: IP address
    :param hostnames: list of hostname strings
    :returns: best hostname or IP
    """
    _ISP_PATTERNS = [
        r'^\d+[-.].*\.(spectrum|comcast|verizon|frontier|sbcglobal)\.',
        r'\.static\.',
        r'^pool-',
        r'\.dsl\.',
        r'\.lightspeed\.',
        r'\.res\.',
        r'\.cpe\.',
        r'\.hsd\d',
        r'\.ip\.linodeusercontent\.',
        r'\.vultrusercontent\.',
        r'\.googleusercontent\.',
    ]
    real = [h for h in hostnames
            if not any(re.search(p, h) for p in _ISP_PATTERNS)]
    if real:
        return sorted(real, key=len)[0]
    if hostnames:
        return sorted(hostnames, key=len)[0]
    return ip


# Ports most commonly carrying telnet/rlogin/BBS traffic, in
# priority order.  Derived from banner-scan data analysis.
_TELNET_PORTS = [23, 2323, 513, 2002, 2003, 4000, 2300, 6800, 128,
                 6400, 24, 2525, 6502, 64000, 1337]


def _find_telnet_port(results_for_ip):
    """Find the most likely telnet port from results.

    :param results_for_ip: list of result dicts for one IP
    :returns: port number or 23
    """
    # Prefer explicit telnet banner.
    for r in results_for_ip:
        if 'Telnet connection from' in r['banner']:
            return r['port']
    # Try common telnet/rlogin ports in priority order.
    seen_ports = {r['port'] for r in results_for_ip}
    for p in _TELNET_PORTS:
        if p in seen_ports:
            return p
    return 23


def discover(queries, server_list_path, list_type):
    """Run Shodan searches and find new servers.

    :param queries: list of (query_string, label) tuples
    :param server_list_path: path to bbslist.txt or mudlist.txt
    :param list_type: 'bbs' or 'mud'
    :returns: (discoveries, stats) where discoveries is a list of
        dicts and stats is a summary dict
    """
    known_hosts, known_ips = _parse_server_list(server_list_path)
    print(f"  {list_type} list: {len(known_hosts)} known hosts",
          file=sys.stderr)

    # Collect all results by IP.
    all_by_ip = defaultdict(list)
    total_results = 0
    for query, label in queries:
        print(f"  Searching Shodan: {query} ...", file=sys.stderr)
        results = _shodan_search(query)
        print(f"    {len(results)} results", file=sys.stderr)
        total_results += len(results)
        for r in results:
            r['query_label'] = label
            all_by_ip[r['ip']].append(r)

    # Forward-resolve all known hostnames to IPs for dedup.
    from concurrent.futures import ThreadPoolExecutor

    hostnames_to_resolve = [h for h in known_hosts
                            if h not in known_ips]
    print(f"  Forward-resolving {len(hostnames_to_resolve)}"
          f" known hostnames ...", file=sys.stderr)

    def _fwd(hostname):
        try:
            return hostname, socket.gethostbyname(hostname)
        except (socket.herror, socket.gaierror, OSError):
            return hostname, None

    with ThreadPoolExecutor(max_workers=32) as pool:
        for hostname, ip in pool.map(_fwd, hostnames_to_resolve):
            if ip:
                known_ips.add(ip)

    # Reverse-resolve Shodan IPs to catch hostname matches.
    print(f"  Reverse-resolving {len(all_by_ip)} Shodan IPs ...",
          file=sys.stderr)

    def _rdns(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            return ip, hostname
        except (socket.herror, socket.gaierror, OSError):
            return ip, None

    with ThreadPoolExecutor(max_workers=32) as pool:
        for ip, hostname in pool.map(_rdns, all_by_ip):
            if hostname:
                all_by_ip[ip][0]['hostnames'].append(hostname)

    # Deduplicate and find new servers.
    discoveries = []
    already_known = 0

    for ip, results in sorted(all_by_ip.items()):
        # Collect all hostnames for this IP (including reverse DNS).
        all_hostnames = set()
        for r in results:
            all_hostnames.update(r['hostnames'])

        # Check if already known by IP, hostname, or reverse DNS.
        if ip in known_ips or ip.lower() in known_hosts:
            already_known += 1
            continue
        if all_hostnames & known_hosts:
            already_known += 1
            continue

        # Find best hostname and telnet port.
        best_host = _best_hostname(ip, sorted(all_hostnames))
        telnet_port = _find_telnet_port(results)

        # Collect software labels.
        sw_labels = sorted(set(r['query_label'] for r in results))

        # Extract version if available.
        version = ''
        for r in results:
            m = re.search(
                r'Version ([\d.]+[a-z]?)', r['banner'], re.IGNORECASE)
            if m:
                version = m.group(1)
                break

        # Prefer telnet port banner, then common BBS ports, then lowest.
        best_banner = ''
        for r in results:
            if r['port'] == telnet_port and r['banner']:
                best_banner = r['banner']
                break
        if not best_banner:
            for tp in _TELNET_PORTS:
                for r in results:
                    if r['port'] == tp and r['banner']:
                        best_banner = r['banner']
                        break
                if best_banner:
                    break
        if not best_banner:
            for r in sorted(results, key=lambda x: x['port']):
                if r['banner']:
                    best_banner = r['banner']
                    break

        discoveries.append({
            'host': best_host,
            'ip': ip,
            'port': telnet_port,
            'hostnames': sorted(all_hostnames),
            'software': ', '.join(sw_labels),
            'version': version,
            'ports_seen': sorted(set(r['port'] for r in results)),
            'banner': best_banner,
        })

    stats = {
        'queries': len(queries),
        'total_results': total_results,
        'unique_ips': len(all_by_ip),
        'already_known': already_known,
        'new': len(discoveries),
    }
    return discoveries, stats


_BANNER_NOISE = re.compile(
    r'HTTP/\d|nginx|apache|<html|text/html|'
    r'SSH-2\.0-OpenSSH|'
    r'SNMP:|RouterOS|MikroTik|PPTP:|'
    r'ESMTP|Exim\b|Postfix\b|Dovecot|'
    r'Microsoft RPC|Remote Desktop|'
    r'Broadcom.*BFC|Kaonmedia|'
    r'NPC Telnet permit|'
    r'telnet is not a secure|telnet service is disabled|'
    r'too many users|maximum number of telnet|'
    r'\\xc8\\x02|\\x16\\x03|'
    r'Satisfactory Server|Minecraft Server|'
    r'Red Hat.*Enigma\)|'
    r'NetBIOS Response|'
    r'Resolver name:|'
    r'LDAP:',
    re.IGNORECASE,
)


def save_discoveries(discoveries, list_type):
    """Save discoveries to a timestamped file.

    :param discoveries: list of discovery dicts
    :param list_type: 'bbs' or 'mud'
    :returns: path to saved file
    """
    # Pre-filter obvious non-telnet noise.
    filtered = [d for d in discoveries
                if not _BANNER_NOISE.search(d.get('banner', ''))]

    os.makedirs(_DISCOVERY_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run_id = str(uuid.uuid4())[:8]
    filename = f'{timestamp}-{list_type}-{run_id}.txt'
    path = _DISCOVERY_DIR / filename

    with open(path, 'w') as f:
        f.write(f'# Shodan discovery: {list_type}\n')
        f.write(f'# Date: {timestamp}\n')
        f.write(f'# Entries: {len(filtered)}\n')
        f.write(f'# Format: host port  # banner\n')
        for d in sorted(filtered, key=lambda x: x['host']):
            # Truncate banner, strip newlines for single-line comment.
            banner = d.get('banner', '')
            banner = banner.replace('\r\n', ' ').replace('\n', ' ')
            banner = banner.replace('\r', ' ').replace('#', '')
            if len(banner) > 120:
                banner = banner[:117] + '...'
            comment = f"  # {banner}" if banner else ''
            f.write(f"{d['host']} {d['port']}{comment}\n")

    return str(path)


def list_pending():
    """List pending discovery files.

    :returns: list of (path, list_type, count, date) tuples
    """
    if not _DISCOVERY_DIR.is_dir():
        return []
    pending = []
    for f in sorted(_DISCOVERY_DIR.glob('*.txt')):
        list_type = 'unknown'
        count = 0
        date = ''
        if '-bbs-' in f.name:
            list_type = 'bbs'
        elif '-mud' in f.name:
            list_type = 'mud'
        with open(f) as fh:
            for line in fh:
                if line.startswith('# Date:'):
                    date = line.split(':', 1)[1].strip()
                elif line.startswith('# Entries:'):
                    count = int(line.split(':', 1)[1].strip())
                elif not line.startswith('#') and line.strip():
                    if count == 0:
                        count += 1
        pending.append((str(f), list_type, count, date))
    return pending


def load_discovery_file(path):
    """Load entries from a discovery file.

    :param path: path to discovery file
    :returns: list of (host, port, comment) tuples
    """
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            comment = ''
            if '#' in line:
                line, comment = line.split('#', 1)
                comment = comment.strip()
                line = line.strip()
            parts = line.split()
            if len(parts) >= 2:
                entries.append((parts[0], parts[1], comment))
    return entries
