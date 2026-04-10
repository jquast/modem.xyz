"""Discover new BBS/MUD servers from nmap banner-scan chunk XMLs.

Reads completed nmap banner-scan chunks, identifies hosts with
telnet/rlogin-like banners, cross-references against existing server
lists, and categorizes new discoveries as MUD or BBS.
"""

import glob
import os
import re
import socket
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from .util import _HERE

_CHUNK_DIR = _HERE / 'nmap' / 'data' / 'banner-scan' / 'chunks'

# Telnet IAC patterns (nmap stores as escaped strings).
_IAC_RE = re.compile(
    r'\\xFF\\xF[BCDE]|\\xff\\xf[bcde]',
)

# ANSI escape sequences.
_ANSI_RE = re.compile(r'\\x1[Bb]\[|\\x1[Bb]\(')

# RLogin indicators.
_RLOGIN_RE = re.compile(
    r'\\x00\\x0D\\x0A|'
    r'Expected RLogin|Failed to detect protocol|'
    r'EMSI_|'
    r'\\x00$',
)

# Non-interactive protocols — exclude before BBS/MUD keyword checks so that
# hostnames containing BBS/MUD words (e.g. "dragon" in "dragons-exodus.net")
# do not cause false positives.
_NONTELNET_RE = re.compile(
    r'^SSH-|'
    r'^\\x80|'
    r'^220[ -]|'
    r'^20[01] |'
    r'NOTICE \* :\*\*\*|'
    r'^\+OK |'
    r'^\* OK |'
    r'^HTTP/|'
    r'^<!DOCTYPE|'
    r'^<html',
    re.IGNORECASE,
)

# Hex escape sequences as nmap stores them (e.g. \xFF\xFB).
# Stripped before the PETSCII inverted-case check so that hex digit letters
# (x, F, B, C, D …) don't spuriously satisfy the case-alternation heuristic.
_HEX_ESC_RE = re.compile(r'\\x[0-9A-Fa-f]{2}')

# MUD keywords (case-insensitive).
_MUD_RE = re.compile(
    r'\bmud\b|\bmoo\b|\bmush\b|\bmuck\b|talker|'
    r'dikumud|circlemud|smaug|fluffos|lpmud|'
    r'lambdamoo|pennmush|tinymush|pueblo|'
    r'hit.?point|mana\b|combat|guild|'
    r'dragon|quest|realm|kingdom|dungeon|'
    r'character.*class|choose.*race|'
    r'connect.*guest|who\b.*online|'
    r'jeremy.elson|hans.henrik|'
    r'ANSI.*\(Y/n\)|Colour.*\(Y/n\)',
    re.IGNORECASE,
)

# BBS keywords (case-insensitive).
_BBS_RE = re.compile(
    r'\bbbs\b|bulletin.board|sysop|'
    r'synchronet|mystic|enigma½|majorbbs|wwiv|citadel|'
    r'wildcat|talisman|fidonet|emsi_|'
    r'petscii|commodore|retroterm|atascii|'
    r'message.area|file.area|door|'
    r'Telnet connection from',
    re.IGNORECASE,
)


def _parse_lists(*paths):
    """Parse server lists and return known hosts and IPs.

    :param paths: paths to server list files
    :returns: (known_hosts, known_ips) sets
    """
    hosts = set()
    ips = set()
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            for line in f:
                stripped = line.split('#')[0].strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if parts:
                    hosts.add(parts[0].lower())
                    try:
                        socket.inet_aton(parts[0])
                        ips.add(parts[0])
                    except OSError:
                        pass
    return hosts, ips


def _is_telnet_service(banner):
    """Check if a banner indicates a telnet/rlogin interactive service.

    :param banner: nmap banner string
    :returns: True if it looks like telnet/rlogin/interactive
    """
    # Hard exclusion: clear non-interactive protocol signatures must win even
    # when BBS/MUD keywords appear in the hostname (e.g. "dragon" in a domain).
    if _NONTELNET_RE.search(banner):
        return False
    if _IAC_RE.search(banner):
        return True
    if _ANSI_RE.search(banner):
        return True
    if _RLOGIN_RE.search(banner):
        return True
    # BBS/MUD software names are a strong signal.
    if _BBS_RE.search(banner):
        return True
    if _MUD_RE.search(banner):
        return True
    return False


def _classify(banner, port, hostname=''):
    """Classify a service as 'mud', 'bbs', or 'other'.

    :param banner: nmap banner string
    :param port: port number
    :param hostname: best hostname for the host (used as a tiebreaker)
    :returns: 'mud', 'bbs', or 'other'
    """
    if _MUD_RE.search(banner):
        return 'mud'
    if _BBS_RE.search(banner):
        return 'bbs'
    # "bbs" in the hostname is a strong signal even without banner keywords.
    if re.search(r'\bbbs\b', hostname, re.IGNORECASE):
        return 'bbs'
    if port == 4000:
        return 'mud'
    # PETSCII ports are BBS.
    if port in (64, 128):
        return 'bbs'
    # Inverted case = PETSCII.  Strip hex escape sequences first so that
    # nmap-escaped bytes like \xFF\xFB don't contribute spurious letters.
    clean = _HEX_ESC_RE.sub('', banner)
    alpha = ''.join(ch for ch in clean if ch.isalpha())
    if len(alpha) >= 4:
        lower_upper = sum(1 for i, ch in enumerate(alpha[:-1])
                          if ch.islower() and alpha[i + 1].isupper())
        upper_lower = sum(1 for i, ch in enumerate(alpha[:-1])
                          if ch.isupper() and alpha[i + 1].islower())
        if lower_upper > upper_lower and lower_upper >= 2:
            return 'bbs'
    return 'other'


def _guess_encoding(banner, port):
    """Guess encoding for a BBS service entry.

    Only call for BBS candidates; MUD services do not use PETSCII/ATASCII.

    :param banner: nmap banner string
    :param port: port number
    :returns: encoding string or None
    """
    if port == 64:
        return 'petscii 40'
    if port == 128:
        return 'petscii 80'
    bl = banner.lower()
    if 'petscii' in bl or '\\x0e\\x0d' in bl:
        return 'petscii'
    # Inverted case = PETSCII.  Strip hex escape sequences first.
    clean = _HEX_ESC_RE.sub('', banner)
    alpha = ''.join(ch for ch in clean if ch.isalpha())
    if len(alpha) >= 4:
        lower_upper = sum(1 for i, ch in enumerate(alpha[:-1])
                          if ch.islower() and alpha[i + 1].isupper())
        upper_lower = sum(1 for i, ch in enumerate(alpha[:-1])
                          if ch.isupper() and alpha[i + 1].islower())
        if lower_upper > upper_lower and lower_upper >= 2:
            return 'petscii'
    if '\\x9b' in bl:
        return 'atascii'
    return None


def _parse_known_pairs(*paths):
    """Parse server lists and return known (host, port) pairs.

    :param paths: paths to server list files
    :returns: set of (host_lower, port_int) tuples
    """
    pairs = set()
    for path in paths:
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            for line in f:
                stripped = line.split('#')[0].strip()
                if not stripped:
                    continue
                parts = stripped.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    pairs.add((parts[0].lower(), int(parts[1])))
    return pairs


def discover_from_nmap(bbs_list, mud_list, chunk_dir=None):
    """Discover new telnet services from nmap banner-scan data.

    Finds both entirely new hosts AND new telnet ports on known hosts.

    :param bbs_list: path to bbslist.txt
    :param mud_list: path to mudlist.txt
    :param chunk_dir: path to banner-scan chunks (default: auto)
    :returns: list of discovery dicts with host, port, banner,
        category ('mud', 'bbs', 'other'), is_new_host (bool)
    """
    if chunk_dir is None:
        chunk_dir = str(_CHUNK_DIR)

    known_hosts, known_ips = _parse_lists(bbs_list, mud_list)
    known_pairs = _parse_known_pairs(bbs_list, mud_list)

    host_data = {}
    for xml_path in sorted(glob.glob(os.path.join(chunk_dir, '*.xml'))):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        for host_el in tree.getroot().findall('host'):
            addrs = []
            for addr in host_el.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    addrs.append(addr.get('addr'))
            hostnames = []
            hn_el = host_el.find('hostnames')
            if hn_el is not None:
                for hn in hn_el.findall('hostname'):
                    name = hn.get('name')
                    if name:
                        hostnames.append(name.lower())

            all_names = set(addrs) | set(hostnames)
            is_known_host = bool(
                (all_names & known_hosts) or (set(addrs) & known_ips))

            ports_el = host_el.find('ports')
            if ports_el is None:
                continue

            for port_el in ports_el.findall('port'):
                portid = int(port_el.get('portid'))

                # Skip if this exact host:port pair is known.
                pair_known = any(
                    (h, portid) in known_pairs for h in all_names)
                if pair_known:
                    continue

                for script in port_el.findall('script'):
                    if script.get('id') != 'banner':
                        continue
                    banner = script.get('output', '')
                    if not banner:
                        continue
                    if not _is_telnet_service(banner):
                        continue

                    best_host = hostnames[0] if hostnames else (
                        addrs[0] if addrs else '?')
                    category = _classify(banner, portid, best_host)

                    # Encoding hints (petscii/atascii) are only meaningful
                    # for BBS services — MUDs never use these encodings.
                    encoding = (None if category == 'mud'
                                else _guess_encoding(banner, portid))

                    key = (best_host, portid)
                    if key not in host_data:
                        host_data[key] = {
                            'host': best_host,
                            'ip': addrs[0] if addrs else '',
                            'port': portid,
                            'banner': banner[:120],
                            'category': category,
                            'encoding': encoding,
                            'hostnames': hostnames,
                            'is_new_host': not is_known_host,
                        }

    return sorted(host_data.values(),
                  key=lambda d: (d['category'], d['host'], d['port']))


# SSH banner patterns that identify BBS-bundled SSH servers.
# Each entry is (regex_pattern, software_label).
_BBS_SSH_PATTERNS = [
    (re.compile(r'^SSH-2\.0-cryptlib\(SBBS\)'), 'Synchronet'),
    (re.compile(r'^SSH-2\.0-cryptlib$'), 'Synchronet'),
    (re.compile(r'^SSH-2\.0-enigma-bbs-'), 'ENiGMA½'),
    (re.compile(r'^SSH-2\.0-WWIV$'), 'WWIV'),
    (re.compile(r'^SSH-2\.0-bbs-sshd$'), 'PTT BBS'),
    (re.compile(r'^SSH-2\.0-tel/os$'), 'tel/os'),
    (re.compile(r'^SSH-2\.0-ROSSSH$'), 'ROSSSH'),
    (re.compile(r'^SSH-2\.0-BinktermPHP'), 'Binkterm'),
    (re.compile(r'^SSH-2\.0-\d+\.\d+\s+FlowSsh.*Bitvise'), 'Bitvise'),
]

# ISP PTR record patterns — prefer real domains over these.
_ISP_RE = re.compile(
    r'^\d+[-.].*\.(spectrum|comcast|verizon|frontier|sbcglobal)\.'
    r'|\.static\.'
    r'|^pool-'
    r'|\.dsl\.'
    r'|\.lightspeed\.'
    r'|\.res\.'
    r'|\.cpe\.'
    r'|\.hsd\d'
    r'|\.ip\.linodeusercontent\.'
    r'|\.vultrusercontent\.'
    r'|\.googleusercontent\.'
    r'|\.contaboserver\.'
    r'|\.bc\.googleusercontent\.'
)


def _match_bbs_ssh(banner):
    """Match an SSH banner against known BBS SSH patterns.

    :param banner: SSH banner string from nmap
    :returns: software label string, or ``None``
    """
    for pattern, label in _BBS_SSH_PATTERNS:
        if pattern.search(banner):
            return label
    return None


def _best_ssh_hostname(ip, hostnames):
    """Pick the best hostname, filtering ISP PTR records.

    :param ip: IP address string
    :param hostnames: list of hostname strings
    :returns: best hostname or IP
    """
    real = [h for h in hostnames if not _ISP_RE.search(h)]
    if real:
        return sorted(real, key=len)[0]
    if hostnames:
        return sorted(hostnames, key=len)[0]
    return ip


def discover_ssh_from_nmap(bbs_list, mud_list, chunk_dir=None):
    """Discover BBS-bundled SSH services from nmap banner-scan data.

    Finds SSH ports whose banners match known BBS SSH server
    patterns (Synchronet cryptlib, ENiGMA, WWIV, etc.) and
    cross-references against existing server lists by hostname
    and resolved IP.

    :param bbs_list: path to bbslist.txt
    :param mud_list: path to mudlist.txt
    :param chunk_dir: path to banner-scan chunks (default: auto)
    :returns: list of discovery dicts with host, port, banner,
        software, category, is_new_host
    """
    from concurrent.futures import ThreadPoolExecutor

    if chunk_dir is None:
        chunk_dir = str(_CHUNK_DIR)

    known_hosts, known_ips = _parse_lists(bbs_list, mud_list)
    known_pairs = _parse_known_pairs(bbs_list, mud_list)

    # Forward-resolve known hostnames to IPs for cross-reference.
    hostnames_to_resolve = [h for h in known_hosts
                            if h not in known_ips]
    print(f"  Resolving {len(hostnames_to_resolve)}"
          f" known hostnames ...", end='\r')

    def _fwd(hostname):
        try:
            return hostname, socket.gethostbyname(hostname)
        except (socket.herror, socket.gaierror, OSError):
            return hostname, None

    # Map resolved IP → set of known hostnames for that IP.
    ip_to_known = defaultdict(set)
    with ThreadPoolExecutor(max_workers=32) as pool:
        for hostname, ip in pool.map(_fwd, hostnames_to_resolve):
            if ip:
                known_ips.add(ip)
                ip_to_known[ip].add(hostname)

    # Also map IPs that appear directly in the lists.
    for h in known_hosts:
        try:
            socket.inet_aton(h)
            ip_to_known[h].add(h)
        except OSError:
            pass

    print(f"  Resolved {len(ip_to_known)} IPs from known lists"
          + ' ' * 20)

    # Scan nmap chunks for BBS SSH banners.
    ssh_hits = {}
    for xml_path in sorted(glob.glob(os.path.join(chunk_dir, '*.xml'))):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        for host_el in tree.getroot().findall('host'):
            addrs = []
            for addr in host_el.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    addrs.append(addr.get('addr'))
            hostnames = []
            hn_el = host_el.find('hostnames')
            if hn_el is not None:
                for hn in hn_el.findall('hostname'):
                    name = hn.get('name')
                    if name:
                        hostnames.append(name.lower())

            ports_el = host_el.find('ports')
            if ports_el is None:
                continue

            for port_el in ports_el.findall('port'):
                for script in port_el.findall('script'):
                    if script.get('id') != 'banner':
                        continue
                    banner = script.get('output', '')
                    if not banner.startswith('SSH-'):
                        continue
                    software = _match_bbs_ssh(banner)
                    if not software:
                        continue

                    portid = int(port_el.get('portid'))
                    ip = addrs[0] if addrs else '?'

                    # Find the best hostname: prefer known list
                    # hostname for this IP, then nmap hostnames.
                    known_for_ip = ip_to_known.get(ip, set())
                    all_names = list(known_for_ip) + hostnames
                    best_host = _best_ssh_hostname(ip, all_names)

                    # Classify: check if any known hostname for
                    # this IP is in the mud or bbs list.
                    category = _classify_ssh_host(
                        best_host, ip, known_for_ip,
                        bbs_list, mud_list)

                    # Check if already in a list with ssh tag.
                    all_check = set(hostnames) | set(addrs)
                    if known_for_ip:
                        all_check |= known_for_ip
                    pair_known = any(
                        (h, portid) in known_pairs
                        for h in all_check)

                    is_known_host = bool(
                        (set(addrs) & known_ips)
                        or (set(hostnames) & known_hosts)
                    )

                    key = (best_host, portid)
                    if key not in ssh_hits:
                        ssh_hits[key] = {
                            'host': best_host,
                            'ip': ip,
                            'port': portid,
                            'banner': banner[:120],
                            'software': software,
                            'category': category,
                            'is_new_host': not is_known_host,
                            'already_listed': pair_known,
                        }

    return sorted(ssh_hits.values(),
                  key=lambda d: (d['software'], d['host'],
                                 d['port']))


def _classify_ssh_host(best_host, ip, known_for_ip,
                       bbs_list, mud_list):
    """Classify an SSH discovery as 'mud' or 'bbs'.

    Checks whether the resolved IP or hostname already appears
    in one of the server lists.

    :param best_host: best hostname for the host
    :param ip: IP address
    :param known_for_ip: set of known hostnames for this IP
    :param bbs_list: path to bbslist.txt
    :param mud_list: path to mudlist.txt
    :returns: 'mud', 'bbs', or 'other'
    """
    if not hasattr(_classify_ssh_host, '_cache'):
        _classify_ssh_host._cache = {}
        for path, label in [(mud_list, 'mud'), (bbs_list, 'bbs')]:
            if not os.path.isfile(path):
                continue
            with open(path) as f:
                for line in f:
                    stripped = line.split('#')[0].strip()
                    if not stripped:
                        continue
                    parts = stripped.split()
                    if parts:
                        _classify_ssh_host._cache[
                            parts[0].lower()] = label

    cache = _classify_ssh_host._cache
    # Check known hostnames for this IP first.
    for h in known_for_ip:
        if h in cache:
            return cache[h]
    if best_host.lower() in cache:
        return cache[best_host.lower()]
    return 'other'
