#!/usr/bin/env python3
"""Nmap service discovery scanner for BBS hosts.

Reads bbslist.txt, extracts unique hostnames, and runs nmap with service
version detection, OS fingerprinting, and DNS lookups.  When given
``--allports-json`` from a prior all-ports sweep, only scans ports
already known to be open on each host — dramatically faster.

Hosts are grouped by their open-port signature and scanned in parallel
chunks.

Requires: nmap, sudo (for SYN scan and OS detection).

Usage::

    # Full scan (all BBS ports on every host):
    sudo python3 nmap_services.py --list bbslist.txt

    # Targeted scan (only open ports from allports sweep):
    sudo python3 nmap_services.py --list bbslist.txt \\
        --allports-json nmap-allports/allports.json
"""

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# All known BBS service ports (Synchronet compiled-in + JS services).
BBS_PORTS = sorted([
    11,     # ActiveUser (finger)
    17,     # QOTD
    18,     # MSP
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    64,     # PETSCII 40-col
    70,     # Gopher
    79,     # Finger
    80,     # HTTP
    110,    # POP3
    119,    # NNTP
    128,    # PETSCII 80-col
    143,    # IMAP
    443,    # HTTPS
    465,    # SMTPS
    513,    # RLogin
    563,    # NNTPS
    587,    # SMTP Submission
    993,    # IMAPS
    995,    # POP3S
    1123,   # WebSocket
    5500,   # Hotline
    5501,   # Hotline Transfer
    6667,   # IRC
    11235,  # WebSocket TLS
    24553,  # BINKPS
    24554,  # BINKP
])

_shutdown = False
_running_procs = set()
_running_procs_lock = threading.Lock()


def parse_hosts(path):
    """Extract unique hostnames from a bbslist.txt server list.

    :param path: path to server list file
    :returns: sorted list of unique hostnames
    """
    hosts = set()
    with open(path) as f:
        for line in f:
            stripped = line.split('#')[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                hosts.add(parts[0])
    return sorted(hosts)


def load_banner_scan(chunk_dir):
    """Load banner-scan chunk XMLs and build per-host port data.

    :param chunk_dir: path to banner-scan chunks directory
    :returns: dict mapping host address to dict with keys
        'open' (set of open ports), 'bannered' (set of ports with banners),
        'closed' (a known closed port for OS fingerprinting, or None)
    """
    import glob
    import xml.etree.ElementTree as ET

    host_data = {}
    for xml_path in sorted(glob.glob(os.path.join(chunk_dir, '*.xml'))):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        for host_el in tree.getroot().findall('host'):
            addrs = [a.get('addr') for a in host_el.findall('address')]
            open_ports = set()
            bannered = set()
            ports_el = host_el.find('ports')
            if ports_el is not None:
                for port in ports_el.findall('port'):
                    portid = int(port.get('portid'))
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        open_ports.add(portid)
                        for script in port.findall('script'):
                            if script.get('id') == 'banner' and script.get('output', ''):
                                bannered.add(portid)
            for addr in addrs:
                if addr in host_data:
                    host_data[addr]['open'].update(open_ports)
                    host_data[addr]['bannered'].update(bannered)
                else:
                    host_data[addr] = {
                        'open': set(open_ports),
                        'bannered': set(bannered),
                    }
    # Pick a known-closed port for each host (for OS fingerprinting).
    # Choose a low port not in the open set.
    for addr, data in host_data.items():
        closed = None
        for p in [1, 3, 7, 9, 13, 37, 42, 113, 256, 1025]:
            if p not in data['open']:
                closed = p
                break
        data['closed'] = closed
    return host_data


def build_port_groups(hosts, banner_data):
    """Group hosts by their no-banner open port signature.

    Only includes ports that are open but had no banner in the
    banner scan — these need service version probing.

    :param hosts: list of hostnames from bbslist.txt
    :param banner_data: dict from :func:`load_banner_scan`
    :returns: (groups, skipped, total_bannered) where groups is a list
        of (port_tuple, closed_port, host_list)
    """
    sig_to_hosts = defaultdict(list)
    skipped = 0
    total_bannered = 0
    for host in hosts:
        data = banner_data.get(host)
        if not data or not data['open']:
            skipped += 1
            continue
        no_banner = sorted(data['open'] - data['bannered'])
        total_bannered += len(data['bannered'])
        if not no_banner:
            skipped += 1
            continue
        # Include a closed port for OS fingerprinting.
        closed = data.get('closed')
        key = (tuple(no_banner), closed)
        sig_to_hosts[key].append(host)
    groups = [(ports, closed, hosts_list)
              for (ports, closed), hosts_list in sig_to_hosts.items()]
    return groups, skipped, total_bannered


def xml_to_hosts(xml_path):
    """Parse nmap XML output and return a list of host dicts.

    :param xml_path: path to nmap XML output file
    :returns: list of host dicts
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall('host'):
        host = {
            'status': {},
            'addresses': [],
            'hostnames': [],
            'ports': [],
            'os': [],
        }

        status = host_el.find('status')
        if status is not None:
            host['status'] = {
                'state': status.get('state'),
                'reason': status.get('reason'),
            }

        for addr in host_el.findall('address'):
            host['addresses'].append({
                'addr': addr.get('addr'),
                'addrtype': addr.get('addrtype'),
                'vendor': addr.get('vendor'),
            })

        hostnames_el = host_el.find('hostnames')
        if hostnames_el is not None:
            for hn in hostnames_el.findall('hostname'):
                host['hostnames'].append({
                    'name': hn.get('name'),
                    'type': hn.get('type'),
                })

        ports_el = host_el.find('ports')
        if ports_el is not None:
            for port in ports_el.findall('port'):
                port_info = {
                    'protocol': port.get('protocol'),
                    'portid': int(port.get('portid')),
                    'state': {},
                    'service': {},
                    'scripts': [],
                }
                state = port.find('state')
                if state is not None:
                    port_info['state'] = {
                        'state': state.get('state'),
                        'reason': state.get('reason'),
                    }
                svc = port.find('service')
                if svc is not None:
                    port_info['service'] = {
                        k: svc.get(k) for k in svc.keys()
                    }
                for script in port.findall('script'):
                    port_info['scripts'].append({
                        'id': script.get('id'),
                        'output': script.get('output'),
                    })
                host['ports'].append(port_info)

        os_el = host_el.find('os')
        if os_el is not None:
            for osmatch in os_el.findall('osmatch'):
                match = {
                    'name': osmatch.get('name'),
                    'accuracy': osmatch.get('accuracy'),
                    'classes': [],
                }
                for osclass in osmatch.findall('osclass'):
                    match['classes'].append({
                        k: osclass.get(k) for k in osclass.keys()
                    })
                host['os'].append(match)

        hosts.append(host)

    return hosts


def scan_chunk(chunk_id, hosts, port_spec, output_dir, host_timeout,
               max_retries):
    """Run nmap service scan on a chunk of hosts sharing the same ports.

    :param chunk_id: integer chunk identifier
    :param hosts: list of hostnames to scan
    :param port_spec: comma-separated port string
    :param output_dir: directory for per-chunk output files
    :param host_timeout: nmap --host-timeout value
    :param max_retries: nmap --max-retries value
    :returns: (chunk_id, host_count, list_of_host_dicts)
    """
    if _shutdown:
        return (chunk_id, len(hosts), [])

    chunk_dir = os.path.join(output_dir, 'chunks')
    os.makedirs(chunk_dir, exist_ok=True)

    hostlist_path = os.path.join(chunk_dir, f'chunk{chunk_id:03d}.hosts')
    xml_path = os.path.join(chunk_dir, f'chunk{chunk_id:03d}.xml')

    with open(hostlist_path, 'w') as f:
        f.write('\n'.join(hosts) + '\n')

    cmd = [
        'nmap',
        '-iL', hostlist_path,
        '-p', port_spec,
        '-sS',
        '-sV',
        '--version-intensity', '5',
        '-O',
        '-Pn',
        '-R',
        '--resolve-all',
        '--randomize-hosts',
        '-T4',
        f'--host-timeout={host_timeout}',
        f'--max-retries={max_retries}',
        '--initial-rtt-timeout=500ms',
        '--max-rtt-timeout=3s',
        '--reason',
        '-oX', xml_path,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with _running_procs_lock:
            _running_procs.add(proc)
        try:
            _, stderr = proc.communicate()
            if _shutdown:
                return (chunk_id, len(hosts), [])
            if proc.returncode != 0:
                msg = stderr.decode(errors='replace').strip()
                print(f"  chunk {chunk_id}: nmap exited {proc.returncode}:"
                      f" {msg[:200]}", file=sys.stderr)
        except Exception:
            return (chunk_id, len(hosts), [])
        finally:
            with _running_procs_lock:
                _running_procs.discard(proc)
    except FileNotFoundError:
        print("Error: nmap not found in PATH", file=sys.stderr)
        return (chunk_id, len(hosts), [])

    if os.path.isfile(xml_path):
        return (chunk_id, len(hosts), xml_to_hosts(xml_path))
    return (chunk_id, len(hosts), [])


def main():
    parser = argparse.ArgumentParser(
        description='Nmap service discovery scan for BBS hosts.')
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _default_data = os.path.join(_script_dir, 'data', 'service-scan')

    parser.add_argument(
        '--list', required=True,
        help='Path to bbslist.txt server list')
    _default_banner_dir = os.path.join(_script_dir, 'data', 'banner-scan')
    parser.add_argument(
        '--banner-data', default=_default_banner_dir,
        help='Path to banner-scan data dir containing chunks/'
             ' (default: data/banner-scan/)')
    parser.add_argument(
        '--output-dir', default=_default_data,
        help='Directory for output files (default: data/results/)')
    parser.add_argument(
        '--extra-ports', default=None,
        help='Additional comma-separated ports to scan')
    parser.add_argument(
        '--chunk-size', type=int, default=16,
        help='Hosts per nmap process (default: 16)')
    parser.add_argument(
        '--num-workers', type=int, default=8,
        help='Parallel nmap processes (default: 8)')
    parser.add_argument(
        '--host-timeout', default='10m',
        help='Per-host timeout (default: 10m)')
    parser.add_argument(
        '--max-retries', type=int, default=3,
        help='Max probe retries per port (default: 3)')
    parser.add_argument(
        '--launch-delay', type=float, default=2.0,
        help='Seconds between launching each nmap process (default: 2.0)')
    parser.add_argument(
        '--resume', action='store_true',
        help='Skip hosts that already have results in existing'
             ' services.json')
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Print plan without executing')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: must run as root (SYN scan + OS detection require it)."
              " Use: sudo python3 nmap_services.py ...", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.list):
        print(f"Error: {args.list} not found", file=sys.stderr)
        sys.exit(1)

    hosts = parse_hosts(args.list)
    if not hosts:
        print("Error: no hosts found in list", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # Resume: load existing results and skip hosts that have data.
    prior_hosts = []
    if args.resume:
        json_path = os.path.join(args.output_dir, 'services.json')
        if os.path.isfile(json_path):
            with open(json_path) as f:
                prior_data = json.load(f)
            prior_hosts = prior_data.get('hosts', [])
            done_addrs = set()
            for host in prior_hosts:
                if host.get('ports'):
                    for addr in host.get('addresses', []):
                        done_addrs.add(addr['addr'])
            before = len(hosts)
            hosts = [h for h in hosts if h not in done_addrs]
            print(f"Resume: {len(done_addrs)} hosts already have data,"
                  f" {before - len(hosts)} skipped,"
                  f" {len(hosts)} remaining", file=sys.stderr)
        else:
            print("Resume: no existing services.json found, scanning all",
                  file=sys.stderr)

    if not hosts:
        print("Nothing to scan — all hosts already have data.",
              file=sys.stderr)
        sys.exit(0)

    extra = set()
    if args.extra_ports:
        for p in args.extra_ports.split(','):
            p = p.strip()
            if p.isdigit():
                extra.add(int(p))

    # Build scan work items from banner-scan data.
    work = []
    skipped = 0
    total_bannered = 0

    banner_chunks = os.path.join(args.banner_data, 'chunks')
    if os.path.isdir(banner_chunks):
        print(f"Loading banner-scan data from {banner_chunks} ...",
              file=sys.stderr)
        banner_data = load_banner_scan(banner_chunks)
        print(f"  {len(banner_data)} hosts in banner-scan data",
              file=sys.stderr)
        groups, skipped, total_bannered = build_port_groups(
            hosts, banner_data)
        for port_tuple, closed_port, group_hosts in groups:
            # Include the closed port for OS fingerprinting.
            ports = list(port_tuple)
            if closed_port is not None:
                ports.append(closed_port)
            port_spec = ','.join(str(p) for p in sorted(set(ports)))
            random.shuffle(group_hosts)
            for i in range(0, len(group_hosts), args.chunk_size):
                chunk = group_hosts[i:i + args.chunk_size]
                work.append((port_spec, chunk))
        random.shuffle(work)
    else:
        print(f"No banner-scan data found at {banner_chunks},"
              f" scanning all BBS ports", file=sys.stderr)
        all_ports = sorted(set(BBS_PORTS) | extra)
        port_spec = ','.join(str(p) for p in all_ports)
        random.shuffle(hosts)
        for i in range(0, len(hosts), args.chunk_size):
            chunk = hosts[i:i + args.chunk_size]
            work.append((port_spec, chunk))

    total_hosts = sum(len(chunk) for _, chunk in work)
    unique_port_specs = len(set(ps for ps, _ in work))

    print(f"Hosts to scan: {total_hosts} ({skipped} skipped,"
          f" {total_bannered} ports already bannered)", file=sys.stderr)
    print(f"Chunks: {len(work)} ({unique_port_specs} distinct port sets)",
          file=sys.stderr)
    print(f"Workers: {args.num_workers} parallel nmap processes",
          file=sys.stderr)

    if args.dry_run:
        for i, (ps, chunk) in enumerate(work):
            print(f"  chunk {i}: {len(chunk)} hosts, ports {ps}",
                  file=sys.stderr)
        print("Dry run — not executing.", file=sys.stderr)
        sys.exit(0)

    def _sigint_handler(signum, frame):
        global _shutdown
        if _shutdown:
            sys.exit(1)
        _shutdown = True
        print("\nInterrupted — killing running scans ...", file=sys.stderr)
        with _running_procs_lock:
            procs = list(_running_procs)
        for proc in procs:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass

    prev_handler = signal.signal(signal.SIGINT, _sigint_handler)

    all_results = []
    completed = 0
    errors = 0
    t0 = time.monotonic()

    try:
        with ThreadPoolExecutor(max_workers=args.num_workers) as pool:
            futures = set()
            for i, (port_spec, chunk) in enumerate(work):
                if _shutdown:
                    break
                future = pool.submit(
                    scan_chunk, i, chunk, port_spec, args.output_dir,
                    args.host_timeout, args.max_retries)
                futures.add(future)
                time.sleep(args.launch_delay)
                done = {f for f in futures if f.done()}
                for f in done:
                    chunk_id, host_count, host_results = f.result()
                    completed += host_count
                    if host_results:
                        all_results.extend(host_results)
                    else:
                        errors += host_count
                    elapsed = time.monotonic() - t0
                    pct = completed / total_hosts * 100
                    print(f"  chunk {chunk_id:3d} done —"
                          f" {completed}/{total_hosts}"
                          f" ({pct:.0f}%) {elapsed:.0f}s elapsed,"
                          f" {len(host_results)} hosts",
                          file=sys.stderr)
                futures -= done

            for future in as_completed(futures):
                if _shutdown:
                    break
                chunk_id, host_count, host_results = future.result()
                completed += host_count
                if host_results:
                    all_results.extend(host_results)
                else:
                    errors += host_count
                elapsed = time.monotonic() - t0
                pct = completed / total_hosts * 100
                print(f"  chunk {chunk_id:3d} done —"
                      f" {completed}/{total_hosts}"
                      f" ({pct:.0f}%) {elapsed:.0f}s elapsed,"
                      f" {len(host_results)} hosts",
                      file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, prev_handler)

    # Merge with prior results if resuming.
    merged = prior_hosts + all_results

    json_path = os.path.join(args.output_dir, 'services.json')
    result = {
        'scanner': 'nmap (chunked service scan)',
        'banner_data': args.banner_data,
        'total_hosts': total_hosts + len(prior_hosts),
        'skipped': skipped,
        'prior_hosts_kept': len(prior_hosts),
        'new_hosts_scanned': total_hosts,
        'hosts_with_results': len(merged),
        'elapsed': f"{time.monotonic() - t0:.0f}s",
        'hosts': merged,
    }
    with open(json_path, 'w') as f:
        json.dump(result, f, indent=2)

    elapsed = time.monotonic() - t0
    print(f"\nDone: {len(all_results)} new hosts"
          f" + {len(prior_hosts)} prior,"
          f" {errors} errors, {elapsed:.0f}s elapsed", file=sys.stderr)
    print(f"Wrote {json_path} ({len(merged)} total hosts)", file=sys.stderr)


if __name__ == '__main__':
    main()
