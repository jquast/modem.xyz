#!/usr/bin/env python3
"""Nmap all-ports scanner for BBS hosts.

Scans all 65535 TCP ports on each host for open/closed/filtered state
and grabs banners.  No service version detection, no OS fingerprinting,
no DNS lookups — just raw port state and banner data.

Hosts are split into chunks and scanned by parallel nmap processes for
much better throughput than a single monolithic invocation.

Requires: nmap, sudo (for SYN scan).

Usage::

    sudo python3 nmap_allports.py --list bbslist.txt --output-dir nmap-allports/
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
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def xml_to_hosts(xml_path):
    """Parse nmap XML output and return a list of host dicts.

    :param xml_path: path to nmap XML output file
    :returns: list of host dicts with addresses, ports, scripts
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall('host'):
        host = {
            'status': {},
            'addresses': [],
            'ports': [],
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
            })

        ports_el = host_el.find('ports')
        if ports_el is not None:
            for port in ports_el.findall('port'):
                port_info = {
                    'protocol': port.get('protocol'),
                    'portid': int(port.get('portid')),
                    'state': {},
                    'scripts': [],
                }
                state = port.find('state')
                if state is not None:
                    port_info['state'] = {
                        'state': state.get('state'),
                        'reason': state.get('reason'),
                    }
                for script in port.findall('script'):
                    port_info['scripts'].append({
                        'id': script.get('id'),
                        'output': script.get('output'),
                    })
                host['ports'].append(port_info)

        hosts.append(host)

    return hosts


def scan_chunk(chunk_id, run_id, hosts, output_dir, host_timeout, max_retries,
               min_rate):
    """Run nmap on a chunk of hosts, return parsed host results.

    :param chunk_id: integer chunk identifier
    :param run_id: unique run identifier to avoid filename collisions
    :param hosts: list of hostnames to scan
    :param output_dir: directory for per-chunk output files
    :param host_timeout: nmap --host-timeout value
    :param max_retries: nmap --max-retries value
    :param min_rate: nmap --min-rate value
    :returns: (chunk_id, host_count, list_of_host_dicts)
    """
    if _shutdown:
        return (chunk_id, len(hosts), [])

    chunk_dir = os.path.join(output_dir, 'chunks')
    os.makedirs(chunk_dir, exist_ok=True)

    prefix = f'r{run_id}_c{chunk_id:03d}'
    hostlist_path = os.path.join(chunk_dir, f'{prefix}.hosts')
    xml_path = os.path.join(chunk_dir, f'{prefix}.xml')

    with open(hostlist_path, 'w') as f:
        f.write('\n'.join(hosts) + '\n')

    cmd = [
        'nmap',
        '-iL', hostlist_path,
        '-p-',
        '-sS',
        '--script', 'banner',
        '-Pn',
        '--randomize-hosts',
        '-T3',
        f'--host-timeout={host_timeout}',
        f'--max-retries={max_retries}',
        f'--min-rate={min_rate}',
        '--initial-rtt-timeout=500ms',
        '--max-rtt-timeout=3s',
        '--reason',
        '--open',
        '--stats-every', '30s',
        '-oX', xml_path,
        '-oN', xml_path.replace('.xml', '.nmap'),
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
            for line in proc.stderr:
                text = line.decode(errors='replace').rstrip()
                if text:
                    print(f"  [{chunk_id:3d}] {text}", file=sys.stderr)
            proc.wait()
            if _shutdown:
                return (chunk_id, len(hosts), [])
            if proc.returncode != 0:
                print(f"  [{chunk_id:3d}] nmap exited {proc.returncode}",
                      file=sys.stderr)
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


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_SCRIPT_DIR)
_DEFAULT_DATA = os.path.join(_SCRIPT_DIR, 'data', 'banner-scan')
_DEFAULT_LIST = os.path.join(_PROJECT_DIR, 'bbslist.txt')


def main():
    parser = argparse.ArgumentParser(
        description='Nmap all-ports scan for BBS hosts (chunked parallel).')
    parser.add_argument(
        '--list', default=_DEFAULT_LIST,
        help='Path to bbslist.txt server list')
    parser.add_argument(
        '--output-dir', default=_DEFAULT_DATA,
        help='Directory for output files (default: data/banner-scan/)')
    parser.add_argument(
        '--chunk-size', type=int, default=8,
        help='Hosts per nmap process (default: 8)')
    parser.add_argument(
        '--num-workers', type=int, default=6,
        help='Parallel nmap processes (default: 6)')
    parser.add_argument(
        '--host-timeout', default='20m',
        help='Per-host timeout (default: 20m)')
    parser.add_argument(
        '--max-retries', type=int, default=2,
        help='Max probe retries per port (default: 2)')
    parser.add_argument(
        '--min-rate', type=int, default=700,
        help='Minimum packets/sec per nmap process (default: 700)')
    parser.add_argument(
        '--launch-delay', type=float, default=2.0,
        help='Seconds between launching each nmap process (default: 2.0)')
    parser.add_argument(
        '--resume', action='store_true', default=True,
        help='Skip hosts already scanned in chunk XMLs (default: True)')
    parser.add_argument(
        '--no-resume', action='store_false', dest='resume',
        help='Rescan all hosts, ignoring previous results')
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Print plan without executing')
    args = parser.parse_args()

    if not os.path.isfile(args.list):
        print(f"Error: {args.list} not found", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print("Error: must run as root (SYN scan requires it)."
              " Use: sudo python3 nmap_allports.py ...", file=sys.stderr)
        sys.exit(1)

    hosts = parse_hosts(args.list)
    if not hosts:
        print("Error: no hosts found in list", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # Resume: scan chunk XMLs for hosts already scanned (with or without
    # open ports).  This is more reliable than allports.json which is only
    # written at the end of a run.
    if args.resume:
        import glob
        chunk_dir = os.path.join(args.output_dir, 'chunks')
        done_addrs = set()
        done_hostnames = set()
        for xml_path in glob.glob(os.path.join(chunk_dir, '*.xml')):
            try:
                tree = ET.parse(xml_path)
            except ET.ParseError:
                continue
            for host_el in tree.getroot().findall('host'):
                for addr in host_el.findall('address'):
                    done_addrs.add(addr.get('addr'))
                hn_el = host_el.find('hostnames')
                if hn_el is not None:
                    for hn in hn_el.findall('hostname'):
                        name = hn.get('name')
                        if name:
                            done_hostnames.add(name)
        before = len(hosts)
        hosts = [h for h in hosts
                 if h not in done_addrs and h not in done_hostnames]
        print(f"Resume: {before - len(hosts)} hosts already scanned,"
              f" {len(hosts)} remaining", file=sys.stderr)

    if not hosts:
        print("Nothing to scan — all hosts already have data.",
              file=sys.stderr)
        sys.exit(0)

    # Run ID to avoid chunk filename collisions across runs.
    run_id = int(time.time())

    # Shuffle so nearby IPs don't land in the same chunk.
    random.shuffle(hosts)

    # Split hosts into chunks.
    chunks = []
    for i in range(0, len(hosts), args.chunk_size):
        chunks.append(hosts[i:i + args.chunk_size])

    print(f"Hosts: {len(hosts)}", file=sys.stderr)
    print(f"Chunks: {len(chunks)} × {args.chunk_size} hosts", file=sys.stderr)
    print(f"Workers: {args.num_workers} parallel nmap processes", file=sys.stderr)
    print(f"Ports: 1-65535 (all)", file=sys.stderr)
    print(f"Rate: --min-rate={args.min_rate} per process"
          f" (~{args.min_rate * args.num_workers} total pps)", file=sys.stderr)

    if args.dry_run:
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

    all_hosts = []
    completed = 0
    errors = 0
    t0 = time.monotonic()

    try:
        with ThreadPoolExecutor(max_workers=args.num_workers) as pool:
            future_to_chunk = {}
            futures = set()
            for i, chunk in enumerate(chunks):
                if _shutdown:
                    break
                future = pool.submit(
                    scan_chunk, i, run_id, chunk, args.output_dir,
                    args.host_timeout, args.max_retries, args.min_rate)
                future_to_chunk[future] = i
                futures.add(future)
                # Stagger launches so we don't blast the network.
                time.sleep(args.launch_delay)
                # Drain completed futures while we wait.
                done = {f for f in futures if f.done()}
                for f in done:
                    chunk_id, host_count, host_results = f.result()
                    completed += host_count
                    if host_results:
                        all_hosts.extend(host_results)
                    else:
                        errors += host_count
                    elapsed = time.monotonic() - t0
                    pct = completed / len(hosts) * 100
                    print(f"  chunk {chunk_id:3d} done —"
                          f" {completed}/{len(hosts)}"
                          f" ({pct:.0f}%) {elapsed:.0f}s elapsed,"
                          f" {len(host_results)} hosts with open ports",
                          file=sys.stderr)
                futures -= done

            for future in as_completed(futures):
                if _shutdown:
                    break
                chunk_id, host_count, host_results = future.result()
                completed += host_count
                if host_results:
                    all_hosts.extend(host_results)
                else:
                    errors += host_count
                elapsed = time.monotonic() - t0
                pct = completed / len(hosts) * 100
                print(f"  chunk {chunk_id:3d} done — {completed}/{len(hosts)}"
                      f" ({pct:.0f}%) {elapsed:.0f}s elapsed,"
                      f" {len(host_results)} hosts with open ports",
                      file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, prev_handler)

    elapsed = time.monotonic() - t0
    print(f"\nDone: {len(all_hosts)} new hosts with open ports,"
          f" {errors} errors, {elapsed:.0f}s elapsed", file=sys.stderr)
    print(f"Results in {args.output_dir}/chunks/ — use query.py to view",
          file=sys.stderr)


if __name__ == '__main__':
    main()
