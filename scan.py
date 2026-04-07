#!/usr/bin/env python3
"""Parallel telnet server scanner using telnetlib3-fingerprint.

Reads a server list file and scans each server in parallel, saving
session data and logs.  The list format is::

    host port [encoding]

An optional third field specifies the encoding to pass to
``telnetlib3-fingerprint --encoding``, for servers that use legacy
encodings like CP437.
"""

import argparse
import os
import random
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Global state for clean shutdown on Ctrl+C.
_shutdown = False
_running_procs = set()
_running_procs_lock = threading.Lock()


def parse_server_list(path):
    """Parse a server list into a list of (host, port, encoding, ssl, rlogin) tuples.

    :param path: path to server list file
    :returns: list of (host, port_str, encoding_or_None, ssl_bool, rlogin_bool) tuples
    """
    entries = []
    with open(path) as f:
        for line in f:
            stripped = line.split('#')[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            host = parts[0]
            port = parts[1]
            ssl_flag = 'ssl' in parts[2:]
            rlogin_flag = 'rlogin' in parts[2:]
            remaining = [p for p in parts[2:] if p not in ('ssl', 'rlogin')]
            encoding = remaining[0] if remaining else None
            entries.append((host, port, encoding, ssl_flag, rlogin_flag))
    return entries


def _kill_process_group(proc):
    """Kill a subprocess and all of its children via process group.

    :param proc: a :class:`subprocess.Popen` started with ``start_new_session=True``
    """
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.wait(timeout=5)


def scan_host(host, port, data_dir, logs_dir, encoding=None,
              ssl=False, rlogin=False, banner_max_wait=20, connect_timeout=60):
    """Scan a single server.

    :param host: server hostname
    :param port: server port string
    :param data_dir: directory for fingerprint data output
    :param logs_dir: directory for log files
    :param encoding: optional encoding argument for telnetlib3-fingerprint
    :param ssl: use TLS for connection (tries verified first, falls back
        to unverified)
    :param rlogin: use RLogin protocol instead of Telnet
    :param banner_max_wait: seconds to wait for banner data
    :param connect_timeout: seconds to wait for TCP connection
    :returns: (host, port, status_message)
    """
    if _shutdown:
        return (host, port, "cancelled")

    logfile = os.path.join(logs_dir, f"{host}:{port}.log")

    try:
        os.remove(logfile)
    except FileNotFoundError:
        pass

    cmd = [
        "telnetlib3-fingerprint", host, port,
        "--data", data_dir,
        f"--banner-max-wait={banner_max_wait}",
        "--banner-quiet-time=5",
        f"--connect-timeout={connect_timeout}",
        "--silent",
        "--ttype", "xterm-256color",
        "--loglevel", "debug",
        "--logfile", logfile,
        "--logfmt", "%(levelname)s %(filename)s:%(lineno)d %(message)s",
    ]
    # Rendering-only hints (font selection) are not valid Python codecs
    # and must not be passed to telnetlib3-fingerprint.  Note: petscii,
    # atascii, and atarist *are* real codecs provided by telnetlib3.
    _RENDER_ONLY_ENCODINGS = {'topaz'}
    if encoding and encoding not in _RENDER_ONLY_ENCODINGS:
        cmd.extend(["--encoding", encoding])
    if rlogin:
        cmd.append("--rlogin")
    if ssl:
        cmd.append("--ssl")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        with _running_procs_lock:
            _running_procs.add(proc)
        try:
            wait_timeout = connect_timeout + (banner_max_wait * 2) + 3
            proc.wait(timeout=wait_timeout)
            if _shutdown:
                return (host, port, "cancelled")
            if proc.returncode == 0:
                if ssl:
                    return (host, port, "scanned (tls verified)")
                return (host, port, "scanned")
            # TLS with strict verification failed — retry without
            # certificate verification so we still get banner data.
            if ssl:
                cmd_noverify = [
                    a for a in cmd if a != "--ssl"
                ] + ["--ssl-no-verify"]
                proc2 = subprocess.Popen(
                    cmd_noverify,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                with _running_procs_lock:
                    _running_procs.add(proc2)
                try:
                    proc2.wait(timeout=wait_timeout)
                    if _shutdown:
                        return (host, port, "cancelled")
                    if proc2.returncode == 0:
                        return (host, port,
                                "scanned (tls unverified)")
                    return (host, port, "error (tls)")
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc2)
                    return (host, port, "timeout (tls)")
                finally:
                    with _running_procs_lock:
                        _running_procs.discard(proc2)
            return (host, port, "error (exit code %d)" % proc.returncode)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            return (host, port, "timeout (subprocess)")
        finally:
            with _running_procs_lock:
                _running_procs.discard(proc)
    except FileNotFoundError:
        return (host, port, "error: telnetlib3-fingerprint not found")


def main():
    parser = argparse.ArgumentParser(
        description='Scan telnet servers in parallel using'
                    ' telnetlib3-fingerprint.')
    parser.add_argument(
        '--list', default=None,
        help='Path to server list file (host port [encoding])')
    parser.add_argument(
        '--data-dir', default=None,
        help='Directory for fingerprint data output'
             ' (default: directory containing --list)')
    parser.add_argument(
        '--logs-dir', default=None,
        help='Directory for scan log files (default: ./logs)')
    parser.add_argument(
        '--num-workers', type=int, default=20,
        help='Number of parallel workers (default: 16)')
    parser.add_argument(
        '--banner-max-wait', type=int, default=20,
        help='Seconds to wait for banner data')
    parser.add_argument(
        '--connect-timeout', type=int, default=30,
        help='Seconds to wait for TCP connection')
    parser.add_argument(
        '--refresh', action='store_true',
        help='Force rescan even if log file exists')
    parser.add_argument(
        '--default-encoding', default=None,
        help='Default encoding when server list entry has none')
    parser.add_argument(
        '--connect-delay', type=float, default=0.05,
        help='Seconds between launching each scan')
    parser.add_argument(
        '--shodan-bbs', action='store_true',
        help='Search Shodan for new BBS servers and save discoveries')
    parser.add_argument(
        '--shodan-muds', action='store_true',
        help='Search Shodan for new MUD servers and save discoveries')
    parser.add_argument(
        '--shodan-general', action='store_true',
        help='Search Shodan for ANSI terminal services (BBS/MUD/other)')
    args = parser.parse_args()

    # Shodan discovery mode — runs searches and exits.
    if args.shodan_bbs or args.shodan_muds or args.shodan_general:
        from moderation.shodan_discover import (
            BBS_QUERIES, MUD_QUERIES, GENERAL_QUERIES,
            discover, save_discoveries,
        )
        if args.shodan_bbs:
            list_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'bbslist.txt')
            print("Discovering new BBS servers via Shodan ...",
                  file=sys.stderr)
            found, stats = discover(BBS_QUERIES, list_path, 'bbs')
            print(f"  {stats['total_results']} total results,"
                  f" {stats['unique_ips']} unique IPs,"
                  f" {stats['already_known']} already known,"
                  f" {stats['new']} new", file=sys.stderr)
            if found:
                path = save_discoveries(found, 'bbs')
                print(f"  Saved {len(found)} discoveries to {path}",
                      file=sys.stderr)
        if args.shodan_muds:
            list_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'mudlist.txt')
            print("Discovering new MUD servers via Shodan ...",
                  file=sys.stderr)
            found, stats = discover(MUD_QUERIES, list_path, 'mud')
            print(f"  {stats['total_results']} total results,"
                  f" {stats['unique_ips']} unique IPs,"
                  f" {stats['already_known']} already known,"
                  f" {stats['new']} new", file=sys.stderr)
            if found:
                path = save_discoveries(found, 'mud')
                print(f"  Saved {len(found)} discoveries to {path}",
                      file=sys.stderr)
        if args.shodan_general:
            # Dedup against both lists.
            bbs_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'bbslist.txt')
            mud_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'mudlist.txt')
            # Combine both lists for dedup.
            from moderation.shodan_discover import _parse_server_list
            bbs_hosts, bbs_ips = _parse_server_list(bbs_path)
            mud_hosts, mud_ips = _parse_server_list(mud_path)
            # Write a temp combined list.
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                            delete=False) as tmp:
                for h in sorted(bbs_hosts | mud_hosts):
                    tmp.write(f"{h} 23\n")
                combined_path = tmp.name
            try:
                print("Discovering ANSI terminal services via Shodan ...",
                      file=sys.stderr)
                found, stats = discover(
                    GENERAL_QUERIES, combined_path, 'general')
                print(f"  {stats['total_results']} total results,"
                      f" {stats['unique_ips']} unique IPs,"
                      f" {stats['already_known']} already known,"
                      f" {stats['new']} new", file=sys.stderr)
                if found:
                    path = save_discoveries(found, 'general')
                    print(f"  Saved {len(found)} discoveries to {path}",
                          file=sys.stderr)
            finally:
                os.unlink(combined_path)
        return

    if not args.list:
        parser.error("--list is required for scanning")
    if not os.path.isfile(args.list):
        print(f"Error: {args.list} not found", file=sys.stderr)
        sys.exit(1)

    if args.data_dir is None:
        args.data_dir = os.path.dirname(args.list) or '.'
    if args.logs_dir is None:
        args.logs_dir = os.path.join(
            os.path.dirname(args.data_dir) or '.', 'logs')

    os.makedirs(args.logs_dir, exist_ok=True)

    entries = parse_server_list(args.list)
    random.shuffle(entries)

    # Pre-filter: separate entries that need scanning from those
    # that will be skipped, so --connect-delay only affects real scans.
    to_scan = []
    skipped = 0
    for host, port, encoding, ssl_flag, rlogin_flag in entries:
        if not host or not port:
            print(f"{host}:{port} -- skip: empty host or port")
            skipped += 1
        elif not args.refresh and os.path.isfile(
                os.path.join(args.logs_dir, f"{host}:{port}.log")):
            print(f"{host}:{port} -- skip: already scanned")
            skipped += 1
        else:
            if not encoding and args.default_encoding:
                encoding = args.default_encoding
            to_scan.append((host, port, encoding, ssl_flag, rlogin_flag))

    print(f"Scanning {len(to_scan)} servers with"
          f" {args.num_workers} workers"
          f" ({skipped} skipped) ...", file=sys.stderr)

    scanned = 0
    errors = 0
    cancelled = 0
    # Map future → (host, port) for status reporting.
    future_to_server = {}

    def _report(future):
        nonlocal scanned, errors, cancelled
        host, port, status = future.result()
        if status == "scanned":
            scanned += 1
        elif status == "cancelled":
            cancelled += 1
        else:
            errors += 1
        if status != "cancelled":
            print(f"{host}:{port} -- {status}")

    def _sigint_handler(signum, frame):
        global _shutdown
        if _shutdown:
            # Second Ctrl+C — force exit.
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

    try:
        with ThreadPoolExecutor(max_workers=args.num_workers) as pool:
            futures = set()
            for host, port, encoding, ssl_flag, rlogin_flag in to_scan:
                if _shutdown:
                    break
                future = pool.submit(
                    scan_host, host, port, args.data_dir, args.logs_dir,
                    encoding, ssl_flag, rlogin_flag, args.banner_max_wait,
                    args.connect_timeout)
                future_to_server[future] = (host, port)
                futures.add(future)
                time.sleep(args.connect_delay)
                # drain any futures that completed while we slept
                done = {f for f in futures if f.done()}
                for f in done:
                    _report(f)
                futures -= done

            if _shutdown:
                for f in futures:
                    f.cancel()
                pool.shutdown(wait=False, cancel_futures=True)
            else:
                # Wait for remaining futures with periodic status updates.
                while futures:
                    if _shutdown:
                        for f in futures:
                            f.cancel()
                        pool.shutdown(wait=False, cancel_futures=True)
                        break
                    newly_done = set()
                    try:
                        for f in as_completed(futures, timeout=10):
                            newly_done.add(f)
                            _report(f)
                            if _shutdown:
                                break
                    except TimeoutError:
                        remaining = futures - newly_done
                        servers = [
                            f"{future_to_server[f][0]}:{future_to_server[f][1]}"
                            for f in remaining if f in future_to_server
                        ]
                        if servers:
                            print(f"  ... waiting on {len(servers)}:"
                                  f" {', '.join(servers[:8])}"
                                  f"{'...' if len(servers) > 8 else ''}",
                                  file=sys.stderr)
                    futures -= newly_done
    finally:
        signal.signal(signal.SIGINT, prev_handler)

    print(f"\nDone: {scanned} scanned, {skipped} skipped,"
          f" {errors} errors"
          f"{f', {cancelled} cancelled' if cancelled else ''}",
          file=sys.stderr)


if __name__ == '__main__':
    main()
