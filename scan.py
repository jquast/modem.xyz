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
    """Parse a server list into a list of (host, port, encoding) tuples.

    :param path: path to server list file
    :returns: list of (host, port_str, encoding_or_None) tuples
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
            encoding = parts[2] if len(parts) >= 3 else None
            entries.append((host, port, encoding))
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
              banner_max_wait=20, connect_timeout=60):
    """Scan a single server.

    :param host: server hostname
    :param port: server port string
    :param data_dir: directory for fingerprint data output
    :param logs_dir: directory for log files
    :param encoding: optional encoding argument for telnetlib3-fingerprint
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
        f"--connect-timeout={connect_timeout}",
        "--silent",
        "--ttype", "xterm-256color",
        "--loglevel", "debug",
        "--logfile", logfile,
        "--logfmt", "%(levelname)s %(filename)s:%(lineno)d %(message)s",
    ]
    # Rendering-only hints (font selection for ansilove) are not valid
    # Python codecs and must not be passed to telnetlib3-fingerprint.
    _RENDER_ONLY_ENCODINGS = {'petscii', 'topaz', 'amiga', 'atarist',
                              'cp437_art', 'cp437-art'}
    if encoding and encoding not in _RENDER_ONLY_ENCODINGS:
        cmd.extend(["--encoding", encoding])

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
            proc.wait(timeout=connect_timeout + (banner_max_wait * 2) + 3)
            if _shutdown:
                return (host, port, "cancelled")
            return (host, port, "scanned")
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
        '--list', required=True,
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
        '--banner-max-wait', type=int, default=60,
        help='Seconds to wait for banner data')
    parser.add_argument(
        '--connect-timeout', type=int, default=60,
        help='Seconds to wait for TCP connection')
    parser.add_argument(
        '--refresh', action='store_true',
        help='Force rescan even if log file exists')
    parser.add_argument(
        '--default-encoding', default=None,
        help='Default encoding when server list entry has none')
    parser.add_argument(
        '--connect-delay', type=float, default=0.123,
        help='Seconds between launching each scan (default: 0.15)')
    args = parser.parse_args()

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
    for host, port, encoding in entries:
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
            to_scan.append((host, port, encoding))

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
            for host, port, encoding in to_scan:
                if _shutdown:
                    break
                future = pool.submit(
                    scan_host, host, port, args.data_dir, args.logs_dir,
                    encoding, args.banner_max_wait,
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
