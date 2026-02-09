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
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def scan_host(host, port, data_dir, logs_dir, encoding=None,
              refresh=False, banner_max_wait=6, connect_timeout=10):
    """Scan a single server.

    :param host: server hostname
    :param port: server port string
    :param data_dir: directory for fingerprint data output
    :param logs_dir: directory for log files
    :param encoding: optional encoding argument for telnetlib3-fingerprint
    :param refresh: if True, rescan even if log file exists
    :param banner_max_wait: seconds to wait for banner data
    :param connect_timeout: seconds to wait for TCP connection
    :returns: (host, port, status_message)
    """
    logfile = os.path.join(logs_dir, f"{host}:{port}.log")

    if not host or not port:
        return (host, port, "skip: empty host or port")

    if not refresh and os.path.isfile(logfile):
        return (host, port, f"skip: file exists, {logfile}")

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
    if encoding:
        cmd.extend(["--encoding", encoding])

    try:
        subprocess.run(cmd, check=False, capture_output=True, timeout=30)
        return (host, port, "scanned")
    except subprocess.TimeoutExpired:
        return (host, port, "timeout (subprocess)")
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
        '--num-workers', type=int, default=32,
        help='Number of parallel workers (default: 4)')
    parser.add_argument(
        '--banner-max-wait', type=int, default=10,
        help='Seconds to wait for banner data (default: 6)')
    parser.add_argument(
        '--connect-timeout', type=int, default=30,
        help='Seconds to wait for TCP connection (default: 10)')
    parser.add_argument(
        '--refresh', action='store_true',
        help='Force rescan even if log file exists')
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

    print(f"Scanning {len(entries)} servers with {args.num_workers} workers...",
          file=sys.stderr)

    scanned = 0
    skipped = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=args.num_workers) as pool:
        futures = {
            pool.submit(scan_host, host, port, args.data_dir, args.logs_dir,
                        encoding, args.refresh, args.banner_max_wait,
                        args.connect_timeout): (host, port)
            for host, port, encoding in entries
        }
        for future in as_completed(futures):
            host, port, status = future.result()
            if status.startswith("skip"):
                skipped += 1
            elif status == "scanned":
                scanned += 1
            else:
                errors += 1
            print(f"{host}:{port} -- {status}")

    print(f"\nDone: {scanned} scanned, {skipped} skipped, {errors} errors",
          file=sys.stderr)


if __name__ == '__main__':
    main()
