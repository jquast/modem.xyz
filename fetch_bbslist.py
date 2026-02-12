#!/usr/bin/env python
"""Fetch BBS list from relay.cfg and cross-reference against mudlist.txt.

Downloads relay.cfg from ipingthereforeiam.com (or reads a local copy),
removes entries that match any host:port pair in the MUD project's
mudlist.txt, and writes the result to data/bbslist.txt.

Preserves any manual encoding overrides (third field) from an existing
bbslist.txt when merging.
"""

import argparse
import os
import sys
import urllib.request

RELAY_CFG_URL = 'https://www.ipingthereforeiam.com/bbs/dir/relay.cfg'
DEFAULT_MUDLIST = os.path.join(os.path.dirname(__file__), 'mudlist.txt')
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), 'bbslist.txt')


def fetch_relay_cfg(source):
    """Fetch relay.cfg from URL or local file.

    :param source: URL or filesystem path
    :returns: list of (host, port) tuples
    """
    if source.startswith(('http://', 'https://')):
        print(f'Downloading {source} ...', file=sys.stderr)
        req = urllib.request.Request(source, headers={
            'User-Agent': 'bbs.modem.xyz/0.1 (telnet census)',
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode('utf-8', errors='replace')
    else:
        print(f'Reading {source} ...', file=sys.stderr)
        with open(source) as f:
            text = f.read()

    entries = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # relay.cfg format: host:port
        if ':' in line:
            parts = line.rsplit(':', 1)
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                continue
        else:
            # fallback: space-separated
            parts = line.split()
            if len(parts) < 2:
                continue
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                continue
        if host and port > 0:
            entries.add((host.lower(), port))
    return entries


def load_mudlist(path):
    """Load mudlist.txt and return set of (host, port) tuples.

    :param path: path to mudlist.txt
    :returns: set of (host, port) tuples
    """
    entries = set()
    if not os.path.isfile(path):
        print(f'Warning: mudlist not found at {path}', file=sys.stderr)
        return entries
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                continue
            entries.add((host.lower(), port))
    return entries


def load_existing_overrides(path):
    """Load encoding overrides from an existing bbslist.txt.

    :param path: path to bbslist.txt
    :returns: dict mapping (host, port) to encoding string
    """
    overrides = {}
    if not os.path.isfile(path):
        return overrides
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides[(host.lower(), port)] = parts[2].strip()
    return overrides


def main():
    parser = argparse.ArgumentParser(
        description='Fetch BBS list from relay.cfg, removing MUD entries.')
    parser.add_argument(
        '--relay-cfg', default=RELAY_CFG_URL,
        help='URL or local path to relay.cfg')
    parser.add_argument(
        '--mudlist', default=DEFAULT_MUDLIST,
        help='Path to mudlist.txt for cross-reference filtering')
    parser.add_argument(
        '--output', default=DEFAULT_OUTPUT,
        help='Output path for bbslist.txt')
    args = parser.parse_args()

    relay_entries = fetch_relay_cfg(args.relay_cfg)
    print(f'  {len(relay_entries)} entries from relay.cfg', file=sys.stderr)

    mud_entries = load_mudlist(args.mudlist)
    print(f'  {len(mud_entries)} entries from mudlist.txt', file=sys.stderr)

    # Remove MUD entries
    bbs_entries = relay_entries - mud_entries
    removed = len(relay_entries) - len(bbs_entries)
    print(f'  {removed} MUD entries removed', file=sys.stderr)
    print(f'  {len(bbs_entries)} BBS entries remaining', file=sys.stderr)

    # Preserve existing encoding overrides
    overrides = load_existing_overrides(args.output)
    if overrides:
        print(f'  {len(overrides)} existing encoding overrides preserved',
              file=sys.stderr)

    # Write output
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, 'w') as f:
        f.write('# host port [encoding]\n')
        f.write('# encoding is optional, defaults to cp437 if omitted\n')
        f.write(f'# generated from {args.relay_cfg}\n')
        f.write(f'# with {removed} MUD entries removed via {args.mudlist}\n')
        for host, port in sorted(bbs_entries):
            enc = overrides.get((host, port), '')
            if enc:
                f.write(f'{host} {port} {enc}\n')
            else:
                f.write(f'{host} {port}\n')

    print(f'Wrote {len(bbs_entries)} entries to {args.output}',
          file=sys.stderr)


if __name__ == '__main__':
    main()
