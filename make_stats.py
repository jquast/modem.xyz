#!/usr/bin/env python
"""Generate RST documentation and plots from server fingerprint data.

Unified entry point for both MUD and BBS statistics generation.
Uses telnetlib3 scan data to produce Sphinx-ready RST pages and
matplotlib plots.

Usage::

    python make_stats.py --muds [--data-dir PATH] [--logs-dir PATH]
    python make_stats.py --bbs  [--data-dir PATH] [--logs-dir PATH]
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description='Generate server statistics site from'
                    ' telnetlib3 data.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--muds', action='store_true',
        help='Generate MUD server statistics (docs-muds/)')
    group.add_argument(
        '--bbs', action='store_true',
        help='Generate BBS server statistics (docs-bbs/)')

    parser.add_argument(
        '--data-dir',
        help='Path to data directory'
             ' (default: data-muds/ or data-bbs/)')
    parser.add_argument(
        '--logs-dir',
        help='Path to scan log directory (default: logs/)')
    parser.add_argument(
        '--server-list',
        help='Path to server list file'
             ' (default: mudlist.txt or bbslist.txt)')
    parser.add_argument(
        '--force', action='store_true',
        help='Regenerate all RST files, ignoring mtime checks')
    parser.add_argument(
        '--no-crt-effects', action='store_true',
        help='Disable CRT bloom and scanline post-processing on banners')

    args = parser.parse_args()

    if args.muds:
        from make_stats.muds import run
    else:
        from make_stats.bbs import run

    run(args)


if __name__ == '__main__':
    main()
