#!/usr/bin/env python
"""Fetch and merge BBS/MUD entries from external sources.

Downloads server listings from external directories, merges new entries
into the local ``bbslist.txt`` and ``mudlist.txt`` files, and preserves
any existing encoding or column overrides.  Cross-list deduplication
ensures hosts already tracked in one list are not added to the other.

Sources:
- BBS: ipingthereforeiam.com relay.cfg, commodorebbs.com JSON API,
  synchro.net sbbsimsg.lst, telnetbbsguide.com ibbs CSV
- MUD: lociterm.com telnetsupport.json
"""

import argparse
import csv
import io
import json
import os
import sys
import urllib.request
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BBSLIST = os.path.join(_HERE, 'bbslist.txt')
DEFAULT_MUDLIST = os.path.join(_HERE, 'mudlist.txt')
DEFAULT_TELNETSUPPORT = os.path.join(_HERE, 'telnetsupport.json')
DEFAULT_DECISIONS = os.path.join(_HERE, 'moderation_decisions.json')
DEFAULT_IBBS_CSV = os.path.join(_HERE, 'ibbs_bbslist.csv')

RELAY_CFG_URL = 'https://www.ipingthereforeiam.com/bbs/dir/relay.cfg'
COMMODOREBBS_URL = 'https://www.commodorebbs.com/api/bbs'
TELNETSUPPORT_URL = 'https://lociterm.com/telnetsupport.json'
IBBS_BASE_URL = 'https://www.telnetbbsguide.com/bbslist/'
SBBSIMSG_URL = 'http://www.synchro.net/sbbs/sbbsimsg.lst'

USER_AGENT = 'modem.xyz/0.1 (telnet census)'


# ---------------------------------------------------------------------------
# List I/O
# ---------------------------------------------------------------------------

def _load_list(path):
    """Load a server list, preserving header and entry data.

    :param path: path to server list file
    :returns: tuple of (header_lines, entries) where header_lines is a list
              of leading comment/blank lines and entries is a dict mapping
              ``(host_lower, port)`` to the original line text
    """
    header_lines = []
    entries = {}
    in_header = True
    if not os.path.isfile(path):
        return header_lines, entries
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            stripped = line.strip()
            if in_header and (not stripped or stripped.startswith('#')):
                header_lines.append(line)
                continue
            in_header = False
            if not stripped or stripped.startswith('#'):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                host = parts[0]
                if parts[1] == 'ssh':
                    entries[(host.lower(), 'ssh')] = stripped
                else:
                    try:
                        port = int(parts[1])
                    except ValueError:
                        continue
                    entries[(host.lower(), port)] = stripped
    return header_lines, entries


def _write_merged_list(path, header_lines, entries, dry_run=False):
    """Write merged server list atomically.

    :param path: target file path
    :param header_lines: leading comment/blank lines to preserve
    :param entries: dict mapping ``(host_lower, port)`` to line text
    :param dry_run: if True, only report what would be written
    """
    sorted_lines = sorted(entries.values(), key=lambda v: v.split()[:2])
    if dry_run:
        print(f"  [dry-run] would write {path}:"
              f" {len(entries)} entries", file=sys.stderr)
        return

    output = path + '.new'
    with open(output, 'w', encoding='utf-8') as f:
        for line in header_lines:
            f.write(line + '\n')
        for line in sorted_lines:
            f.write(line + '\n')
    os.replace(output, path)


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------

def fetch_relay_cfg(source=RELAY_CFG_URL):
    """Fetch BBS entries from ipingthereforeiam.com relay.cfg.

    :param source: URL or local filesystem path
    :returns: list of ``(host, port)`` tuples
    """
    if source.startswith(('http://', 'https://')):
        print(f'  downloading {source} ...', file=sys.stderr)
        req = urllib.request.Request(
            source, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode('utf-8', errors='replace')
    else:
        print(f'  reading {source} ...', file=sys.stderr)
        with open(source, encoding='utf-8', errors='replace') as f:
            text = f.read()

    entries = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            parts = line.rsplit(':', 1)
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                continue
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                continue
        if host and port > 0:
            key = (host.lower(), port)
            if key not in seen:
                seen.add(key)
                entries.append((host, port))
    return entries


def fetch_commodorebbs(url=COMMODOREBBS_URL):
    """Fetch BBS entries from commodorebbs.com JSON API.

    :param url: API endpoint URL
    :returns: list of ``(host, port)`` tuples
    """
    print(f'  downloading {url} ...', file=sys.stderr)
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())

    entries = []
    seen = set()
    for item in data:
        host = (item.get('address') or '').strip()
        port = item.get('port')
        if not host or not port:
            continue
        try:
            port = int(port)
        except (ValueError, TypeError):
            continue
        if port > 0:
            key = (host.lower(), port)
            if key not in seen:
                seen.add(key)
                entries.append((host, port))
    return entries


def fetch_telnetsupport(url=TELNETSUPPORT_URL, local_path=DEFAULT_TELNETSUPPORT):
    """Fetch MUD entries from lociterm.com telnetsupport.json.

    Downloads the JSON and saves a local copy for use by the build
    pipeline (lociterm link annotations).

    :param url: telnetsupport.json URL
    :param local_path: where to save the local copy
    :returns: list of ``(host, port, ssl)`` tuples where *ssl* is bool
    """
    print(f'  downloading {url} ...', file=sys.stderr)
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        data = json.loads(raw)

    output = local_path + '.new'
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    os.replace(output, local_path)
    print(f'  saved {local_path} ({len(data)} entries)', file=sys.stderr)

    entries = []
    seen = set()
    for item in data:
        host = (item.get('host') or '').strip()
        port = item.get('port')
        if not host or not port:
            continue
        try:
            port = int(port)
        except (ValueError, TypeError):
            continue
        if port > 0:
            key = (host.lower(), port)
            if key not in seen:
                seen.add(key)
                entries.append((host, port, item.get('ssl') == 1))
    return entries


def _ibbs_urls():
    """Return (daily_url, monthly_url) with daily = yesterday.

    :returns: tuple of (daily_url, monthly_url)
    """
    from datetime import date, timedelta
    yesterday = date.today() - timedelta(days=1)
    return (
        IBBS_BASE_URL + f"ibbs{yesterday:%m%d%y}.zip",
        IBBS_BASE_URL + f"ibbs{yesterday:%m%y}.zip",
    )


def fetch_ibbs_csv(daily_url=None, monthly_url=None,
                   csv_out=DEFAULT_IBBS_CSV):
    """Fetch BBS entries from telnetbbsguide.com ibbs zip.

    Tries the daily URL (yesterday) first, falls back to monthly.
    Saves the extracted bbslist.csv to csv_out for later use by make_stats.

    :param daily_url: URL for yesterday's daily zip (or None to compute)
    :param monthly_url: URL for monthly zip (or None to compute)
    :param csv_out: path to save extracted bbslist.csv
    :returns: tuple of (telnet_entries, ssh_map) where telnet_entries is a
              list of (host, port) and ssh_map is {host_lower: (host, ssh_port)}
    """
    if daily_url is None or monthly_url is None:
        daily_url, monthly_url = _ibbs_urls()

    zip_data = None
    for url in (daily_url, monthly_url):
        try:
            print(f'  downloading {url} ...', file=sys.stderr)
            req = urllib.request.Request(
                url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                zip_data = resp.read()
            break
        except OSError:
            continue
    if zip_data is None:
        raise OSError('ibbs: all URLs failed')

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        csv_bytes = zf.read('bbslist.csv')

    output = csv_out + '.new'
    with open(output, 'wb') as f:
        f.write(csv_bytes)
    os.replace(output, csv_out)
    print(f'  saved {csv_out}', file=sys.stderr)

    telnet_entries = []
    ssh_map = {}
    seen = set()
    reader = csv.DictReader(
        io.StringIO(csv_bytes.decode('utf-8', errors='replace')))
    for row in reader:
        row = {k.strip(): (v.strip() if v else '') for k, v in row.items()}
        host = row.get('TelnetAddress', '').strip()
        port_str = row.get('TelnetPort', '').strip()
        ssh_port_str = row.get('SSHPort', '').strip()
        if not host:
            continue
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                port = None
            if port and port > 0:
                key = (host.lower(), port)
                if key not in seen:
                    seen.add(key)
                    telnet_entries.append((host, port))
        if ssh_port_str:
            try:
                ssh_port = int(ssh_port_str)
            except ValueError:
                ssh_port = None
            if ssh_port and ssh_port > 0:
                ssh_map[host.lower()] = (host, ssh_port)
    return telnet_entries, ssh_map


def fetch_sbbsimsg(source=SBBSIMSG_URL):
    """Fetch BBS entries from Synchronet sbbsimsg.lst.

    The file is tab-separated with columns: hostname, IP, BBS name.
    All entries are assumed to use port 23 (standard Synchronet telnet).

    :param source: URL or local filesystem path
    :returns: list of ``(host, port)`` tuples
    """
    if source.startswith(('http://', 'https://')):
        print(f'  downloading {source} ...', file=sys.stderr)
        req = urllib.request.Request(
            source, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode('utf-8', errors='replace')
    else:
        print(f'  reading {source} ...', file=sys.stderr)
        with open(source, encoding='utf-8', errors='replace') as f:
            text = f.read()

    entries = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        host = parts[0].strip()
        if not host:
            continue
        key = (host.lower(), 23)
        if key not in seen:
            seen.add(key)
            entries.append((host, 23))
    return entries


def _merge_ssh_entries(existing, ssh_map):
    """Add SSH lines for hosts already tracked as telnet entries.

    :param existing: dict {(host_lower, port_or_'ssh'): line} — modified in place
    :param ssh_map: {host_lower: (host, ssh_port)} from fetch_ibbs_csv
    :returns: number of SSH lines added
    """
    known_hosts = {host for host, _ in existing}
    added = 0
    for host_lower, (host, ssh_port) in ssh_map.items():
        if host_lower in known_hosts and (host_lower, 'ssh') not in existing:
            existing[(host_lower, 'ssh')] = f'{host} ssh {ssh_port}'
            added += 1
    return added


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------

def _load_rejected(path, list_name):
    """Load the rejection set for a given list from decisions file.

    :param path: path to ``moderation_decisions.json``
    :param list_name: ``"mud"`` or ``"bbs"``
    :returns: set of ``(host_lower, port)`` tuples previously rejected
    """
    result = set()
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return result
    bucket = data.get('rejected', {}).get(list_name, {})
    for key in bucket:
        parts = key.rsplit(':', 1)
        if len(parts) == 2:
            try:
                result.add((parts[0].lower(), int(parts[1])))
            except ValueError:
                continue
    return result


def _merge_entries(existing, new_entries, encoding_hint='',
                   rejected=frozenset(), exclude_hosts=frozenset()):
    """Merge new entries into existing list, skipping duplicates.

    :param existing: dict ``{(host_lower, port): line}`` — modified in place
    :param new_entries: list of ``(host, port)`` or ``(host, port, ssl)``
        tuples from a source
    :param encoding_hint: encoding string to add for new entries (or '')
    :param rejected: set of ``(host_lower, port)`` to skip (previously
                     removed by moderation)
    :param exclude_hosts: set of lowercased hostnames already tracked in
                          the other list (cross-list deduplication)
    :returns: tuple of ``(added, skipped_rejected, skipped_alt_port,
              skipped_cross_list)``
    """
    known_hosts = {host for host, _port in existing}
    added = 0
    skipped_rejected = 0
    skipped_alt_port = 0
    skipped_cross_list = 0
    for entry in new_entries:
        host, port = entry[0], entry[1]
        ssl_flag = entry[2] if len(entry) > 2 else False
        key = (host.lower(), port)
        if key in existing:
            continue
        if key in rejected:
            skipped_rejected += 1
            continue
        if host.lower() in exclude_hosts:
            skipped_cross_list += 1
            continue
        if host.lower() in known_hosts:
            skipped_alt_port += 1
            continue
        line = f'{host} {port}'
        if encoding_hint:
            line += f' {encoding_hint}'
        if ssl_flag:
            line += ' ssl'
        existing[key] = line
        known_hosts.add(host.lower())
        added += 1
    return added, skipped_rejected, skipped_alt_port, skipped_cross_list


def _remove_rlogin_dupes(entries):
    """Remove rlogin (port 513) entries when the host has another port.

    :param entries: dict ``{(host_lower, port): line}`` — modified in place
    :returns: number of rlogin entries removed
    """
    hosts = {}
    for host, port in entries:
        hosts.setdefault(host, set()).add(port)

    removed = 0
    for host, ports in hosts.items():
        if 513 in ports and len(ports) > 1:
            del entries[(host, 513)]
            removed += 1
    return removed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    """Fetch and merge BBS/MUD entries from external sources."""
    parser = argparse.ArgumentParser(
        description='Fetch and merge BBS/MUD entries from external sources.')
    parser.add_argument(
        '--bbs', action='store_true',
        help='update BBS list only')
    parser.add_argument(
        '--muds', action='store_true',
        help='update MUD list only')
    parser.add_argument(
        '--dry-run', action='store_true',
        help='show what would change without writing')
    parser.add_argument(
        '--bbslist', default=DEFAULT_BBSLIST,
        help='path to bbslist.txt')
    parser.add_argument(
        '--mudlist', default=DEFAULT_MUDLIST,
        help='path to mudlist.txt')
    parser.add_argument(
        '--relay-cfg', default=RELAY_CFG_URL,
        help='URL or path for relay.cfg')
    parser.add_argument(
        '--no-relay-cfg', action='store_true',
        help='skip relay.cfg source')
    parser.add_argument(
        '--no-commodorebbs', action='store_true',
        help='skip commodorebbs.com source')
    parser.add_argument(
        '--no-telnetsupport', action='store_true',
        help='skip lociterm.com telnetsupport source')
    parser.add_argument(
        '--ignore-rejections', action='store_true',
        help='ignore moderation rejection list')
    parser.add_argument(
        '--decisions', default=DEFAULT_DECISIONS,
        help='path to moderation_decisions.json')
    parser.add_argument(
        '--no-ibbs', action='store_true',
        help='skip telnetbbsguide.com ibbs source')
    parser.add_argument(
        '--ibbs-csv', default=DEFAULT_IBBS_CSV,
        help='path to save ibbs_bbslist.csv')
    parser.add_argument(
        '--no-sbbsimsg', action='store_true',
        help='skip synchro.net sbbsimsg source')
    parser.add_argument(
        '--sbbsimsg', default=SBBSIMSG_URL,
        help='URL or path for sbbsimsg.lst')
    args = parser.parse_args(argv)

    do_bbs = args.bbs or not (args.bbs or args.muds)
    do_muds = args.muds or not (args.bbs or args.muds)

    # Load both lists upfront for cross-list deduplication by host.
    _, mud_entries = _load_list(args.mudlist)
    mud_hosts = {host for host, _port in mud_entries}
    _, bbs_entries = _load_list(args.bbslist)
    bbs_hosts = {host for host, _port in bbs_entries}

    if do_bbs:
        print('BBS list update:', file=sys.stderr)
        header, entries = _load_list(args.bbslist)
        before = len(entries)
        rejected = (frozenset() if args.ignore_rejections
                    else _load_rejected(args.decisions, 'bbs'))
        if rejected:
            print(f'  {len(rejected)} previously rejected'
                  f' entries loaded', file=sys.stderr)
        print(f'  {len(mud_hosts)} mud hosts excluded'
              f' (cross-list)', file=sys.stderr)

        if not args.no_relay_cfg:
            try:
                relay = fetch_relay_cfg(args.relay_cfg)
                n, rej, alt, cross = _merge_entries(
                    entries, relay, rejected=rejected,
                    exclude_hosts=mud_hosts)
                msg = f'  relay.cfg: {len(relay)} fetched, {n} new'
                if rej:
                    msg += f', {rej} rejected'
                if alt:
                    msg += f', {alt} alt-port skipped'
                if cross:
                    msg += f', {cross} in mudlist'
                print(msg, file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f'  relay.cfg: fetch failed ({exc})',
                      file=sys.stderr)

        if not args.no_commodorebbs:
            try:
                cbbs = fetch_commodorebbs()
                n, rej, alt, cross = _merge_entries(
                    entries, cbbs, encoding_hint='petscii',
                    rejected=rejected, exclude_hosts=mud_hosts)
                msg = (f'  commodorebbs.com: {len(cbbs)} fetched,'
                       f' {n} new (petscii)')
                if rej:
                    msg += f', {rej} rejected'
                if alt:
                    msg += f', {alt} alt-port skipped'
                if cross:
                    msg += f', {cross} in mudlist'
                print(msg, file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f'  commodorebbs.com: fetch failed ({exc})',
                      file=sys.stderr)

        if not args.no_ibbs:
            try:
                ibbs_t, ibbs_ssh = fetch_ibbs_csv(csv_out=args.ibbs_csv)
                n, rej, alt, cross = _merge_entries(
                    entries, ibbs_t, rejected=rejected,
                    exclude_hosts=mud_hosts)
                n_ssh = _merge_ssh_entries(entries, ibbs_ssh)
                print(f'  ibbs: {len(ibbs_t)} fetched,'
                      f' {n} new telnet, {n_ssh} new SSH',
                      file=sys.stderr)
            except (OSError, ValueError, KeyError) as exc:
                print(f'  ibbs: fetch failed ({exc})', file=sys.stderr)

        if not args.no_sbbsimsg:
            try:
                sbbs = fetch_sbbsimsg(args.sbbsimsg)
                n, rej, alt, cross = _merge_entries(
                    entries, sbbs, rejected=rejected,
                    exclude_hosts=mud_hosts)
                msg = f'  sbbsimsg: {len(sbbs)} fetched, {n} new'
                if rej:
                    msg += f', {rej} rejected'
                if alt:
                    msg += f', {alt} alt-port skipped'
                if cross:
                    msg += f', {cross} in mudlist'
                print(msg, file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f'  sbbsimsg: fetch failed ({exc})',
                      file=sys.stderr)

        rlogin_removed = _remove_rlogin_dupes(entries)
        if rlogin_removed:
            print(f'  rlogin dedup: {rlogin_removed} port-513'
                  f' entries removed', file=sys.stderr)

        after = len(entries)
        print(f'  total: {after - before} entries added'
              f' ({before} -> {after})', file=sys.stderr)
        if after > before or rlogin_removed:
            _write_merged_list(args.bbslist, header, entries,
                               dry_run=args.dry_run)

    if do_muds:
        print('MUD list update:', file=sys.stderr)
        header, entries = _load_list(args.mudlist)
        before = len(entries)
        rejected = (frozenset() if args.ignore_rejections
                    else _load_rejected(args.decisions, 'mud'))
        if rejected:
            print(f'  {len(rejected)} previously rejected'
                  f' entries loaded', file=sys.stderr)
        print(f'  {len(bbs_hosts)} bbs hosts excluded'
              f' (cross-list)', file=sys.stderr)

        if not args.no_telnetsupport:
            try:
                ts = fetch_telnetsupport(
                    local_path=DEFAULT_TELNETSUPPORT)
                n, rej, alt, cross = _merge_entries(
                    entries, ts, rejected=rejected,
                    exclude_hosts=bbs_hosts)
                msg = (f'  telnetsupport.json:'
                       f' {len(ts)} fetched, {n} new')
                if rej:
                    msg += f', {rej} rejected'
                if alt:
                    msg += f', {alt} alt-port skipped'
                if cross:
                    msg += f', {cross} in bbslist'
                print(msg, file=sys.stderr)
            except (OSError, ValueError) as exc:
                print(f'  telnetsupport.json: fetch failed'
                      f' ({exc})', file=sys.stderr)

        rlogin_removed = _remove_rlogin_dupes(entries)
        if rlogin_removed:
            print(f'  rlogin dedup: {rlogin_removed} port-513'
                  f' entries removed', file=sys.stderr)

        after = len(entries)
        print(f'  total: {after - before} entries added'
              f' ({before} -> {after})', file=sys.stderr)
        if after > before or rlogin_removed:
            _write_merged_list(args.mudlist, header, entries,
                               dry_run=args.dry_run)


if __name__ == '__main__':
    main()
