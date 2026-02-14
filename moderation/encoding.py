"""Encoding discovery, fix, review, and bulk operations."""

import os
import re
import sys
from pathlib import Path

import wcwidth

from make_stats.common import _strip_ansi

from .data import load_server_list
from .util import _prompt


# Quick-filter regex for UTF-8 mojibake in CP437-decoded text.  When
# UTF-8 multi-byte sequences are decoded as CP437, the leading bytes
# 0xE2 and 0xEF produce the characters below.  This pattern matches
# the most common trigrams (box-drawing and block elements) plus the
# UTF-8 BOM.  Used as a fast pre-filter before the full re-encoding
# validation in _detect_utf8_as_cp437().
_UTF8_AS_CP437_RE = re.compile(
    r'\u0393[\u00fb\u00f2\u00f6\u00ea\u00ee\u00e9]'
    r'[\u00e4\u00c7\u00ea\u00c6\u00e6\u2551\u00eb\u00c9\u00a3\u00bc'
    r'\u00f1\u00ac\u00f4\u00fa\u00ee\u00c9\u00c6\u00f2\u00f9\u00e1'
    r'\u00ed\u00f3\u00fa\u2591\u2592\u2593\u2502\u2524\u2551\u2557'
    r'\u255d\u255c\u2510\u2514\u2534\u252c\u251c\u2500\u255a\u2554'
    r'\u2569\u2566\u2560\u2550\u256c\u2518\u250c\u2588\u2584\u258c'
    r'\u2590\u2580\u00aa\u00ba\u00d6\u00dc\w]'
    r'|\u2229\u2557\u2510'
)


def _find_best_encoding(text):
    """Find the encoding that produces the cleanest decode of text.

    :param text: string with possible surrogate escapes or replacement
        chars
    :returns: tuple of (encoding_name, replacement_char_count)
    """
    if not text or '\ufffd' not in text:
        return None, 0

    candidates = ['cp437', 'cp850', 'atascii', 'iso-8859-1', 'ascii']
    best_encoding = None
    best_score = text.count('\ufffd')

    for encoding in candidates:
        try:
            raw = text.encode('utf-8', errors='surrogateescape')
            decoded = raw.decode(encoding, errors='replace')
            score = decoded.count('\ufffd')
            if score < best_score:
                best_score = score
                best_encoding = encoding
        except (UnicodeDecodeError, UnicodeEncodeError, LookupError):
            pass

    return best_encoding, best_score


def _detect_utf8_as_cp437(banner, stored_encoding):
    """Detect banners where UTF-8 content was decoded as CP437.

    When the scanner uses ``--encoding=cp437`` but the server actually
    transmits UTF-8 (common with Synchronet/ENiGMA auto-sensing), the
    multi-byte UTF-8 sequences are split into individual CP437 code
    points, producing characteristic mojibake.

    Returns ``'utf-8'`` if re-encoding as CP437 and decoding as UTF-8
    produces cleaner output, ``None`` otherwise.

    :param banner: banner text as stored (decoded with wrong encoding)
    :param stored_encoding: the encoding used by the scanner
    :returns: ``'utf-8'`` if UTF-8 mojibake detected, else ``None``
    """
    if not banner or stored_encoding not in ('cp437', None):
        return None

    mojibake_hits = len(_UTF8_AS_CP437_RE.findall(banner))
    if mojibake_hits < 3:
        return None

    visible = _strip_ansi(banner)
    try:
        raw = visible.encode('cp437', errors='replace')
        redecoded = raw.decode('utf-8', errors='replace')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None

    original_replacements = visible.count('\ufffd')
    redecoded_replacements = redecoded.count('\ufffd')

    if redecoded_replacements >= mojibake_hits:
        return None

    box_drawing = sum(
        1 for c in redecoded
        if '\u2500' <= c <= '\u259f' or '\u2580' <= c <= '\u259f'
    )
    if box_drawing < 3:
        return None

    return 'utf-8'


def _detect_utf8_native(banner, stored_encoding, list_encoding,
                        default_encoding):
    """Detect UTF-8 banners that need an explicit encoding override.

    When the scanner records UTF-8 but the server list has no encoding
    override, the build's default encoding (e.g. ``cp437`` for BBS)
    would re-decode the banner via :func:`_combine_banners`, corrupting
    genuine Unicode box-drawing and block-element characters.

    :param banner: banner text as stored
    :param stored_encoding: encoding recorded by the scanner
    :param list_encoding: encoding override from the list file, or
        ``None``
    :param default_encoding: build default encoding (e.g. ``'cp437'``),
        or ``None`` when no re-decoding would occur
    :returns: ``'utf-8'`` if an explicit override is needed, else
        ``None``
    """
    if not banner or stored_encoding != 'utf-8':
        return None
    if list_encoding:
        return None
    if not default_encoding or default_encoding == 'utf-8':
        return None

    visible = _strip_ansi(banner)
    box_count = sum(1 for c in visible if '\u2500' <= c <= '\u259f')
    if box_count < 3:
        return None

    return 'utf-8'


def discover_encoding_issues(data_dir='.', list_path=None,
                             default_encoding=None):
    """Scan JSON fingerprint data to find servers with encoding issues.

    :param data_dir: path to server data directory (default ``'.'``)
    :param list_path: path to server list file (mud/bbs list)
    :param default_encoding: build default encoding (e.g. ``'cp437'``
        for BBS); used to detect UTF-8 banners that would be corrupted
        by re-decoding
    :returns: list of dicts with host, port, suggested_encoding
    """
    import json
    from .banner_analysis import _measure_banner_columns

    issues = []
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed_servers = {(h, p) for h, p, _ in list_entries if h and p}
    list_encodings = {}
    for h, p, line in list_entries:
        if h and p:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    int(parts[2])
                except ValueError:
                    list_encodings[(h, p)] = parts[2]

    for fp_dir in sorted(os.listdir(server_dir)):
        fp_path = os.path.join(server_dir, fp_dir)
        if not os.path.isdir(fp_path):
            continue
        for fname in sorted(os.listdir(fp_path)):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(fp_path, fname)
            try:
                with open(fpath, encoding='utf-8',
                          errors='surrogateescape') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            probe = data.get('server-probe', {})
            sessions = data.get('sessions', [])
            if not sessions:
                continue

            session = sessions[-1]
            host = session.get('host', session.get('ip', 'unknown'))
            port = session.get('port', 0)

            if (host, port) not in allowed_servers:
                continue

            session_data = probe.get('session_data', {})
            stored_enc = session_data.get('encoding')
            list_enc = list_encodings.get((host, port))
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')
            after_stripped = _strip_ansi(banner_after).strip()
            if (banner_before and after_stripped
                    and after_stripped not in
                    _strip_ansi(banner_before)):
                banner = (banner_before.rstrip()
                          + '\r\n' + banner_after.lstrip())
            else:
                banner = banner_before or banner_after

            max_width, _ = _measure_banner_columns(banner)

            utf8_suggest = _detect_utf8_as_cp437(
                banner, stored_enc)
            if utf8_suggest:
                mojibake_count = len(
                    _UTF8_AS_CP437_RE.findall(banner))
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': utf8_suggest,
                    'replacement_count': mojibake_count,
                    'reason': 'utf8_mojibake',
                    'list_already_correct':
                        list_enc == utf8_suggest,
                })
                continue

            utf8_native = _detect_utf8_native(
                banner, stored_enc, list_enc, default_encoding)
            if utf8_native:
                visible = _strip_ansi(banner)
                box_count = sum(
                    1 for c in visible
                    if '\u2500' <= c <= '\u259f')
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': utf8_native,
                    'replacement_count': box_count,
                    'reason': 'utf8_native',
                    'list_already_correct': False,
                })
                continue

            if list_enc and stored_enc and list_enc != stored_enc:
                continue

            if max_width < 80 or max_width >= 200:
                continue

            suggested_enc, replacement_count = _find_best_encoding(
                banner)
            if suggested_enc and replacement_count > 0:
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': suggested_enc,
                    'replacement_count': replacement_count,
                    'list_already_correct':
                        list_enc == suggested_enc,
                })

    return issues


def _apply_encoding_fix(list_path, host, port, encoding,
                        dry_run=False):
    """Update a single server's encoding in the list file.

    :param list_path: path to server list file
    :param host: server hostname
    :param port: server port
    :param encoding: new encoding value
    :param dry_run: if True, don't write
    :returns: True if the entry was found and updated
    """
    entries = load_server_list(list_path)
    updated = False
    new_entries = []
    for h, p, line in entries:
        if h == host and p == port:
            parts = line.split()
            if len(parts) >= 4:
                parts[2] = encoding
            elif len(parts) >= 2:
                parts[2:] = [encoding]
            new_entries.append((h, p, ' '.join(parts)))
            updated = True
        else:
            new_entries.append((h, p, line))
    if updated and not dry_run:
        with open(list_path, 'w', encoding='utf-8') as f:
            for _, _, line in new_entries:
                f.write(line + '\n')
    return updated


def _apply_encoding_fixes_bulk(list_path, fixes, dry_run=False):
    """Update encodings for multiple servers in one write.

    :param list_path: path to server list file
    :param fixes: dict mapping (host, port) to new encoding
    :param dry_run: if True, don't write
    :returns: number of entries updated
    """
    entries = load_server_list(list_path)
    updated = 0
    new_entries = []
    for h, p, line in entries:
        if (h, p) in fixes:
            parts = line.split()
            enc = fixes[(h, p)]
            if len(parts) >= 4:
                parts[2] = enc
            elif len(parts) >= 2:
                parts[2:] = [enc]
            new_entries.append((h, p, ' '.join(parts)))
            updated += 1
        else:
            new_entries.append((h, p, line))
    if updated and not dry_run:
        with open(list_path, 'w', encoding='utf-8') as f:
            for _, _, line in new_entries:
                f.write(line + '\n')
    return updated


def _expunge_logs(logs_dir, servers):
    """Delete log files for a list of (host, port) pairs.

    :param logs_dir: path to logs directory
    :param servers: iterable of (host, port) tuples
    :returns: number of log files deleted
    """
    deleted = 0
    for host, port in servers:
        log_file = os.path.join(logs_dir, f"{host}:{port}.log")
        if os.path.isfile(log_file):
            os.remove(log_file)
            deleted += 1
    return deleted


def _expunge_server_json(data_dir, servers):
    """Delete JSON fingerprint data files for a list of servers.

    Scans all protocol fingerprint directories under
    ``data_dir/server/`` for JSON files whose session matches any of
    the given servers, and deletes them so that a re-scan creates fresh
    data.

    :param data_dir: path to data directory (containing ``server/``)
    :param servers: iterable of (host, port) tuples
    :returns: number of JSON files deleted
    """
    import json
    target = set(servers)
    if not target:
        return 0
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return 0

    deleted = 0
    empty_dirs = []
    for fp_dir in os.listdir(server_dir):
        fp_path = os.path.join(server_dir, fp_dir)
        if not os.path.isdir(fp_path):
            continue
        for fname in os.listdir(fp_path):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(fp_path, fname)
            try:
                with open(fpath, encoding='utf-8',
                          errors='surrogateescape') as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            for session in data.get('sessions', []):
                host = session.get('host', session.get('ip', ''))
                port = session.get('port', 0)
                if (host, port) in target:
                    os.remove(fpath)
                    deleted += 1
                    break
        remaining = [
            f for f in os.listdir(fp_path) if f.endswith('.json')
        ]
        if not remaining:
            empty_dirs.append(fp_path)

    for d in empty_dirs:
        try:
            os.rmdir(d)
        except OSError:
            pass

    return deleted


def _review_mojibake_group(issues, list_path, logs_dir, data_dir,
                           mode, report_only=False, dry_run=False):
    """Review a group of UTF-8 mojibake issues as a batch.

    :param issues: list of mojibake issue dicts
    :param list_path: path to server list file
    :param logs_dir: path to logs directory
    :param data_dir: path to data directory (containing ``server/``)
    :param mode: 'mud' or 'bbs'
    :param report_only: if True, don't prompt or modify files
    :param dry_run: if True, show changes without writing
    :returns: number of entries fixed
    """
    need_list_fix = [
        i for i in issues if not i.get('list_already_correct')
    ]
    already_correct = [
        i for i in issues if i.get('list_already_correct')
    ]

    if need_list_fix:
        print(f"\n  {len(need_list_fix)} servers transmitting UTF-8"
              f" but recorded as cp437:")
        for issue in need_list_fix:
            host = issue['host']
            port = issue['port']
            count = issue['replacement_count']
            print(f"    {host}:{port}"
                  f"  ({count} mojibake patterns)")

    if already_correct:
        print(f"\n  {len(already_correct)} servers already listed as"
              f" utf-8 but data still has cp437 mojibake"
              f" (need expunge):")
        for issue in already_correct:
            host = issue['host']
            port = issue['port']
            count = issue['replacement_count']
            print(f"    {host}:{port}"
                  f"  ({count} mojibake patterns)")

    if report_only:
        return 0

    list_basename = os.path.basename(list_path)
    total = len(issues)
    updated = 0

    if need_list_fix:
        print(f"\n  y = set encoding to utf-8 in {list_basename}")
        print(f"  x = set encoding to utf-8 AND expunge data"
              f" (forces fresh re-scan)")
        print(f"  n = skip (default)")
        choice = _prompt(
            f"\n  Apply utf-8 to all {len(need_list_fix)}?"
            f" [y/x/n] ",
            "yxnq")
        if choice == 'q':
            return -1
        if choice in ('y', 'x'):
            fixes = {(i['host'], i['port']): 'utf-8'
                     for i in need_list_fix}
            updated = _apply_encoding_fixes_bulk(
                list_path, fixes, dry_run=dry_run)
            if dry_run:
                print(f"  (dry-run) would update"
                      f" {updated} entries")
            else:
                print(f"  Updated {updated} entries"
                      f" in {list_basename}")
            if choice == 'x' and not dry_run:
                servers = [
                    (i['host'], i['port']) for i in need_list_fix
                ]
                deleted_logs = _expunge_logs(logs_dir, servers)
                deleted_json = _expunge_server_json(
                    data_dir, servers)
                print(f"  Expunged {deleted_logs} log files,"
                      f" {deleted_json} data files"
                      f" (will re-scan with utf-8)")

    if already_correct:
        print(f"\n  x = expunge stale data"
              f" (forces fresh re-scan)")
        print(f"  n = skip (default)")
        choice = _prompt(
            f"\n  Expunge data for {len(already_correct)}"
            f" already-correct servers? [x/n] ", "xnq")
        if choice == 'q':
            return -1 if updated == 0 else updated
        if choice == 'x' and not dry_run:
            servers = [
                (i['host'], i['port']) for i in already_correct
            ]
            deleted_logs = _expunge_logs(logs_dir, servers)
            deleted_json = _expunge_server_json(
                data_dir, servers)
            print(f"  Expunged {deleted_logs} log files,"
                  f" {deleted_json} data files"
                  f" (will re-scan with utf-8)")
            updated += len(already_correct)

    return updated


def review_encoding_issues(mud_issues, bbs_issues, mud_list,
                           bbs_list, logs_dir, mud_data=None,
                           bbs_data=None, report_only=False,
                           dry_run=False):
    """Interactively review and apply encoding fixes.

    UTF-8 mojibake issues (auto-sensing servers) are grouped and
    presented as an all-or-nothing batch.  Other encoding issues
    are reviewed individually.

    :param mud_issues: list of encoding issues from MUD data
    :param bbs_issues: list of encoding issues from BBS data
    :param mud_list: path to MUD server list
    :param bbs_list: path to BBS server list
    :param logs_dir: path to logs directory
    :param mud_data: path to MUD data directory (for JSON expunge)
    :param bbs_data: path to BBS data directory (for JSON expunge)
    :param report_only: if True, don't prompt or modify files
    :param dry_run: if True, show changes without writing
    """
    all_issues = [('mud', mud_issues, mud_list, mud_data),
                  ('bbs', bbs_issues, bbs_list, bbs_data)]
    applied_count = 0

    for mode, issues, list_path, data_dir in all_issues:
        if not issues or not os.path.isfile(list_path):
            continue

        mojibake = [
            i for i in issues
            if i.get('reason') == 'utf8_mojibake'
        ]
        utf8_native = [
            i for i in issues
            if i.get('reason') == 'utf8_native'
        ]
        other = [
            i for i in issues
            if i.get('reason') not in (
                'utf8_mojibake', 'utf8_native')
        ]

        print(f"\n{mode.upper()} encoding issues found:"
              f" {len(issues)}")

        if mojibake:
            result = _review_mojibake_group(
                mojibake, list_path, logs_dir, data_dir, mode,
                report_only=report_only, dry_run=dry_run)
            if result == -1:
                return applied_count
            applied_count += max(result, 0)

        if utf8_native:
            print(f"\n  UTF-8 native banners needing list"
                  f" override: {len(utf8_native)}")
            for issue in utf8_native:
                host = issue['host']
                port = issue['port']
                count = issue['replacement_count']
                print(f"    {host}:{port}"
                      f"  ({count} box-drawing chars)")
            if not report_only:
                choice = _prompt(
                    f"    Add utf-8 override for all"
                    f" {len(utf8_native)} servers? (y/n/q) ",
                    "ynq")
                if choice == 'q':
                    return applied_count
                if choice == 'y':
                    fixes = {(i['host'], i['port']): 'utf-8'
                             for i in utf8_native}
                    result = _apply_encoding_fixes_bulk(
                        list_path, fixes, dry_run=dry_run)
                    applied_count += result

        for issue in other:
            host = issue['host']
            port = issue['port']
            suggested = issue['suggested_encoding']
            print(f"\n  {host}:{port}")
            print(f"    Suggested encoding: {suggested}")
            print(f"    Replacement chars in banner:"
                  f" {issue['replacement_count']}")

            if report_only:
                continue

            choice = _prompt(
                f"    Apply {suggested}? (y/n/q) ", "ynq")
            if choice == 'q':
                return applied_count
            if choice != 'y':
                continue

            if _apply_encoding_fix(
                    list_path, host, port, suggested,
                    dry_run=dry_run):
                if not dry_run:
                    print(f"    Updated"
                          f" {os.path.basename(list_path)}")
                    log_file = os.path.join(
                        logs_dir, f"{host}:{port}.log")
                    if os.path.isfile(log_file):
                        os.remove(log_file)
                        print(f"    Deleted {log_file}")
                    if data_dir:
                        nj = _expunge_server_json(
                            data_dir, [(host, port)])
                        if nj:
                            print(f"    Deleted {nj}"
                                  f" data file(s)")
                applied_count += 1


def _entries_by_encoding(list_path, encoding):
    """Collect list entries matching a given encoding.

    :param list_path: path to server list file
    :param encoding: encoding name to match, or ``'all'`` for all
        entries
    :returns: list of (host, port, entry_encoding) tuples
    """
    result = []
    for host, port, line in load_server_list(list_path):
        if host is None:
            continue
        parts = line.split()
        entry_enc = parts[2] if len(parts) >= 3 else None
        if entry_enc is not None:
            try:
                int(entry_enc)
                entry_enc = None
            except ValueError:
                pass
        if encoding == 'all' or entry_enc == encoding:
            result.append((host, port, entry_enc))
    return result


def _load_banner_for(host, port, data_dir):
    """Load the raw banner for a specific host:port from server data.

    :param host: server hostname or IP
    :param port: server port number
    :param data_dir: path to data directory (containing ``server/``)
    :returns: combined banner string, or empty string if not found
    """
    import json
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return ''
    for fp_dir in os.listdir(server_dir):
        fp_path = os.path.join(server_dir, fp_dir)
        if not os.path.isdir(fp_path):
            continue
        for fname in os.listdir(fp_path):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(fp_path, fname)
            try:
                with open(fpath, encoding='utf-8',
                          errors='surrogateescape') as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            for session in data.get('sessions', []):
                if (session.get('host') == host
                        and session.get('port') == port):
                    sd = data.get(
                        'server-probe', {}
                    ).get('session_data', {})
                    before = sd.get(
                        'banner_before_return', '')
                    after = sd.get(
                        'banner_after_return', '')
                    return (before or '') + (after or '')
    return ''


def show_all_banners(list_path, data_dir, encoding):
    """Display raw banners for all servers matching an encoding.

    Prints each banner to stdout with an ANSI reset and a header
    between them.

    :param list_path: path to server list file
    :param data_dir: path to data directory (containing ``server/``)
    :param encoding: encoding name to match, or ``'all'``
    """
    entries = _entries_by_encoding(list_path, encoding)
    if not entries:
        print(f"No entries with encoding {encoding!r}"
              f" in {list_path}")
        return

    print(f"{len(entries)} entries with encoding {encoding!r}")
    shown = 0
    for host, port, entry_enc in entries:
        banner = _load_banner_for(host, port, data_dir)
        if not banner:
            continue
        shown += 1
        enc_label = f" [{entry_enc}]" if entry_enc else ""
        sys.stdout.write(f"\x1b[0m\n{chr(0x2500) * 60}\n")
        sys.stdout.write(f"  {host}:{port}{enc_label}\n")
        sys.stdout.write(f"{chr(0x2500) * 60}\n")
        sys.stdout.write(banner)
        sys.stdout.write('\x1b[0m\n')
    print(f"\x1b[0m\n{shown}/{len(entries)} banners displayed")


def expunge_all_logs(list_path, logs_dir, encoding, data_dir=None):
    """Delete log and data files for all servers matching an encoding.

    :param list_path: path to server list file
    :param logs_dir: path to logs directory
    :param encoding: encoding name to match, or ``'all'``
    :param data_dir: path to data directory (for JSON expunge)
    """
    entries = _entries_by_encoding(list_path, encoding)
    if not entries:
        print(f"No entries with encoding {encoding!r}"
              f" in {list_path}")
        return

    logs_path = Path(logs_dir)
    deleted_logs = 0
    missing = 0
    for host, port, _ in entries:
        logfile = logs_path / f"{host}:{port}.log"
        if logfile.is_file():
            logfile.unlink()
            deleted_logs += 1
            print(f"  deleted {logfile.name}")
        else:
            missing += 1

    deleted_json = 0
    if data_dir:
        servers = [(h, p) for h, p, _ in entries]
        deleted_json = _expunge_server_json(data_dir, servers)

    print(f"\n{deleted_logs} log(s) deleted,"
          f" {deleted_json} data file(s) deleted,"
          f" {missing} log(s) not found"
          f" (of {len(entries)} {encoding!r} entries)")
