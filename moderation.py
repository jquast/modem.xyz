#!/usr/bin/env python
"""Interactive moderation tool for MUD and BBS server lists.

Combines dead-entry pruning, within-list duplicate detection, cross-list
conflict resolution, and encoding issue discovery into a single workflow.

Modes (run all by default, or select one):
  --only-dns        Only remove IP entries that duplicate a hostname (auto)
  --only-prune      Only prune dead servers (no fingerprint data)
  --only-dupes      Only find within-list duplicates
  --only-cross      Only find entries present in both MUD and BBS lists
  --only-encodings  Only discover and suggest encoding fixes
  --only-columns    Only discover and suggest column width overrides
  --only-empty      Only find servers with fingerprint data but empty banners
  --only-renders-empty  Only find banners that render to an empty screen
  --only-renders-small  Only find banners whose rendered PNGs are tiny (<1KB)

Scope (moderate both by default, or select one):
  --mud           Only moderate the MUD list
  --bbs           Only moderate the BBS list

Bulk encoding operations:
  --show-all=ENC     Display raw banners for all servers with encoding ENC
  --expunge-all=ENC  Delete log files for all servers with encoding ENC
                     Use 'all' to match every encoding.

Other options:
  --report-only   Print report without interactive prompts
  --prune-data    Offer to delete data files for removed entries
  --dry-run       Show what would change without writing files
"""

import collections
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import wcwidth

_BAT = shutil.which("bat") or shutil.which("batcat")
_JQ = shutil.which("jq")
_DIGITS_RE = re.compile(r"\d+")

# Default paths relative to this script
_HERE = Path(__file__).resolve().parent
DEFAULT_MUD_LIST = _HERE / "mudlist.txt"
DEFAULT_BBS_LIST = _HERE / "bbslist.txt"
DEFAULT_MUD_DATA = _HERE  # scan.py defaults to list file directory
DEFAULT_BBS_DATA = _HERE  # scan.py defaults to list file directory
DEFAULT_LOGS = _HERE / "logs"
DEFAULT_DECISIONS = _HERE / "moderation_decisions.json"


# Utility helpers

def _strip_ansi(text):
    """Remove all terminal escape sequences (CSI, OSC, DCS, etc.)."""
    return wcwidth.strip_sequences(text)


def _normalize_banner(text):
    """Normalize banner for comparison: strip ANSI, digits, whitespace."""
    text = _strip_ansi(text)
    text = _DIGITS_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _banner_hash(text):
    """Hash normalized banner text for grouping."""
    normalized = _normalize_banner(text)
    if not normalized:
        return ""
    return hashlib.sha256(
        normalized.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


def _normalize_mssp_name(name):
    """Normalize MSSP NAME for comparison."""
    return name.strip().lower()


def _print_json(label, data):
    """Print labeled JSON, colorized through bat or jq when available."""
    raw = json.dumps(data, indent=4, sort_keys=True)
    if _BAT:
        r = subprocess.run(
            [_BAT, "-l", "json", "--style=plain", "--color=always"],
            input=raw, capture_output=True, text=True, check=False,
        )
        if r.returncode == 0:
            raw = r.stdout.rstrip("\n")
    elif _JQ:
        r = subprocess.run(
            [_JQ, "-C", "."],
            input=raw, capture_output=True, text=True, check=False,
        )
        if r.returncode == 0:
            raw = r.stdout.rstrip("\n")
    print(f"{label} {raw}")


def _display_banner(text, maxlines=8):
    """Format banner for compact display."""
    text = _strip_ansi(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > maxlines:
        shown = lines[:maxlines]
        shown.append(f"  ... ({len(lines) - maxlines} more lines)")
        return "\n".join(shown)
    return "\n".join(lines)


def _prompt(message, choices="ynq"):
    """Prompt user for a single-character choice.

    :param message: prompt text
    :param choices: string of valid characters
    :returns: lowercase character, or None on EOF/interrupt
    """
    try:
        answer = input(message).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if answer and answer[0] in choices:
        return answer[0]
    return answer


# DNS helpers

def _is_ip_address(host):
    """Check whether *host* is a literal IP address (v4 or v6).

    :param host: hostname or IP string
    :returns: True if *host* is a valid IP address
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_hostnames(hostnames, workers=8):
    """Resolve a collection of hostnames to their IP addresses.

    Uses a thread pool with a small worker count to be gentle on DNS.

    :param hostnames: iterable of hostname strings
    :param workers: number of parallel resolver threads
    :returns: dict mapping hostname to set of resolved IP strings
    """
    hostnames = list(hostnames)
    results = {}

    def _resolve(host):
        try:
            infos = socket.getaddrinfo(
                host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return host, {info[4][0] for info in infos}
        except (socket.gaierror, OSError):
            return host, set()

    total = len(hostnames)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, (host, ips) in enumerate(
                pool.map(_resolve, hostnames), 1):
            results[host] = ips
            if done % 100 == 0 or done == total:
                print(f"  resolved {done}/{total} hostnames",
                      file=sys.stderr, end="\r")
    print(file=sys.stderr)
    return results


# Decision cache

def load_decisions(path):
    """Load cached moderation decisions from a JSON file.

    :param path: path to the decisions file
    :returns: dict with ``"cross"`` and ``"dupes"`` keys
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault("cross", {})
    data.setdefault("dupes", {})
    data.setdefault("dns", {})
    return data


def save_decisions(path, decisions):
    """Save moderation decisions atomically.

    :param path: path to write the decisions file
    :param decisions: dict with ``"cross"`` and ``"dupes"`` keys
    """
    output = Path(str(path) + ".new")
    with open(output, "w", encoding="utf-8") as f:
        json.dump(decisions, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(output, path)


def _group_cache_key(members):
    """Create a stable cache key from a group of records.

    :param members: list of record dicts with ``host`` and ``port`` keys
    :returns: string key (sorted ``host:port`` pairs joined by ``|``)
    """
    parts = sorted(f"{r['host']}:{r['port']}" for r in members)
    return "|".join(parts)


# Encoding discovery

def _find_best_encoding(text):
    """Find the encoding that produces the cleanest decode of text.

    :param text: string with possible surrogate escapes or replacement chars
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


# Quick-filter regex for UTF-8 mojibake in CP437-decoded text.  When
# UTF-8 multi-byte sequences are decoded as CP437, the leading bytes
# 0xE2 and 0xEF produce Γ and ∩ respectively.  This pattern matches
# the most common trigrams (box-drawing and block elements) plus the
# UTF-8 BOM.  Used as a fast pre-filter before the full re-encoding
# validation in _detect_utf8_as_cp437().
_UTF8_AS_CP437_RE = re.compile(
    r'Γ[ûòöêîé][äÇêÆæ║ëÉ£¼ñ¬ôúîÉÆòùáíóú░▒▓│┤║╗╝╜┐└┴┬├─╚╔╩╦╠═╬┘┌█▄▌▐▀ªºÖÜ\w]'
    r'|∩╗┐'
)


def _detect_utf8_as_cp437(banner, stored_encoding):
    """Detect banners where UTF-8 content was decoded as CP437.

    When the scanner uses ``--encoding=cp437`` but the server actually
    transmits UTF-8 (common with Synchronet/ENiGMA auto-sensing), the
    multi-byte UTF-8 sequences are split into individual CP437 code
    points, producing characteristic mojibake like ``Γûä`` for ``▄``.

    Returns ``'utf-8'`` if re-encoding as CP437 and decoding as UTF-8
    produces cleaner output, ``None`` otherwise.

    :param banner: banner text as stored (decoded with wrong encoding)
    :param stored_encoding: the encoding used by the scanner
    :returns: ``'utf-8'`` if UTF-8 mojibake detected, else ``None``
    """
    if not banner or stored_encoding not in ('cp437', None):
        return None

    # Quick check: does the banner contain known mojibake patterns?
    mojibake_hits = len(_UTF8_AS_CP437_RE.findall(banner))
    if mojibake_hits < 3:
        return None

    # Try the reverse: re-encode as cp437, decode as UTF-8.
    visible = _strip_ansi(banner)
    try:
        raw = visible.encode('cp437', errors='replace')
        redecoded = raw.decode('utf-8', errors='replace')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None

    # Count how much damage each interpretation has.
    original_replacements = visible.count('\ufffd')
    redecoded_replacements = redecoded.count('\ufffd')

    # The re-decoded version must be strictly better: fewer replacement
    # chars than mojibake hits in the original.
    if redecoded_replacements >= mojibake_hits:
        return None

    # Sanity check: the re-decoded text should contain real Unicode
    # box-drawing or block-element characters, confirming it was UTF-8.
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
    override, the build's default encoding (e.g. ``cp437`` for BBS) would
    re-decode the banner via :func:`_combine_banners`, corrupting genuine
    Unicode box-drawing and block-element characters.

    :param banner: banner text as stored
    :param stored_encoding: encoding recorded by the scanner
    :param list_encoding: encoding override from the list file, or ``None``
    :param default_encoding: build default encoding (e.g. ``'cp437'``),
        or ``None`` when no re-decoding would occur
    :returns: ``'utf-8'`` if an explicit override is needed, else ``None``
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
    :param default_encoding: build default encoding (e.g. ``'cp437'`` for
        BBS); used to detect UTF-8 banners that would be corrupted by
        re-decoding
    :returns: list of dicts with host, port, suggested_encoding
    """
    issues = []
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    # Load server list to know which servers to check, and their
    # current encoding overrides so we skip already-fixed entries.
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

    # Scan fingerprint data
    for fp_dir in sorted(os.listdir(server_dir)):
        fp_path = os.path.join(server_dir, fp_dir)
        if not os.path.isdir(fp_path):
            continue
        for fname in sorted(os.listdir(fp_path)):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(fp_path, fname)
            try:
                with open(fpath, encoding='utf-8', errors='surrogateescape') as f:
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
            banner_before = session_data.get('banner_before_return', '')
            banner_after = session_data.get('banner_after_return', '')
            after_stripped = _strip_ansi(banner_after).strip()
            if (banner_before and after_stripped
                    and after_stripped not in _strip_ansi(banner_before)):
                banner = banner_before.rstrip() + '\r\n' + banner_after.lstrip()
            else:
                banner = banner_before or banner_after

            max_width, _ = _measure_banner_columns(banner)

            # Check for UTF-8 content mis-decoded as CP437 first, since
            # mojibake inflates apparent width ~3x (each UTF-8 char
            # becomes 3 cp437 chars), which would fail the width filter.
            utf8_suggest = _detect_utf8_as_cp437(banner, stored_enc)
            if utf8_suggest:
                mojibake_count = len(_UTF8_AS_CP437_RE.findall(banner))
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': utf8_suggest,
                    'replacement_count': mojibake_count,
                    'reason': 'utf8_mojibake',
                    'list_already_correct': list_enc == utf8_suggest,
                })
                continue

            # Check for genuine UTF-8 banners that need an explicit
            # override to prevent re-decoding to the build default.
            utf8_native = _detect_utf8_native(
                banner, stored_enc, list_enc, default_encoding)
            if utf8_native:
                visible = _strip_ansi(banner)
                box_count = sum(
                    1 for c in visible if '\u2500' <= c <= '\u259f')
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': utf8_native,
                    'replacement_count': box_count,
                    'reason': 'utf8_native',
                    'list_already_correct': False,
                })
                continue

            # Skip servers whose list encoding already differs from
            # what the scanner recorded — encoding override is in
            # place and a re-scan will use it.  (Checked after the
            # mojibake detector so stale data with mojibake is still
            # caught even when the list is already correct.)
            if list_enc and stored_enc and list_enc != stored_enc:
                continue

            if max_width < 80 or max_width >= 200:
                continue

            suggested_enc, replacement_count = _find_best_encoding(banner)
            if suggested_enc and replacement_count > 0:
                issues.append({
                    'host': host,
                    'port': port,
                    'suggested_encoding': suggested_enc,
                    'replacement_count': replacement_count,
                    'list_already_correct': list_enc == suggested_enc,
                })

    return issues


def _apply_encoding_fix(list_path, host, port, encoding, dry_run=False):
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
    """Delete JSON fingerprint data files for a list of (host, port) pairs.

    Scans all protocol fingerprint directories under ``data_dir/server/``
    for JSON files whose session matches any of the given servers, and
    deletes them so that a re-scan creates fresh data.

    :param data_dir: path to data directory (containing ``server/``)
    :param servers: iterable of (host, port) tuples
    :returns: number of JSON files deleted
    """
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
        # Track empty fingerprint directories for cleanup.
        remaining = [f for f in os.listdir(fp_path) if f.endswith('.json')]
        if not remaining:
            empty_dirs.append(fp_path)

    for d in empty_dirs:
        try:
            os.rmdir(d)
        except OSError:
            pass

    return deleted


def _review_mojibake_group(issues, list_path, logs_dir, data_dir, mode,
                           report_only=False, dry_run=False):
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
    need_list_fix = [i for i in issues if not i.get('list_already_correct')]
    already_correct = [i for i in issues if i.get('list_already_correct')]

    if need_list_fix:
        print(f"\n  {len(need_list_fix)} servers transmitting UTF-8"
              f" but recorded as cp437:")
        for issue in need_list_fix:
            host = issue['host']
            port = issue['port']
            count = issue['replacement_count']
            print(f"    {host}:{port}  ({count} mojibake patterns)")

    if already_correct:
        print(f"\n  {len(already_correct)} servers already listed as utf-8"
              f" but data still has cp437 mojibake (need expunge):")
        for issue in already_correct:
            host = issue['host']
            port = issue['port']
            count = issue['replacement_count']
            print(f"    {host}:{port}  ({count} mojibake patterns)")

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
            f"\n  Apply utf-8 to all {len(need_list_fix)}? [y/x/n] ",
            "yxnq")
        if choice == 'q':
            return -1
        if choice in ('y', 'x'):
            fixes = {(i['host'], i['port']): 'utf-8'
                     for i in need_list_fix}
            updated = _apply_encoding_fixes_bulk(
                list_path, fixes, dry_run=dry_run)
            if dry_run:
                print(f"  (dry-run) would update {updated} entries")
            else:
                print(f"  Updated {updated} entries in {list_basename}")
            if choice == 'x' and not dry_run:
                servers = [(i['host'], i['port']) for i in need_list_fix]
                deleted_logs = _expunge_logs(logs_dir, servers)
                deleted_json = _expunge_server_json(data_dir, servers)
                print(f"  Expunged {deleted_logs} log files,"
                      f" {deleted_json} data files"
                      f" (will re-scan with utf-8)")

    if already_correct:
        print(f"\n  x = expunge stale data (forces fresh re-scan)")
        print(f"  n = skip (default)")
        choice = _prompt(
            f"\n  Expunge data for {len(already_correct)}"
            f" already-correct servers? [x/n] ", "xnq")
        if choice == 'q':
            return -1 if updated == 0 else updated
        if choice == 'x' and not dry_run:
            servers = [(i['host'], i['port']) for i in already_correct]
            deleted_logs = _expunge_logs(logs_dir, servers)
            deleted_json = _expunge_server_json(data_dir, servers)
            print(f"  Expunged {deleted_logs} log files,"
                  f" {deleted_json} data files"
                  f" (will re-scan with utf-8)")
            updated += len(already_correct)

    return updated


def review_encoding_issues(mud_issues, bbs_issues, mud_list, bbs_list,
                           logs_dir, mud_data=None, bbs_data=None,
                           report_only=False, dry_run=False):
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

        mojibake = [i for i in issues if i.get('reason') == 'utf8_mojibake']
        utf8_native = [i for i in issues if i.get('reason') == 'utf8_native']
        other = [i for i in issues
                 if i.get('reason') not in ('utf8_mojibake', 'utf8_native')]

        print(f"\n{mode.upper()} encoding issues found: {len(issues)}")

        # Batch review for UTF-8 mojibake group
        if mojibake:
            result = _review_mojibake_group(
                mojibake, list_path, logs_dir, data_dir, mode,
                report_only=report_only, dry_run=dry_run)
            if result == -1:  # quit
                return applied_count
            applied_count += max(result, 0)

        # UTF-8 native: scanner data is valid, just add list override.
        # No expunge needed — the data is already correctly encoded.
        if utf8_native:
            print(f"\n  UTF-8 native banners needing list override:"
                  f" {len(utf8_native)}")
            for issue in utf8_native:
                host = issue['host']
                port = issue['port']
                count = issue['replacement_count']
                print(f"    {host}:{port}"
                      f"  ({count} box-drawing chars)")
            if not report_only:
                choice = _prompt(
                    f"    Add utf-8 override for all {len(utf8_native)}"
                    f" servers? (y/n/q) ", "ynq")
                if choice == 'q':
                    return applied_count
                if choice == 'y':
                    fixes = {(i['host'], i['port']): 'utf-8'
                             for i in utf8_native}
                    result = _apply_encoding_fixes_bulk(
                        list_path, fixes, dry_run=dry_run)
                    applied_count += result

        # Individual review for other encoding issues
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

            choice = _prompt(f"    Apply {suggested}? (y/n/q) ", "ynq")
            if choice == 'q':
                return applied_count
            if choice != 'y':
                continue

            if _apply_encoding_fix(list_path, host, port, suggested,
                                   dry_run=dry_run):
                if not dry_run:
                    print(f"    Updated {os.path.basename(list_path)}")
                    log_file = os.path.join(logs_dir, f"{host}:{port}.log")
                    if os.path.isfile(log_file):
                        os.remove(log_file)
                        print(f"    Deleted {log_file}")
                    if data_dir:
                        nj = _expunge_server_json(
                            data_dir, [(host, port)])
                        if nj:
                            print(f"    Deleted {nj} data file(s)")
                applied_count += 1


# Bulk encoding operations

def _entries_by_encoding(list_path, encoding):
    """Collect list entries matching a given encoding.

    :param list_path: path to server list file
    :param encoding: encoding name to match, or ``'all'`` for all entries
    :returns: list of (host, port, entry_encoding) tuples
    """
    result = []
    for host, port, line in load_server_list(list_path):
        if host is None:
            continue
        parts = line.split()
        entry_enc = parts[2] if len(parts) >= 3 else None
        # Skip entries whose third field is a number (column override, no encoding)
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
    """Load the raw banner for a specific host:port from server JSON data.

    :param host: server hostname or IP
    :param port: server port number
    :param data_dir: path to data directory (containing ``server/``)
    :returns: combined banner string, or empty string if not found
    """
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
                if session.get('host') == host and session.get('port') == port:
                    sd = data.get('server-probe', {}).get('session_data', {})
                    before = sd.get('banner_before_return', '')
                    after = sd.get('banner_after_return', '')
                    return (before or '') + (after or '')
    return ''


def show_all_banners(list_path, data_dir, encoding):
    """Display raw banners for all servers matching an encoding.

    Prints each banner to stdout with an ANSI reset and a header between them.

    :param list_path: path to server list file
    :param data_dir: path to data directory (containing ``server/``)
    :param encoding: encoding name to match, or ``'all'``
    """
    entries = _entries_by_encoding(list_path, encoding)
    if not entries:
        print(f"No entries with encoding {encoding!r} in {list_path}")
        return

    print(f"{len(entries)} entries with encoding {encoding!r}")
    shown = 0
    for host, port, entry_enc in entries:
        banner = _load_banner_for(host, port, data_dir)
        if not banner:
            continue
        shown += 1
        enc_label = f" [{entry_enc}]" if entry_enc else ""
        sys.stdout.write(f"\x1b[0m\n{'─' * 60}\n")
        sys.stdout.write(f"  {host}:{port}{enc_label}\n")
        sys.stdout.write(f"{'─' * 60}\n")
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
        print(f"No entries with encoding {encoding!r} in {list_path}")
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

    print(f"\n{deleted_logs} log(s) deleted, {deleted_json} data file(s)"
          f" deleted, {missing} log(s) not found"
          f" (of {len(entries)} {encoding!r} entries)")


# Column width discovery

def _measure_banner_columns(text):
    """Measure visible line widths in banner text.

    :param text: banner text, may contain ANSI escape sequences
    :returns: tuple of (max_width, all_narrow) where *all_narrow* is
        True when no line exceeds 40 columns
    """
    if not text:
        return 0, True
    max_width = 0
    for line in text.splitlines():
        stripped = _strip_ansi(line).rstrip()
        w = wcwidth.wcswidth(stripped)
        if w < 0:
            w = len(stripped)
        if w > max_width:
            max_width = w
    return max_width, max_width <= 40


def _suggest_columns(max_width):
    """Round a measured width to the nearest 10 at or above, minimum 40.

    :param max_width: maximum observed line width
    :returns: suggested column width (multiple of 10, at least 40)
    """
    return max(40, ((max_width + 9) // 10) * 10)


def discover_column_width_issues(data_dir, list_path):
    """Scan JSON fingerprint data to find servers needing column overrides.

    Flags servers whose banners exceed 80 columns or never exceed 40.

    :param data_dir: path to server data directory
    :param list_path: path to server list file (mud/bbs list)
    :returns: list of dicts with host, port, max_width, suggested_columns
    """
    issues = []
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed_servers = {(h, p) for h, p, _ in list_entries if h and p}

    # Build set of servers that already have a column override
    has_override = set()
    for h, p, line in list_entries:
        if h and p:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    int(parts[3])
                    has_override.add((h, p))
                except ValueError:
                    pass

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
            if (host, port) in has_override:
                continue

            session_data = probe.get('session_data', {})
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')
            banner = banner_before or banner_after
            if not banner:
                continue

            max_width, all_narrow = _measure_banner_columns(banner)

            if max_width > 80 or (all_narrow and max_width > 0):
                suggested = _suggest_columns(max_width)
                if suggested == 80:
                    continue
                issues.append({
                    'host': host,
                    'port': port,
                    'max_width': max_width,
                    'suggested_columns': suggested,
                    'banner': banner,
                })

    return issues


def review_column_width_issues(mud_issues, bbs_issues,
                               mud_list, bbs_list, logs_dir,
                               report_only=False, dry_run=False):
    """Interactively review and apply column width overrides.

    :param mud_issues: list of column width issues from MUD data
    :param bbs_issues: list of column width issues from BBS data
    :param mud_list: path to MUD server list
    :param bbs_list: path to BBS server list
    :param logs_dir: path to logs directory
    :param report_only: if True, don't prompt or modify files
    :param dry_run: if True, show changes without writing
    """
    all_issues = [
        ('mud', mud_issues, mud_list),
        ('bbs', bbs_issues, bbs_list),
    ]
    applied_count = 0

    for mode, issues, list_path in all_issues:
        if not issues or not os.path.isfile(list_path):
            continue

        print(f"\n{mode.upper()} column width issues: {len(issues)}")
        for issue in issues:
            host = issue['host']
            port = issue['port']
            max_w = issue['max_width']
            suggested = issue['suggested_columns']
            banner = issue['banner']

            print(f"\n  {host}:{port}")
            print(f"    Max line width: {max_w}")
            print(f"    Suggested columns: {suggested}")

            # Preview: wrap each paragraph at the suggested width
            print(f"    Preview at {suggested} columns:")
            print(f"    {'─' * suggested}")
            for para in _strip_ansi(banner).splitlines():
                if not para.strip():
                    print()
                    continue
                for wrapped in wcwidth.wrap(para, suggested):
                    print(f"    {wrapped}")
            print(f"    {'─' * suggested}")

            if report_only:
                continue

            choice = _prompt(
                f"    Apply {suggested} columns? (Y/n/q/NUMBER) ",
                "ynq")
            if choice == 'q':
                return applied_count
            if choice == 'n':
                continue

            # Allow entering a custom column width as a number
            columns = suggested
            if choice and choice not in 'ynq':
                try:
                    columns = int(choice)
                except ValueError:
                    print(f"    Invalid number: {choice!r}, skipping")
                    continue

            entries = load_server_list(list_path)
            updated = False
            new_entries = []
            for h, p, line in entries:
                if h == host and p == port:
                    parts = line.split()
                    if len(parts) >= 4:
                        parts[3] = str(columns)
                    elif len(parts) >= 3:
                        parts.append(str(columns))
                    elif len(parts) >= 2:
                        parts.extend(['utf-8', str(columns)])
                    new_entries.append((h, p, ' '.join(parts)))
                    updated = True
                else:
                    new_entries.append((h, p, line))

            if updated and not dry_run:
                with open(list_path, 'w', encoding='utf-8') as f:
                    for _, _, line in new_entries:
                        f.write(line + '\n')
                print(f"    ✓ Updated {list_path} ({columns} columns)")
                applied_count += 1


# Empty banner discovery

def discover_empty_banners(data_dir, list_path, logs_dir):
    """Find servers with fingerprint data but empty banners.

    These are servers that connected and completed telnet negotiation
    but returned no banner text.  They may need to be re-scanned from
    another IP, or marked as failed.

    :param data_dir: path to data directory (containing ``server/``)
    :param list_path: path to server list file
    :param logs_dir: path to logs directory
    :returns: list of dicts with host, port, data_path, reason
    """
    issues = []
    seen = set()
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed = {(h, p) for h, p, _ in list_entries if h and p}

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
            except (OSError, json.JSONDecodeError):
                continue

            probe = data.get('server-probe', {})
            session_data = probe.get('session_data', {})
            banner_before = session_data.get('banner_before_return', '')
            banner_after = session_data.get('banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (banner_before or '') + (banner_after or '')

            if combined.strip():
                continue

            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if not host or not port:
                    continue
                if (host, port) not in allowed:
                    continue
                if (host, port) in seen:
                    continue
                seen.add((host, port))

                reason = detect_failure_reason(host, str(port), logs_dir)
                issues.append({
                    'host': host,
                    'port': port,
                    'data_path': fpath,
                    'reason': reason,
                    'has_session_data': bool(session_data),
                    'has_fingerprint': bool(probe.get('fingerprint', '')),
                })
    return issues


def review_empty_banners(mud_issues, bbs_issues, mud_list, bbs_list,
                         logs_dir, mud_data=None, bbs_data=None,
                         report_only=False, dry_run=False):
    """Interactively review servers with empty banners.

    For each server, the user can:
    - ``x`` to expunge log and data files for rescan
    - ``y`` to remove the entry from the server list
    - ``n`` to skip
    - ``q`` to quit

    :param mud_issues: list of empty-banner issues from MUD data
    :param bbs_issues: list of empty-banner issues from BBS data
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

    for mode, issues, list_path, data_dir in all_issues:
        if not issues or not os.path.isfile(list_path):
            continue

        print(f"\n--- {mode.upper()} servers with empty banners: "
              f"{len(issues)} ---")
        removals = set()
        rescans = 0
        rescan_servers = []

        for issue in issues:
            host = issue['host']
            port = issue['port']
            reason = issue['reason']
            fp = 'yes' if issue['has_fingerprint'] else 'no'
            sd = 'yes' if issue['has_session_data'] else 'no'
            print(f"\n  {host}:{port}")
            print(f"    fingerprint: {fp}, session_data: {sd}")
            print(f"    log: {reason}")

            if report_only:
                continue

            choice = _prompt(
                "    [x]expunge for rescan / "
                "[y]remove from list / [n]skip / [q]uit? ",
                "xynq")
            if choice == 'q':
                break
            if choice == 'x':
                log_file = Path(logs_dir) / f"{host}:{port}.log"
                if log_file.is_file() and not dry_run:
                    log_file.unlink()
                    print(f"    deleted {log_file}")
                elif log_file.is_file():
                    print(f"    [dry-run] would delete {log_file}")
                else:
                    print(f"    no log file to delete")
                if data_dir and not dry_run:
                    nj = _expunge_server_json(
                        data_dir, [(host, port)])
                    if nj:
                        print(f"    deleted {nj} data file(s)")
                rescans += 1
                rescan_servers.append((host, port))
            elif choice == 'y':
                removals.add((host, port))

        if removals:
            entries = load_server_list(list_path)
            write_filtered_list(list_path, entries, removals,
                                dry_run=dry_run)
        if rescans:
            print(f"  {rescans} server(s) queued for rescan")
        if removals:
            print(f"  {len(removals)} server(s) removed from {list_path}")


# Visually empty banner discovery

def discover_renders_empty(data_dir, list_path):
    """Find servers whose banners contain only escape sequences or whitespace.

    These servers have raw banner data but nothing visible after stripping
    ANSI sequences — they would render to a blank screenshot.

    :param data_dir: path to data directory (containing ``server/``)
    :param list_path: path to server list file
    :returns: list of dicts with host, port, data_path, raw_banner
    """
    issues = []
    seen = set()
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed = {(h, p) for h, p, _ in list_entries if h and p}

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
            except (OSError, json.JSONDecodeError):
                continue

            probe = data.get('server-probe', {})
            session_data = probe.get('session_data', {})
            banner_before = session_data.get('banner_before_return', '')
            banner_after = session_data.get('banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (banner_before or '') + (banner_after or '')

            if not combined.strip():
                continue

            visible = _strip_ansi(combined)
            if visible.strip():
                continue

            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if not host or not port:
                    continue
                if (host, port) not in allowed:
                    continue
                if (host, port) in seen:
                    continue
                seen.add((host, port))

                issues.append({
                    'host': host,
                    'port': port,
                    'data_path': fpath,
                    'raw_banner': combined,
                })
    return issues


def review_renders_empty(mud_issues, bbs_issues, mud_list, bbs_list,
                         logs_dir, mud_data=None, bbs_data=None,
                         report_only=False, dry_run=False):
    """Interactively review servers whose banners render to empty screens.

    For each server, shows ``repr()`` of the raw banner so the moderator
    can inspect the escape sequences.  Options:

    - ``x`` to expunge log and data files for rescan
    - ``y`` to remove the entry from the server list
    - ``n`` to skip
    - ``q`` to quit

    :param mud_issues: list of renders-empty issues from MUD data
    :param bbs_issues: list of renders-empty issues from BBS data
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

    for mode, issues, list_path, data_dir in all_issues:
        if not issues or not os.path.isfile(list_path):
            continue

        print(f"\n--- {mode.upper()} banners that render to empty screen: "
              f"{len(issues)} ---")
        removals = set()
        rescans = 0

        for issue in issues:
            host = issue['host']
            port = issue['port']
            raw = issue['raw_banner']
            print(f"\n  {host}:{port}")
            print(f"    Raw banner ({len(raw)} chars):")
            raw_repr = repr(raw)
            if len(raw_repr) > 500:
                raw_repr = raw_repr[:500] + '...'
            print(f"    {raw_repr}")

            if report_only:
                continue

            choice = _prompt(
                "    [x]expunge for rescan / "
                "[y]remove from list / [n]skip / [q]uit? ",
                "xynq")
            if choice == 'q':
                break
            if choice == 'x':
                log_file = Path(logs_dir) / f"{host}:{port}.log"
                if log_file.is_file() and not dry_run:
                    log_file.unlink()
                    print(f"    deleted {log_file}")
                elif log_file.is_file():
                    print(f"    [dry-run] would delete {log_file}")
                else:
                    print(f"    no log file to delete")
                if data_dir and not dry_run:
                    nj = _expunge_server_json(
                        data_dir, [(host, port)])
                    if nj:
                        print(f"    deleted {nj} data file(s)")
                rescans += 1
            elif choice == 'y':
                removals.add((host, port))

        if removals:
            entries = load_server_list(list_path)
            write_filtered_list(list_path, entries, removals,
                                dry_run=dry_run)
        if rescans:
            print(f"  {rescans} server(s) queued for rescan")
        if removals:
            print(f"  {len(removals)} server(s) removed from {list_path}")


# Small render discovery

def _strip_mxp_sgml(text):
    """Remove MXP/SGML protocol artifacts from banner text.

    Duplicates the logic from :func:`make_stats.common._strip_mxp_sgml`
    so the moderation tool can compute banner hashes independently.

    :param text: banner text possibly containing MXP/SGML
    :returns: cleaned text
    """
    text = re.sub(r'\x1b\[\d+z', '', text)
    text = re.sub(r'<!--.*?-->', '', text)
    text = re.sub(r'<!(EL(EMENT)?|ATTLIST|EN(TITY)?)\b.*', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = html.unescape(text)
    return text.rstrip()


def _compute_banner_filename(text, encoding, columns=None):
    """Compute the expected PNG filename for a banner.

    Replicates the preprocessing and hashing from
    :func:`make_stats.common._banner_to_png`.

    :param text: raw banner text
    :param encoding: encoding string (e.g. ``'cp437'``, ``'utf-8'``)
    :param columns: optional column width override
    :returns: filename string like ``banner_abcdef012345.png``
    """
    text = text.replace('\x00', '')
    text = text.replace('\r\n', '\n').replace('\n\r', '\n')
    text = _strip_mxp_sgml(text)
    text = re.sub(r'\x1b\[[0-9;]*[nc]', '', text).rstrip()

    max_bytes = 512 * 1024
    encoded = text.encode('utf-8', errors='surrogateescape')
    if len(encoded) > max_bytes:
        text = encoded[:max_bytes].decode('utf-8', errors='ignore').rstrip()

    hash_input = text + '\x00' + encoding
    if columns is not None:
        hash_input += '\x00' + str(columns)
    key = hashlib.sha1(
        hash_input.encode('utf-8', errors='surrogateescape')).hexdigest()[:12]
    return f"banner_{key}.png"


def _read_png_dimensions(path):
    """Read pixel width and height from a PNG file header.

    :param path: path to a PNG file
    :returns: ``(width, height)`` tuple, or ``(None, None)`` on failure
    """
    try:
        with open(path, 'rb') as fh:
            header = fh.read(24)
        if len(header) >= 24 and header[:8] == b'\x89PNG\r\n\x1a\n':
            width, height = struct.unpack('>II', header[16:24])
            return width, height
    except OSError:
        pass
    return None, None


def discover_renders_small(data_dir, list_path, banners_dir,
                           default_encoding=None):
    """Find servers whose rendered banner PNGs are suspiciously small.

    These are banners that have raw content but rendered to a tiny image
    (under 1000 bytes), indicating poison escape sequences or invisible
    content that the terminal couldn't display.

    :param data_dir: path to data directory (containing ``server/``)
    :param list_path: path to server list file
    :param banners_dir: path to the rendered banners directory
    :param default_encoding: fallback encoding when no override is set;
        BBS passes ``'cp437'``, MUD passes ``None`` (use scanner encoding)
    :returns: list of dicts with host, port, data_path, raw_banner,
        png_path, file_size, pixel_width, pixel_height
    """
    issues = []
    seen = set()
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues
    if not os.path.isdir(banners_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed = {(h, p) for h, p, _ in list_entries if h and p}

    # Build encoding and column override lookups from the list
    encoding_overrides = {}
    column_overrides = {}
    for h, p, line in list_entries:
        if h is None:
            continue
        parts = line.split()
        if len(parts) >= 3:
            encoding_overrides[(h, p)] = parts[2]
        if len(parts) >= 4:
            try:
                column_overrides[(h, p)] = int(parts[3])
            except ValueError:
                pass

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
            except (OSError, json.JSONDecodeError):
                continue

            probe = data.get('server-probe', {})
            session_data = probe.get('session_data', {})
            banner_before = session_data.get('banner_before_return', '')
            banner_after = session_data.get('banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (banner_before or '') + (banner_after or '')

            if not combined.strip():
                continue

            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if not host or not port:
                    continue
                if (host, port) not in allowed:
                    continue
                if (host, port) in seen:
                    continue
                seen.add((host, port))

                enc_override = encoding_overrides.get((host, port))
                if enc_override:
                    enc = enc_override
                elif default_encoding:
                    enc = default_encoding
                else:
                    # MUD mode: use scanner-detected encoding
                    scanner_enc = session_data.get('encoding', 'ascii')
                    enc = (scanner_enc or 'ascii').lower()
                cols = column_overrides.get((host, port))
                png_name = _compute_banner_filename(combined, enc, cols)
                png_path = os.path.join(banners_dir, png_name)

                if not os.path.isfile(png_path):
                    continue

                file_size = os.path.getsize(png_path)
                if file_size == 0:
                    continue

                pixel_w, pixel_h = _read_png_dimensions(png_path)

                # Flag if file is tiny (<1KB), or the visible text
                # is a single short line (under 40 columns wide).
                # wcwidth.width() is sequence-aware, no ANSI stripping
                # needed.
                small_file = file_size < 1000
                visible_lines = [
                    ln for ln in combined.splitlines()
                    if _strip_ansi(ln).strip()
                ]
                if len(visible_lines) <= 1:
                    total_w = max(
                        (wcwidth.width(ln) for ln in visible_lines),
                        default=0)
                    one_liner = total_w < 40
                else:
                    one_liner = False
                if not small_file and not one_liner:
                    continue

                reason = 'small file' if small_file else '1-liner'
                issues.append({
                    'host': host,
                    'port': port,
                    'data_path': fpath,
                    'raw_banner': combined,
                    'png_path': png_path,
                    'file_size': file_size,
                    'pixel_width': pixel_w,
                    'pixel_height': pixel_h,
                    'reason': reason,
                    'visible_lines': len(visible_lines),
                })
    return issues


def review_renders_small(mud_issues, bbs_issues, mud_list, bbs_list,
                         logs_dir, mud_data=None, bbs_data=None,
                         report_only=False, dry_run=False):
    """Interactively review servers whose banner PNGs are suspiciously small.

    For each server, shows file size, pixel dimensions, and ``repr()``
    of the raw banner.  Options:

    - ``x`` to expunge log and data files for rescan
    - ``d`` to delete the PNG and expunge log and data files
    - ``y`` to remove the entry from the server list
    - ``n`` to skip
    - ``q`` to quit

    :param mud_issues: list of renders-small issues from MUD data
    :param bbs_issues: list of renders-small issues from BBS data
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

    for mode, issues, list_path, data_dir in all_issues:
        if not issues or not os.path.isfile(list_path):
            continue

        print(f"\n--- {mode.upper()} banners with small renders: "
              f"{len(issues)} ---")
        removals = set()
        rescans = 0

        for issue in issues:
            host = issue['host']
            port = issue['port']
            file_size = issue['file_size']
            pixel_w = issue['pixel_width']
            pixel_h = issue['pixel_height']
            raw = issue['raw_banner']
            png_path = issue['png_path']

            reason = issue['reason']
            n_lines = issue['visible_lines']
            dims = (f"{pixel_w}x{pixel_h}" if pixel_w is not None
                    else "unknown")
            print(f"\n  {host}:{port}  [{reason}]")
            print(f"    PNG: {file_size} bytes, {dims} pixels, "
                  f"{n_lines} visible line(s)")
            raw_repr = repr(raw)
            if len(raw_repr) > 500:
                raw_repr = raw_repr[:500] + '...'
            print(f"    Raw banner ({len(raw)} chars): {raw_repr}")

            if report_only:
                continue

            choice = _prompt(
                "    [x]expunge / [d]elete PNG + expunge / "
                "[y]remove from list / [N]skip / [q]uit? ",
                "xdynq")
            if choice == 'q':
                break
            if choice in ('x', 'd'):
                if choice == 'd':
                    if not dry_run:
                        if os.path.isfile(png_path):
                            os.unlink(png_path)
                            print(f"    deleted {png_path}")
                    else:
                        print(f"    [dry-run] would delete {png_path}")
                log_file = Path(logs_dir) / f"{host}:{port}.log"
                if log_file.is_file() and not dry_run:
                    log_file.unlink()
                    print(f"    deleted {log_file}")
                elif log_file.is_file():
                    print(f"    [dry-run] would delete {log_file}")
                else:
                    print(f"    no log file to delete")
                if data_dir and not dry_run:
                    nj = _expunge_server_json(
                        data_dir, [(host, port)])
                    if nj:
                        print(f"    deleted {nj} data file(s)")
                rescans += 1
            elif choice == 'y':
                removals.add((host, port))

        if removals:
            entries = load_server_list(list_path)
            write_filtered_list(list_path, entries, removals,
                                dry_run=dry_run)
        if rescans:
            print(f"  {rescans} server(s) queued for rescan")
        if removals:
            print(f"  {len(removals)} server(s) removed from {list_path}")


# Server list I/O

def load_server_list(path):
    """Load a server list, preserving original lines.

    :param path: path to server list file
    :returns: list of (host, port, original_line) tuples;
              host/port are None for comments and blank lines
    """
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                entries.append((None, None, line))
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                try:
                    port = int(parts[1])
                    entries.append((parts[0], port, line))
                    continue
                except ValueError:
                    pass
            entries.append((None, None, line))
    return entries


def _parse_host_port_set(path):
    """Parse a server list into a set of (host_lower, port) tuples.

    :param path: path to server list file
    :returns: set of (host, port) tuples
    """
    result = set()
    for host, port, _ in load_server_list(path):
        if host is not None:
            result.add((host.lower(), port))
    return result


def write_filtered_list(path, entries, removals, dry_run=False):
    """Write filtered server list, excluding removed entries.

    :param path: original file path
    :param entries: list from :func:`load_server_list`
    :param removals: set of (host, port) to remove
    :param dry_run: if True, only print what would happen
    :returns: number of entries removed
    """
    output = Path(str(path) + ".new")
    removed = 0
    kept = 0
    lines = []
    for host, port, original in entries:
        if host is not None and (host, port) in removals:
            removed += 1
            continue
        lines.append(original + "\n")
        if host is not None:
            kept += 1

    if dry_run:
        print(f"  [dry-run] would write {output}: kept {kept}, removed {removed}")
        return removed

    with open(output, "w", encoding="utf-8") as f:
        f.writelines(lines)

    os.replace(output, path)
    print(f"  wrote {path}: kept {kept}, removed {removed}")
    return removed


# Fingerprint data loading

def load_server_records(data_dir):
    """Load all server JSON files, return list of record dicts.

    :param data_dir: path containing a ``server/`` subdirectory
    :returns: list of record dicts
    """
    records = []
    server_dir = data_dir / "server"
    if not server_dir.is_dir():
        return records
    for path in sorted(server_dir.glob("*/*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        probe = data.get("server-probe", {})
        fingerprint = probe.get("fingerprint", "")
        fp_data = probe.get("fingerprint-data", {})
        session_data = probe.get("session_data", {})

        banner_before = session_data.get("banner_before_return", "")
        banner_after = session_data.get("banner_after_return", "")
        if isinstance(banner_before, dict):
            banner_before = banner_before.get("text", "")
        if isinstance(banner_after, dict):
            banner_after = banner_after.get("text", "")
        combined = (banner_before or "") + (banner_after or "")

        mssp = session_data.get("mssp", {})
        mssp_name = mssp.get("NAME", "") if isinstance(mssp, dict) else ""

        for session in data.get("sessions", []):
            records.append({
                "host": session.get("host", ""),
                "port": session.get("port", 0),
                "ip": session.get("ip", ""),
                "connected": session.get("connected", ""),
                "fingerprint": fingerprint,
                "fp_data": fp_data,
                "banner_hash": _banner_hash(combined),
                "banner_before": banner_before,
                "banner_after": banner_after,
                "mssp_name": mssp_name,
                "encoding": session_data.get("encoding", ""),
                "data_path": str(path),
            })
    return records


def deduplicate_records(records):
    """Keep only the most recent record per (host, port).

    :param records: list of record dicts
    :returns: deduplicated list
    """
    by_hp = {}
    for rec in records:
        key = (rec["host"], rec["port"])
        existing = by_hp.get(key)
        if existing is None or rec["connected"] > existing["connected"]:
            by_hp[key] = rec
    return list(by_hp.values())


def build_alive_set(data_dir):
    """Build set of ``"host port"`` strings that have fingerprint data.

    :param data_dir: path to the ``server/`` directory containing fingerprints
    :returns: set of ``"host port"`` strings
    """
    alive = set()
    if not os.path.isdir(data_dir):
        return alive
    for fp_dir in sorted(os.listdir(data_dir)):
        fp_path = os.path.join(data_dir, fp_dir)
        if not os.path.isdir(fp_path):
            continue
        for fname in sorted(os.listdir(fp_path)):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(fp_path, fname)
            try:
                with open(fpath) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if host and port:
                    alive.add(f"{host} {port}")
    return alive


def detect_failure_reason(host, port, logs_dir):
    """Search the scan log for a failure reason.

    :param host: server hostname
    :param port: server port
    :param logs_dir: directory containing scan log files
    :returns: human-readable reason string
    """
    logfile = os.path.join(str(logs_dir), f"{host}:{port}.log")
    if not os.path.isfile(logfile):
        return "no log file"
    try:
        with open(logfile, errors='replace') as f:
            content = f.read()
    except OSError:
        return "no log file"

    lower = content.lower()
    if "timed out" in lower:
        return "connection timed out"
    if "connection refused" in lower:
        return "connection refused"
    if re.search(r"no address.*associated|name or service not known"
                 r"|name.*not resolve|getaddrinfo", lower):
        return "DNS resolution failed"
    if "network is unreachable" in lower or "no route to host" in lower:
        return "network unreachable"
    if re.search(r"error|exception|fail", lower):
        return "error (see log)"
    return "no fingerprint data"


# Duplicate grouping

def _find_fp_ip_groups(records):
    """Group by (fingerprint, ip) -- strongest duplicate signal."""
    groups = collections.defaultdict(list)
    for rec in records:
        if rec["fingerprint"] and rec["ip"]:
            groups[(rec["fingerprint"], rec["ip"])].append(rec)
    return {k: sorted(v, key=lambda r: (r["port"], r["host"]))
            for k, v in groups.items() if len(v) > 1}


def _find_banner_groups(records):
    """Group by normalized banner hash."""
    groups = collections.defaultdict(list)
    for rec in records:
        if rec["banner_hash"]:
            groups[rec["banner_hash"]].append(rec)
    return {k: sorted(v, key=lambda r: (r["port"], r["host"]))
            for k, v in groups.items() if len(v) > 1}


def _find_mssp_groups(records):
    """Group by normalized MSSP NAME."""
    groups = collections.defaultdict(list)
    for rec in records:
        if rec["mssp_name"]:
            key = _normalize_mssp_name(rec["mssp_name"])
            groups[key].append(rec)
    return {k: sorted(v, key=lambda r: (r["port"], r["host"]))
            for k, v in groups.items() if len(v) > 1}


def _subtract_covered(groups, covered):
    """Remove already-covered (host, port) pairs from groups."""
    result = {}
    for key, members in groups.items():
        remaining = [m for m in members
                     if (m["host"], m["port"]) not in covered]
        if len(remaining) > 1:
            result[key] = remaining
    return result


# Interactive display

def _print_group_member(idx, rec, removals, source_label=None):
    """Print one member of a duplicate group."""
    marker = "x" if (rec["host"], rec["port"]) in removals else " "
    mssp = f"  name={rec['mssp_name']!r}" if rec["mssp_name"] else ""
    source = f"  [{source_label}]" if source_label else ""
    print(f"  [{marker}] {idx}. {rec['host']}:{rec['port']}"
          f"  ip={rec['ip']}  fp={rec['fingerprint'][:12]}{mssp}{source}")

    before = rec.get("banner_before", "")
    if before:
        displayed = _display_banner(before, maxlines=5)
        for line in displayed.splitlines():
            print(f"       {line}")
    print()


def _review_groups(groups, label, decisions=None, logs_dir=None,
                   data_dir=None):
    """Interactive review of duplicate groups.

    :param groups: dict of group key -> list of record dicts
    :param label: display label for the group type
    :param decisions: mutable decisions dict for caching, or None
    :param logs_dir: path to logs directory for rescan, or None
    :param data_dir: path to data directory (for JSON expunge)
    :returns: set of (host, port) to remove
    """
    removals = set()
    items = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    dupes_cache = (decisions or {}).get("dupes", {})
    cached_count = 0

    print(f"\n{'=' * 70}")
    print(f"  {label}: {len(items)} group(s)")
    print(f"{'=' * 70}")

    for idx, (key, members) in enumerate(items, 1):
        cache_key = _group_cache_key(members)
        cached = dupes_cache.get(cache_key)

        if cached is not None:
            action = cached.get("action", "")
            if action == "skip":
                cached_count += 1
                continue
            if action == "remove":
                member_set = {
                    f"{r['host']}:{r['port']}" for r in members
                }
                valid = [
                    hp for hp in cached.get("remove", [])
                    if hp in member_set
                ]
                if valid:
                    for hp in valid:
                        h, _, p = hp.rpartition(":")
                        removals.add((h, int(p)))
                    cached_count += 1
                    continue

        print(f"\n--- Group {idx}/{len(items)} ", end="")
        if isinstance(key, tuple):
            print(f"[fp={key[0][:12]}  ip={key[1]}] ---")
        else:
            print(f"[{key}] ---")
        print(f"  {len(members)} entries:\n")

        for i, rec in enumerate(members, 1):
            _print_group_member(i, rec, removals)

        print("  Enter numbers to remove (e.g. '2 3'), [*] rescan all, [s]kip, [q]uit")
        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return removals

        if choice == "q":
            return removals
        if choice == "*":
            if logs_dir:
                servers = [(r['host'], r['port']) for r in members]
                deleted_logs = _expunge_logs(logs_dir, servers)
                deleted_json = 0
                if data_dir:
                    deleted_json = _expunge_server_json(
                        data_dir, servers)
                print(f"    -> {deleted_logs} log(s),"
                      f" {deleted_json} data file(s)"
                      f" deleted for rescan")
            else:
                print("    (no logs directory -- use --logs)")
            continue
        if choice in ("s", "k", ""):
            if decisions is not None:
                decisions["dupes"][cache_key] = {"action": "skip"}
            continue

        removed = []
        for token in choice.split():
            try:
                num = int(token)
                if 1 <= num <= len(members):
                    rec = members[num - 1]
                    removals.add((rec["host"], rec["port"]))
                    removed.append(
                        f"{rec['host']}:{rec['port']}"
                    )
                    print(f"    -> remove {rec['host']}:{rec['port']}")
            except ValueError:
                continue

        if decisions is not None:
            if removed:
                decisions["dupes"][cache_key] = {
                    "action": "remove",
                    "remove": removed,
                }
            else:
                decisions["dupes"][cache_key] = {"action": "skip"}

    if cached_count:
        print(f"\n  ({cached_count} group(s) auto-resolved from cache)")

    return removals


def _report_groups(groups, label):
    """Non-interactive report of duplicate groups."""
    items = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    print(f"\n  {label}: {len(items)} group(s)")
    for key, members in items:
        if isinstance(key, tuple):
            print(f"\n    fp={key[0][:12]}  ip={key[1]}:")
        else:
            print(f"\n    {key}:")
        for rec in members:
            mssp = f"  name={rec['mssp_name']!r}" if rec["mssp_name"] else ""
            print(f"      {rec['host']}:{rec['port']}{mssp}")


def _prune_data_files(records, removals):
    """List and optionally delete data files for removed entries."""
    paths = set()
    for rec in records:
        if (rec["host"], rec["port"]) in removals:
            paths.add(rec["data_path"])
    if not paths:
        return
    print(f"\n{len(paths)} data file(s) for removed entries:")
    for p in sorted(paths):
        print(f"  {p}")
    answer = _prompt("\nDelete these data files? [y/N] ", "yn")
    if answer != "y":
        return
    for p in paths:
        try:
            os.unlink(p)
            print(f"  deleted {p}")
            parent = Path(p).parent
            try:
                parent.rmdir()
            except OSError:
                pass
        except OSError as err:
            print(f"  error deleting {p}: {err}", file=sys.stderr)


# Prune dead servers

def prune_dead(list_path, data_dir, logs_dir, report_only=False,
               dry_run=False):
    """Find and remove dead entries from a server list.

    :param list_path: path to server list file
    :param data_dir: path to data directory (containing server/)
    :param logs_dir: path to logs directory
    :param report_only: if True, only print report
    :param dry_run: if True, don't write changes
    :returns: set of (host, port) removed
    """
    list_path = Path(list_path)
    server_dir = str(Path(data_dir) / "server")

    print(f"\n--- Pruning dead entries from {list_path.name} ---")
    alive = build_alive_set(server_dir)

    entries = load_server_list(list_path)
    dead = []

    for host, port, _ in entries:
        if host is None:
            continue
        if f"{host} {port}" not in alive:
            reason = detect_failure_reason(host, str(port), logs_dir)
            dead.append((host, port, reason))

    total = sum(1 for h, _, _ in entries if h is not None)
    alive_count = total - len(dead)

    if not dead:
        print(f"  {total} entries, all alive. Nothing to prune.")
        return set()

    print()
    for host, port, reason in dead:
        print(f"  DEAD: {host}:{port} -- {reason}")

    print(f"\n  Total: {total}, Alive: {alive_count}, Dead: {len(dead)}")

    if report_only:
        return set()

    answer = _prompt(f"\n  Remove {len(dead)} dead entries? [y/N/x] ", "ynx")
    if answer == "x":
        servers = [(h, p) for h, p, _ in dead]
        deleted_logs = _expunge_logs(logs_dir, servers)
        deleted_json = _expunge_server_json(data_dir, servers)
        print(f"  Expunged {deleted_logs} log(s),"
              f" {deleted_json} data file(s) for rescan")
        answer = _prompt(f"  Now remove from list? [y/N] ", "yn")

    if answer != "y":
        print("  Skipped.")
        return set()

    removals = {(h, p) for h, p, _ in dead}
    write_filtered_list(list_path, entries, removals, dry_run=dry_run)
    return removals


# Within-list duplicates

def find_duplicates(list_path, data_dir, report_only=False,
                    prune_data=False, dry_run=False, decisions=None,
                    logs_dir=None):
    """Find and review duplicate entries within a single server list.

    :param list_path: path to server list file
    :param data_dir: path to data directory (containing server/)
    :param report_only: if True, only print report
    :param prune_data: if True, offer to delete data files
    :param dry_run: if True, don't write changes
    :param decisions: mutable decisions dict for caching, or None
    :param logs_dir: path to logs directory for rescan, or None
    :returns: set of (host, port) removed
    """
    list_path = Path(list_path)
    data_dir = Path(data_dir)

    print(f"\n--- Finding duplicates in {list_path.name} ---")
    records = load_server_records(data_dir)
    records = deduplicate_records(records)

    # Filter to only entries still in the list (earlier steps may have removed some)
    current_entries = _parse_host_port_set(list_path)
    records = [r for r in records
               if (r["host"].lower(), r["port"]) in current_entries]

    print(f"  {len(records)} unique host:port records")

    if not records:
        print("  No fingerprint data to analyze.")
        return set()

    fp_ip_groups = _find_fp_ip_groups(records)
    banner_groups = _find_banner_groups(records)
    mssp_groups = _find_mssp_groups(records)

    covered = set()
    for members in fp_ip_groups.values():
        for rec in members:
            covered.add((rec["host"], rec["port"]))

    extra_banner = _subtract_covered(banner_groups, covered)
    for members in extra_banner.values():
        for rec in members:
            covered.add((rec["host"], rec["port"]))

    extra_mssp = _subtract_covered(mssp_groups, covered)

    total = len(fp_ip_groups) + len(extra_banner) + len(extra_mssp)
    print(f"  {len(fp_ip_groups)} groups by fingerprint + IP")
    if extra_banner:
        print(f"  {len(extra_banner)} additional by banner similarity")
    if extra_mssp:
        print(f"  {len(extra_mssp)} additional by MSSP NAME")

    if total == 0:
        print("  No duplicates found.")
        return set()

    if report_only:
        if fp_ip_groups:
            _report_groups(fp_ip_groups, "Fingerprint + IP")
        if extra_banner:
            _report_groups(extra_banner, "Banner similarity")
        if extra_mssp:
            _report_groups(extra_mssp, "MSSP NAME")
        return set()

    removals = set()
    if fp_ip_groups:
        r = _review_groups(
            fp_ip_groups, "Fingerprint + IP duplicates", decisions,
            logs_dir=logs_dir, data_dir=str(data_dir))
        removals.update(r)
    if extra_banner:
        r = _review_groups(
            extra_banner, "Banner similarity duplicates", decisions,
            logs_dir=logs_dir, data_dir=str(data_dir))
        removals.update(r)
    if extra_mssp:
        r = _review_groups(
            extra_mssp, "MSSP NAME duplicates", decisions,
            logs_dir=logs_dir, data_dir=str(data_dir))
        removals.update(r)

    if not removals:
        print("\n  No entries marked for removal.")
        return set()

    print(f"\n  {len(removals)} entry/entries marked for removal:")
    for host, port in sorted(removals):
        print(f"    {host}:{port}")

    answer = _prompt("\n  Apply changes? [y/N] ", "yn")
    if answer != "y":
        print("  Cancelled.")
        return set()

    entries = load_server_list(list_path)
    write_filtered_list(list_path, entries, removals, dry_run=dry_run)

    if prune_data:
        _prune_data_files(records, removals)

    return removals


# Cross-list conflicts

def find_cross_list_conflicts(mud_list, bbs_list, mud_data_dir,
                              bbs_data_dir, report_only=False,
                              dry_run=False, decisions=None):
    """Find entries present in both the MUD and BBS lists.

    For each conflict, show fingerprint data and banner, then prompt
    whether to keep in MUD list, BBS list, or both.

    :param mud_list: path to mudlist.txt
    :param bbs_list: path to bbslist.txt
    :param mud_data_dir: path to MUD data directory
    :param bbs_data_dir: path to BBS data directory
    :param report_only: if True, only print report
    :param dry_run: if True, don't write changes
    :param decisions: mutable decisions dict for caching, or None
    :returns: (mud_removals, bbs_removals) sets
    """
    mud_list = Path(mud_list)
    bbs_list = Path(bbs_list)

    print(f"\n--- Cross-list conflicts (entries in both lists) ---")

    mud_set = _parse_host_port_set(mud_list)
    bbs_set = _parse_host_port_set(bbs_list)

    conflicts = mud_set & bbs_set
    if not conflicts:
        print("  No entries appear in both lists.")
        return set(), set()

    print(f"  {len(conflicts)} entries found in both lists")

    # Load fingerprint data for context
    mud_records = {(r["host"].lower(), r["port"]): r
                   for r in deduplicate_records(
                       load_server_records(Path(mud_data_dir)))}
    bbs_records = {(r["host"].lower(), r["port"]): r
                   for r in deduplicate_records(
                       load_server_records(Path(bbs_data_dir)))}

    if report_only:
        for host, port in sorted(conflicts):
            rec = mud_records.get((host, port)) or bbs_records.get((host, port))
            fp = rec["fingerprint"][:12] if rec else "?"
            mssp = ""
            if rec and rec.get("mssp_name"):
                mssp = f"  name={rec['mssp_name']!r}"
            print(f"    {host}:{port}  fp={fp}{mssp}")
        return set(), set()

    mud_removals = set()
    bbs_removals = set()
    cross_cache = (decisions or {}).get("cross", {})
    cached_count = 0

    for idx, (host, port) in enumerate(sorted(conflicts), 1):
        cache_key = f"{host}:{port}"
        cached = cross_cache.get(cache_key)

        if cached is not None:
            if cached == "m":
                bbs_removals.add((host, port))
            elif cached == "b":
                mud_removals.add((host, port))
            cached_count += 1
            continue

        print(f"\n--- Conflict {idx}/{len(conflicts)}: {host}:{port} ---")

        rec = mud_records.get((host, port)) or bbs_records.get((host, port))
        if rec:
            fp = rec["fingerprint"][:12]
            ip = rec["ip"]
            mssp = (f"  name={rec['mssp_name']!r}"
                    if rec.get("mssp_name") else "")
            print(f"  fp={fp}  ip={ip}{mssp}")
            before = rec.get("banner_before", "")
            if before:
                displayed = _display_banner(before, maxlines=8)
                for line in displayed.splitlines():
                    print(f"    {line}")
        else:
            print("  (no fingerprint data available)")

        in_mud = "MUD" if (host, port) in mud_set else ""
        in_bbs = "BBS" if (host, port) in bbs_set else ""
        print(f"\n  Currently in: {in_mud} {in_bbs}")
        print("  Keep in: [m]ud, [b]bs, [k]eep both, [s]kip, [q]uit")

        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            break

        if choice == "q":
            break
        elif choice == "m":
            bbs_removals.add((host, port))
            print(f"    -> remove from BBS list")
        elif choice == "b":
            mud_removals.add((host, port))
            print(f"    -> remove from MUD list")
        elif choice in ("k", "s", ""):
            choice = "k" if choice == "k" else "s"

        if decisions is not None and choice in ("m", "b", "k", "s"):
            decisions["cross"][cache_key] = choice

    if cached_count:
        print(f"\n  ({cached_count} conflict(s) auto-resolved from cache)")

    if not mud_removals and not bbs_removals:
        print("\n  No changes.")
        return set(), set()

    if mud_removals:
        print(f"\n  {len(mud_removals)} to remove from MUD list:")
        for host, port in sorted(mud_removals):
            print(f"    {host}:{port}")
    if bbs_removals:
        print(f"\n  {len(bbs_removals)} to remove from BBS list:")
        for host, port in sorted(bbs_removals):
            print(f"    {host}:{port}")

    answer = _prompt("\n  Apply changes? [y/N] ", "yn")
    if answer != "y":
        print("  Cancelled.")
        return set(), set()

    if mud_removals:
        entries = load_server_list(mud_list)
        write_filtered_list(mud_list, entries, mud_removals, dry_run=dry_run)
    if bbs_removals:
        entries = load_server_list(bbs_list)
        write_filtered_list(bbs_list, entries, bbs_removals, dry_run=dry_run)

    return mud_removals, bbs_removals


# DNS deduplication

def find_dns_duplicates(mud_list, bbs_list, report_only=False,
                        dry_run=False):
    """Automatically remove IP entries that duplicate a hostname entry.

    Resolves all hostnames from both lists, then removes IP entries
    whose address matches a resolved hostname at the same port.
    This step is fully automatic and requires no interactive prompts.

    :param mud_list: path to mudlist.txt
    :param bbs_list: path to bbslist.txt
    :param report_only: if True, only print report
    :param dry_run: if True, don't write changes
    :returns: (mud_removals, bbs_removals) sets
    """
    mud_list = Path(mud_list)
    bbs_list = Path(bbs_list)

    print(f"\n--- DNS deduplication (prefer hostname over IP) ---")

    # Load entries from both lists
    mud_set = _parse_host_port_set(mud_list) if mud_list.is_file() else set()
    bbs_set = _parse_host_port_set(bbs_list) if bbs_list.is_file() else set()
    all_entries = set()
    for host, port in mud_set:
        all_entries.add((host, port, "mud"))
    for host, port in bbs_set:
        all_entries.add((host, port, "bbs"))

    # Split into hostnames and IP entries
    hostnames = set()
    ip_entries = []
    for host, port, source in all_entries:
        if _is_ip_address(host):
            ip_entries.append((host, port, source))
        else:
            hostnames.add(host)

    if not hostnames or not ip_entries:
        print("  No hostname/IP overlap possible.")
        return set(), set()

    print(f"  {len(hostnames)} unique hostnames, "
          f"{len(ip_entries)} IP entries")

    # Resolve all hostnames
    print("  Resolving hostnames ...", file=sys.stderr)
    resolved = _resolve_hostnames(hostnames)

    # Build reverse lookup: (ip, port) -> [hostname entries]
    ip_to_hostname = collections.defaultdict(list)
    for host, port, source in all_entries:
        if not _is_ip_address(host):
            for ip in resolved.get(host, ()):
                ip_to_hostname[(ip, port)].append(
                    (host, port, source))

    # Automatically remove all IP entries that match a resolved hostname
    mud_removals = set()
    bbs_removals = set()
    for ip, port, source in ip_entries:
        hostname_entries = ip_to_hostname.get((ip, port))
        if hostname_entries:
            names = ", ".join(h for h, _, _ in hostname_entries[:3])
            print(f"  auto-remove {ip}:{port} [{source}] -> {names}")
            if source == "mud":
                mud_removals.add((ip, port))
            else:
                bbs_removals.add((ip, port))

    total = len(mud_removals) + len(bbs_removals)
    if not total:
        print("  No IP entries match a resolved hostname.")
        return set(), set()

    print(f"\n  {total} IP entries to remove:")
    if mud_removals:
        print(f"    MUD list: {len(mud_removals)}")
    if bbs_removals:
        print(f"    BBS list: {len(bbs_removals)}")

    if report_only:
        return set(), set()

    if mud_removals and mud_list.is_file():
        entries = load_server_list(mud_list)
        write_filtered_list(mud_list, entries, mud_removals,
                            dry_run=dry_run)
    if bbs_removals and bbs_list.is_file():
        entries = load_server_list(bbs_list)
        write_filtered_list(bbs_list, entries, bbs_removals,
                            dry_run=dry_run)

    return mud_removals, bbs_removals


# CLI

def _get_argument_parser():
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        description="Moderate MUD and BBS server lists: prune dead servers,"
                    " find duplicates, and resolve cross-list conflicts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scope = parser.add_argument_group("scope (default: both)")
    scope_mx = scope.add_mutually_exclusive_group()
    scope_mx.add_argument(
        "--mud", action="store_true",
        help="only moderate the MUD list",
    )
    scope_mx.add_argument(
        "--bbs", action="store_true",
        help="only moderate the BBS list",
    )

    mode = parser.add_argument_group("mode (default: all)")
    mode_mx = mode.add_mutually_exclusive_group()
    mode_mx.add_argument(
        "--only-prune", action="store_true",
        help="only prune dead servers",
    )
    mode_mx.add_argument(
        "--only-dupes", action="store_true",
        help="only find within-list duplicates",
    )
    mode_mx.add_argument(
        "--only-cross", action="store_true",
        help="only find entries in both MUD and BBS lists",
    )
    mode_mx.add_argument(
        "--only-dns", action="store_true",
        help="only remove IP entries that duplicate a hostname",
    )
    mode_mx.add_argument(
        "--only-encodings", action="store_true",
        help="only discover and fix encoding issues in banners",
    )
    mode_mx.add_argument(
        "--only-columns", action="store_true",
        help="only discover and suggest column width overrides",
    )
    mode_mx.add_argument(
        "--only-empty", action="store_true",
        help="only find servers with fingerprint data but empty banners",
    )
    mode_mx.add_argument(
        "--only-renders-empty", action="store_true",
        help="only find banners that render to an empty screen",
    )
    mode_mx.add_argument(
        "--only-renders-small", action="store_true",
        help="only find banners whose rendered PNGs are tiny (<1KB)",
    )

    parser.add_argument(
        "--report-only", action="store_true",
        help="print report without interactive prompts",
    )
    parser.add_argument(
        "--prune-data", action="store_true",
        help="offer to delete data files for removed entries",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="show what would change without writing files",
    )
    parser.add_argument(
        "--show-all", metavar="ENCODING",
        help="display raw banners for all servers with the given encoding "
             "(or 'all' for every encoding)",
    )
    parser.add_argument(
        "--expunge-all", metavar="ENCODING",
        help="delete log files for all servers with the given encoding "
             "(or 'all' for every encoding), allowing re-scan",
    )
    parser.add_argument(
        "--skip-dns", action="store_true",
        help="skip DNS deduplication step",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="ignore cached decisions, re-prompt everything",
    )

    paths = parser.add_argument_group("paths")
    paths.add_argument(
        "--mud-list", default=str(DEFAULT_MUD_LIST),
        help=f"path to MUD server list (default: {DEFAULT_MUD_LIST})",
    )
    paths.add_argument(
        "--bbs-list", default=str(DEFAULT_BBS_LIST),
        help=f"path to BBS server list (default: {DEFAULT_BBS_LIST})",
    )
    paths.add_argument(
        "--mud-data", default=str(DEFAULT_MUD_DATA),
        help=f"MUD data directory, containing server/ subdirectory "
             f"(default: {DEFAULT_MUD_DATA})",
    )
    paths.add_argument(
        "--bbs-data", default=str(DEFAULT_BBS_DATA),
        help=f"BBS data directory, containing server/ subdirectory "
             f"(default: {DEFAULT_BBS_DATA})",
    )
    paths.add_argument(
        "--logs", default=str(DEFAULT_LOGS),
        help=f"shared logs directory (default: {DEFAULT_LOGS})",
    )
    paths.add_argument(
        "--decisions", default=str(DEFAULT_DECISIONS),
        help=f"decisions cache file (default: {DEFAULT_DECISIONS})",
    )

    return parser


def main():
    """CLI entry point."""
    args = _get_argument_parser().parse_args()

    do_mud = not args.bbs
    do_bbs = not args.mud

    # Handle --show-all and --expunge-all early exits
    if args.show_all:
        if do_mud and os.path.isfile(args.mud_list):
            show_all_banners(args.mud_list, args.mud_data, args.show_all)
        if do_bbs and os.path.isfile(args.bbs_list):
            show_all_banners(args.bbs_list, args.bbs_data, args.show_all)
        return

    if args.expunge_all:
        if do_mud and os.path.isfile(args.mud_list):
            expunge_all_logs(args.mud_list, args.logs, args.expunge_all,
                            data_dir=args.mud_data)
        if do_bbs and os.path.isfile(args.bbs_list):
            expunge_all_logs(args.bbs_list, args.logs, args.expunge_all,
                            data_dir=args.bbs_data)
        return

    only_flags = (args.only_prune, args.only_dupes,
                  args.only_cross, args.only_dns,
                  args.only_encodings, args.only_columns,
                  args.only_empty, args.only_renders_empty,
                  args.only_renders_small)
    any_only = any(only_flags)
    do_prune = args.only_prune or not any_only
    do_dupes = args.only_dupes or not any_only
    do_cross = args.only_cross or not any_only
    do_dns = (args.only_dns or not any_only) and not args.skip_dns
    do_encodings = args.only_encodings or not any_only
    do_columns = args.only_columns
    do_empty = args.only_empty
    do_renders_empty = args.only_renders_empty
    do_renders_small = args.only_renders_small

    # Cross-list and DNS modes require both lists
    if do_cross and (args.mud or args.bbs):
        do_cross = False
    if do_dns and (args.mud or args.bbs):
        do_dns = False

    # Load cached decisions
    decisions = None
    if not args.no_cache and not args.report_only:
        decisions = load_decisions(args.decisions)

    # DNS deduplication (automatic, runs first)
    if do_dns:
        if (os.path.isfile(args.mud_list) and os.path.isfile(args.bbs_list)):
            find_dns_duplicates(
                args.mud_list, args.bbs_list,
                report_only=args.report_only,
                dry_run=args.dry_run)

    # Prune dead servers
    if do_prune:
        if do_mud and os.path.isfile(args.mud_list):
            prune_dead(args.mud_list, args.mud_data, args.logs,
                       report_only=args.report_only, dry_run=args.dry_run)
        if do_bbs and os.path.isfile(args.bbs_list):
            prune_dead(args.bbs_list, args.bbs_data, args.logs,
                       report_only=args.report_only, dry_run=args.dry_run)

    # Within-list duplicates
    if do_dupes:
        if do_mud and os.path.isfile(args.mud_list):
            find_duplicates(args.mud_list, args.mud_data,
                            report_only=args.report_only,
                            prune_data=args.prune_data,
                            dry_run=args.dry_run,
                            decisions=decisions,
                            logs_dir=args.logs)
        if do_bbs and os.path.isfile(args.bbs_list):
            find_duplicates(args.bbs_list, args.bbs_data,
                            report_only=args.report_only,
                            prune_data=args.prune_data,
                            dry_run=args.dry_run,
                            decisions=decisions,
                            logs_dir=args.logs)

    # Cross-list conflicts
    if do_cross:
        if (os.path.isfile(args.mud_list) and os.path.isfile(args.bbs_list)):
            find_cross_list_conflicts(
                args.mud_list, args.bbs_list,
                args.mud_data, args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run,
                decisions=decisions)

    # Encoding discovery and fixes
    if do_encodings:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_encoding_issues(args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_encoding_issues(
                args.bbs_data, args.bbs_list, default_encoding='cp437')

        if mud_issues or bbs_issues:
            review_encoding_issues(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data, bbs_data=args.bbs_data,
                report_only=args.report_only, dry_run=args.dry_run)
        else:
            print("No encoding issues detected.")

    # Column width discovery and fixes
    if do_columns:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_column_width_issues(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_column_width_issues(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_column_width_issues(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No column width issues detected.")

    # Empty banner discovery
    if do_empty:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_empty_banners(
                args.mud_data, args.mud_list, args.logs)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_empty_banners(
                args.bbs_data, args.bbs_list, args.logs)

        if mud_issues or bbs_issues:
            review_empty_banners(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data, bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No empty banner issues detected.")

    # Renders-empty banner discovery
    if do_renders_empty:
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_renders_empty(
                args.mud_data, args.mud_list)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_renders_empty(
                args.bbs_data, args.bbs_list)

        if mud_issues or bbs_issues:
            review_renders_empty(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data, bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No banners that render to empty screen.")

    # Renders-small banner discovery
    if do_renders_small:
        mud_banners = _HERE / "docs-muds" / "_static" / "banners"
        bbs_banners = _HERE / "docs-bbs" / "_static" / "banners"
        mud_issues = []
        bbs_issues = []
        if do_mud and os.path.isfile(args.mud_list):
            mud_issues = discover_renders_small(
                args.mud_data, args.mud_list, str(mud_banners),
                default_encoding=None)
        if do_bbs and os.path.isfile(args.bbs_list):
            bbs_issues = discover_renders_small(
                args.bbs_data, args.bbs_list, str(bbs_banners),
                default_encoding='cp437')

        if mud_issues or bbs_issues:
            review_renders_small(
                mud_issues, bbs_issues,
                args.mud_list, args.bbs_list, args.logs,
                mud_data=args.mud_data, bbs_data=args.bbs_data,
                report_only=args.report_only,
                dry_run=args.dry_run)
        else:
            print("No banners with small renders detected.")

    # Save decisions cache
    if decisions is not None:
        save_decisions(args.decisions, decisions)


if __name__ == "__main__":
    main()
