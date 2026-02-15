"""Column width, empty banners, renders-empty, and renders-small analysis."""

import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

import wcwidth

from make_stats.common import _strip_ansi, _strip_mxp_sgml

from .data import (
    load_server_list,
    write_filtered_list,
    detect_failure_reason,
)
from .encoding import _expunge_server_json
from .util import _prompt


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
    """Scan JSON data to find servers needing column overrides.

    Flags servers whose banners exceed 80 columns or never exceed 40.

    :param data_dir: path to server data directory
    :param list_path: path to server list file (mud/bbs list)
    :returns: list of dicts with host, port, max_width,
        suggested_columns
    """
    issues = []
    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return issues

    list_entries = load_server_list(list_path)
    allowed_servers = {(h, p) for h, p, _ in list_entries if h and p}

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

            print(f"    Preview at {suggested} columns:")
            print(f"    {chr(0x2500) * suggested}")
            for para in _strip_ansi(banner).splitlines():
                if not para.strip():
                    print()
                    continue
                for wrapped in wcwidth.wrap(para, suggested):
                    print(f"    {wrapped}")
            print(f"    {chr(0x2500) * suggested}")

            if report_only:
                continue

            choice = _prompt(
                f"    Apply {suggested} columns?"
                f" (Y/n/q/NUMBER) ",
                "ynq")
            if choice == 'q':
                return applied_count
            if choice == 'n':
                continue

            columns = suggested
            if choice and choice not in 'ynq':
                try:
                    columns = int(choice)
                except ValueError:
                    print(f"    Invalid number: {choice!r},"
                          f" skipping")
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
                print(f"    \u2713 Updated {list_path}"
                      f" ({columns} columns)")
                applied_count += 1


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
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (
                (banner_before or '') + (banner_after or '')
            )

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

                reason = detect_failure_reason(
                    host, str(port), logs_dir)
                issues.append({
                    'host': host,
                    'port': port,
                    'data_path': fpath,
                    'reason': reason,
                    'has_session_data': bool(session_data),
                    'has_fingerprint': bool(
                        probe.get('fingerprint', '')),
                })
    return issues


def _group_by_reason(issues):
    """Group empty-banner issues by their log reason.

    :param issues: list of issue dicts with a ``reason`` key
    :returns: list of ``(reason, issues)`` tuples, ordered by first
        occurrence
    """
    groups = {}
    order = []
    for issue in issues:
        reason = issue['reason']
        if reason not in groups:
            groups[reason] = []
            order.append(reason)
        groups[reason].append(issue)
    return [(r, groups[r]) for r in order]


def review_empty_banners(mud_issues, bbs_issues, mud_list, bbs_list,
                         logs_dir, mud_data=None, bbs_data=None,
                         report_only=False, dry_run=False):
    """Interactively review servers with empty banners.

    Servers are grouped by log reason.  For each group, the user can
    apply a single action to every server in the group:

    - ``x`` to expunge log and data files for rescan
    - ``y`` to remove entries from the server list
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
        quit_requested = False

        for reason, group in _group_by_reason(issues):
            if quit_requested:
                break

            print(f"\n  [{reason}] ({len(group)} server(s)):")
            for issue in group:
                host = issue['host']
                port = issue['port']
                fp = 'yes' if issue['has_fingerprint'] else 'no'
                sd = 'yes' if issue['has_session_data'] else 'no'
                print(f"    {host}:{port}"
                      f"  (fp: {fp}, session: {sd})")

            if report_only:
                continue

            choice = _prompt(
                f"\n  Apply to all {len(group)}: "
                "[x]expunge for rescan / "
                "[y]remove from list / [n]skip / [q]uit? ",
                "xynq")
            if choice == 'q':
                quit_requested = True
                break
            if choice == 'n' or choice is None:
                continue
            if choice == 'x':
                for issue in group:
                    host = issue['host']
                    port = issue['port']
                    log_file = (
                        Path(logs_dir) / f"{host}:{port}.log"
                    )
                    if log_file.is_file() and not dry_run:
                        log_file.unlink()
                        print(f"    deleted {log_file}")
                    elif log_file.is_file():
                        print(f"    [dry-run] would delete"
                              f" {log_file}")
                if data_dir and not dry_run:
                    servers = [(i['host'], i['port'])
                               for i in group]
                    nj = _expunge_server_json(
                        data_dir, servers)
                    if nj:
                        print(f"    deleted {nj} data file(s)")
                rescans += len(group)
            elif choice == 'y':
                for issue in group:
                    removals.add((issue['host'], issue['port']))

        if removals:
            entries = load_server_list(list_path)
            write_filtered_list(list_path, entries, removals,
                                dry_run=dry_run)
        if rescans:
            print(f"  {rescans} server(s) queued for rescan")
        if removals:
            print(f"  {len(removals)} server(s) removed"
                  f" from {list_path}")


def discover_renders_empty(data_dir, list_path):
    """Find servers whose banners contain only escapes or whitespace.

    These servers have raw banner data but nothing visible after
    stripping ANSI sequences -- they would render to a blank
    screenshot.

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
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (
                (banner_before or '') + (banner_after or '')
            )

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
    """Interactively review servers whose banners render to empty.

    For each server, shows ``repr()`` of the raw banner so the
    moderator can inspect the escape sequences.  Options:

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

        print(f"\n--- {mode.upper()} banners that render to empty"
              f" screen: {len(issues)} ---")
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
                    print(f"    [dry-run] would delete"
                          f" {log_file}")
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
            print(f"  {len(removals)} server(s) removed"
                  f" from {list_path}")


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
        text = encoded[:max_bytes].decode(
            'utf-8', errors='ignore').rstrip()

    hash_input = text + '\x00' + encoding
    if columns is not None:
        hash_input += '\x00' + str(columns)
    key = hashlib.sha1(
        hash_input.encode('utf-8', errors='surrogateescape')
    ).hexdigest()[:12]
    return f"banner_{key}.png"


def _read_png_dimensions(path):
    """Read pixel width and height from a PNG file header.

    :param path: path to a PNG file
    :returns: ``(width, height)`` tuple, or ``(None, None)`` on failure
    """
    try:
        with open(path, 'rb') as fh:
            header = fh.read(24)
        if (len(header) >= 24
                and header[:8] == b'\x89PNG\r\n\x1a\n'):
            width, height = struct.unpack('>II', header[16:24])
            return width, height
    except OSError:
        pass
    return None, None


def discover_renders_small(data_dir, list_path, banners_dir,
                           default_encoding=None):
    """Find servers whose rendered banner PNGs are suspiciously small.

    These are banners that have raw content but rendered to a tiny
    image (under 1000 bytes), indicating poison escape sequences or
    invisible content that the terminal couldn't display.

    :param data_dir: path to data directory (containing ``server/``)
    :param list_path: path to server list file
    :param banners_dir: path to the rendered banners directory
    :param default_encoding: fallback encoding when no override is
        set; BBS passes ``'cp437'``, MUD passes ``None`` (use scanner
        encoding)
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
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')
            if isinstance(banner_before, dict):
                banner_before = banner_before.get('text', '')
            if isinstance(banner_after, dict):
                banner_after = banner_after.get('text', '')
            combined = (
                (banner_before or '') + (banner_after or '')
            )

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

                enc_override = encoding_overrides.get(
                    (host, port))
                if enc_override:
                    enc = enc_override
                elif default_encoding:
                    enc = default_encoding
                else:
                    scanner_enc = session_data.get(
                        'encoding', 'ascii')
                    enc = (scanner_enc or 'ascii').lower()
                cols = column_overrides.get((host, port))
                png_name = _compute_banner_filename(
                    combined, enc, cols)
                png_path = os.path.join(banners_dir, png_name)

                if not os.path.isfile(png_path):
                    continue

                file_size = os.path.getsize(png_path)

                if file_size == 0:
                    # Zero-byte sentinel = failed render.
                    visible = _strip_ansi(combined).strip()
                    if visible:
                        issues.append({
                            'host': host,
                            'port': port,
                            'data_path': fpath,
                            'raw_banner': combined,
                            'png_path': png_path,
                            'file_size': 0,
                            'pixel_width': None,
                            'pixel_height': None,
                            'reason': 'render failed (0-byte)',
                            'visible_lines': len([
                                ln for ln in combined.splitlines()
                                if _strip_ansi(ln).strip()
                            ]),
                        })
                    continue

                pixel_w, pixel_h = _read_png_dimensions(png_path)

                small_file = file_size < 1000
                visible_lines = [
                    ln for ln in combined.splitlines()
                    if _strip_ansi(ln).strip()
                ]
                if len(visible_lines) <= 1:
                    total_w = max(
                        (wcwidth.width(ln)
                         for ln in visible_lines),
                        default=0)
                    one_liner = total_w < 40
                else:
                    one_liner = False
                if not small_file and not one_liner:
                    continue

                reason = (
                    'small file' if small_file else '1-liner'
                )
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
    """Interactively review servers with suspiciously small PNGs.

    For each server, shows file size, pixel dimensions, and
    ``repr()`` of the raw banner.  Options:

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
            dims = (f"{pixel_w}x{pixel_h}"
                    if pixel_w is not None else "unknown")
            print(f"\n  {host}:{port}  [{reason}]")
            print(f"    PNG: {file_size} bytes, {dims} pixels, "
                  f"{n_lines} visible line(s)")
            raw_repr = repr(raw)
            if len(raw_repr) > 500:
                raw_repr = raw_repr[:500] + '...'
            print(f"    Raw banner ({len(raw)} chars):"
                  f" {raw_repr}")

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
                        print(f"    [dry-run] would delete"
                              f" {png_path}")
                log_file = (
                    Path(logs_dir) / f"{host}:{port}.log"
                )
                if log_file.is_file() and not dry_run:
                    log_file.unlink()
                    print(f"    deleted {log_file}")
                elif log_file.is_file():
                    print(f"    [dry-run] would delete"
                          f" {log_file}")
                else:
                    print(f"    no log file to delete")
                if data_dir and not dry_run:
                    nj = _expunge_server_json(
                        data_dir, [(host, port)])
                    if nj:
                        print(f"    deleted {nj}"
                              f" data file(s)")
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
            print(f"  {len(removals)} server(s) removed"
                  f" from {list_path}")
