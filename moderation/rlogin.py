"""Detect RLogin servers and unanswered codepage prompts from collected banners.

Scans fingerprint JSON data for banners that indicate the server rejected
a Telnet probe with an RLogin error, cross-references with the server list,
and offers to add the ``rlogin`` keyword and delete the stale log file so
the server is re-scanned with the correct protocol.

Also finds servers whose banners contain an unanswered codepage selection
prompt (e.g. "Select Terminal Codepage [ENTER]=CP437") and offers to delete
their log files so they are re-scanned now that the fingerprint client
automatically responds to these prompts.
"""

import json
import os
import re

from .data import load_server_list
from .encoding import _expunge_logs
from .util import _display_banner, _prompt


# Matches the rejection message an RLogin server sends when it receives
# Telnet IAC bytes instead of the RLogin handshake.
_RLOGIN_REJECTION_RE = re.compile(
    r'Expected RLogin|Failed to detect protocol',
    re.IGNORECASE,
)

# Matches codepage/option prompts where pressing Enter accepts a default:
#   "Select Terminal Codepage [Enter = CP437]:"  (= inside brackets)
#   "ENTER TERMINAL TYPE (ENTER=ASCII)"          (= inside parens)
#   "Select Terminal Codepage [ENTER]=CP437"     (= outside brackets)
_CODEPAGE_PROMPT_RE = re.compile(
    r'[\[<(](?:enter|return)(?:\s*=|[\]>)]\s*=)',
    re.IGNORECASE,
)


def _has_rlogin_keyword(line):
    """Return True if *line* already carries the ``rlogin`` keyword.

    :param line: original line text from the server list
    :returns: bool
    """
    return 'rlogin' in line.split()[2:]


def discover_rlogin_banners(data_dir, list_path):
    """Find server list entries whose banners show RLogin rejection.

    Scans every JSON fingerprint file under ``data_dir/server/`` and
    matches sessions against *list_path* entries that lack the ``rlogin``
    keyword.  Only entries whose ``banner_before_return`` contains a known
    RLogin rejection string are returned.

    :param data_dir: path to data directory (contains ``server/``)
    :param list_path: path to server list file (bbslist.txt / mudlist.txt)
    :returns: list of dicts with keys ``host``, ``port``, ``banner``
    """
    # Build a map of (host_lower, port) → original_line for untagged entries.
    untagged = {}
    for host, port, line in load_server_list(list_path):
        if host is None:
            continue
        if not _has_rlogin_keyword(line):
            untagged[(host.lower(), port)] = line

    if not untagged:
        return []

    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return []

    # Collect hits, deduplicating by (host, port) keeping the most recent.
    hits = {}  # (host_lower, port) → dict

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

            probe = data.get('server-probe', {})
            # Skip sessions already correctly probed as rlogin.
            if probe.get('fingerprint-data', {}).get(
                    'probed-protocol') == 'rlogin':
                continue

            session_data = probe.get('session_data', {})
            banner = session_data.get('banner_before_return', '')
            if not _RLOGIN_REJECTION_RE.search(banner):
                continue

            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if not host or not port:
                    continue
                key = (host.lower(), port)
                if key not in untagged:
                    continue
                connected = session.get('connected', '')
                existing = hits.get(key)
                if existing is None or connected > existing['connected']:
                    hits[key] = {
                        'host': host,
                        'port': port,
                        'banner': banner,
                        'connected': connected,
                    }

    return sorted(hits.values(), key=lambda r: (r['host'], r['port']))


def _apply_rlogin_tags_bulk(list_path, servers, dry_run=False):
    """Add ``rlogin`` keyword to multiple server list entries in one write.

    :param list_path: path to server list file
    :param servers: iterable of (host, port) tuples
    :param dry_run: if True, don't write the file
    :returns: number of entries updated
    """
    target = {(h.lower(), p) for h, p in servers}
    entries = load_server_list(list_path)
    updated = 0
    new_entries = []
    for h, p, line in entries:
        if h is not None and (h.lower(), p) in target:
            parts = line.split()
            if 'rlogin' not in parts[2:]:
                parts.append('rlogin')
                new_entries.append((h, p, ' '.join(parts)))
                updated += 1
            else:
                new_entries.append((h, p, line))
        else:
            new_entries.append((h, p, line))

    if updated and not dry_run:
        with open(list_path, 'w', encoding='utf-8') as f:
            for _, _, line in new_entries:
                f.write(line + '\n')

    return updated


def review_rlogin_banners(
    mud_issues, bbs_issues,
    mud_list, bbs_list, logs_dir,
    report_only=False,
    dry_run=False,
):
    """Interactively review RLogin banner detections and apply fixes.

    Presents each detected server, offers to add the ``rlogin`` keyword
    to its list entry and delete its log file so the next scan uses the
    correct protocol.

    :param mud_issues: list of dicts from :func:`discover_rlogin_banners`
        for the MUD list
    :param bbs_issues: list of dicts from :func:`discover_rlogin_banners`
        for the BBS list
    :param mud_list: path to MUD server list file
    :param bbs_list: path to BBS server list file
    :param logs_dir: path to logs directory
    :param report_only: if True, only print; no prompts or changes
    :param dry_run: if True, show what would change without writing
    """
    all_work = []
    for issue in mud_issues:
        all_work.append((issue, mud_list, 'MUD'))
    for issue in bbs_issues:
        all_work.append((issue, bbs_list, 'BBS'))

    total = len(all_work)
    print(f"\n  {total} server(s) with RLogin rejection banners"
          f" and no 'rlogin' keyword:\n")

    if report_only:
        for issue, list_path, label in all_work:
            banner_snip = _display_banner(issue['banner'], maxlines=2)
            print(f"  [{label}] {issue['host']} {issue['port']}")
            if banner_snip:
                for line in banner_snip.splitlines():
                    print(f"      {line}")
        return

    # Group by list file for bulk application.
    mud_confirmed = []
    bbs_confirmed = []

    for idx, (issue, list_path, label) in enumerate(all_work, 1):
        host = issue['host']
        port = issue['port']
        banner_snip = _display_banner(issue['banner'], maxlines=2)

        print(f"\n  [{idx}/{total}] [{label}] {host} {port}")
        if banner_snip:
            for line in banner_snip.splitlines():
                print(f"    {line}")

        ans = _prompt(
            f"  Add 'rlogin', delete log for re-scan?"
            f" [y/n/a(ll)/q(uit)] ",
            "yanq",
        )
        if ans is None or ans == 'q':
            print("  Stopped.")
            break
        if ans == 'a':
            remaining = all_work[idx - 1:]
            for rem_issue, rem_list, rem_label in remaining:
                if rem_list == mud_list:
                    mud_confirmed.append(
                        (rem_issue['host'], rem_issue['port']))
                else:
                    bbs_confirmed.append(
                        (rem_issue['host'], rem_issue['port']))
            print(f"  Accepting all remaining ({len(remaining)}).")
            break
        if ans == 'y':
            if list_path == mud_list:
                mud_confirmed.append((host, port))
            else:
                bbs_confirmed.append((host, port))

    _apply_confirmed(
        mud_confirmed, bbs_confirmed,
        mud_list, bbs_list, logs_dir,
        dry_run=dry_run,
    )


def _apply_confirmed(
    mud_confirmed, bbs_confirmed,
    mud_list, bbs_list, logs_dir,
    dry_run=False,
):
    """Apply confirmed rlogin tags and log deletions.

    :param mud_confirmed: list of (host, port) tuples for MUD list
    :param bbs_confirmed: list of (host, port) tuples for BBS list
    :param mud_list: path to MUD server list file
    :param bbs_list: path to BBS server list file
    :param logs_dir: path to logs directory
    :param dry_run: if True, show what would change without writing
    """
    all_confirmed = mud_confirmed + bbs_confirmed
    if not all_confirmed:
        print("  Nothing to update.")
        return

    if dry_run:
        for host, port in all_confirmed:
            print(f"  [dry-run] would tag {host} {port} rlogin"
                  f" and delete {host}:{port}.log")
        return

    if mud_confirmed:
        n = _apply_rlogin_tags_bulk(mud_list, mud_confirmed)
        print(f"  Tagged {n} entry/entries in {mud_list}")
    if bbs_confirmed:
        n = _apply_rlogin_tags_bulk(bbs_list, bbs_confirmed)
        print(f"  Tagged {n} entry/entries in {bbs_list}")

    deleted = _expunge_logs(logs_dir, all_confirmed)
    print(f"  Deleted {deleted} log file(s) — entries queued for re-scan")


def discover_codepage_prompts(data_dir, list_path):
    """Find servers whose banners contain an unanswered codepage selection prompt.

    These are servers that displayed e.g. "Select Terminal Codepage [ENTER]=CP437"
    before the fingerprint client knew to respond.  Deleting their logs queues
    them for re-scan so the client can now press RETURN automatically.

    :param data_dir: path to data directory (contains ``server/``)
    :param list_path: path to server list file (bbslist.txt / mudlist.txt)
    :returns: list of dicts with keys ``host``, ``port``, ``banner``
    """
    known = {}
    for host, port, line in load_server_list(list_path):
        if host is None:
            continue
        known[(host.lower(), port)] = line

    if not known:
        return []

    server_dir = os.path.join(data_dir, 'server')
    if not os.path.isdir(server_dir):
        return []

    hits = {}  # (host_lower, port) → dict, keep most recent

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

            probe = data.get('server-probe', {})
            session_data = probe.get('session_data', {})
            banner_before = session_data.get('banner_before_return', '')
            banner_after = session_data.get('banner_after_return', '')
            combined = (banner_before or '') + (banner_after or '')

            if not _CODEPAGE_PROMPT_RE.search(combined):
                continue

            for session in data.get('sessions', []):
                host = session.get('host', '')
                port = session.get('port', 0)
                if not host or not port:
                    continue
                key = (host.lower(), port)
                if key not in known:
                    continue
                connected = session.get('connected', '')
                existing = hits.get(key)
                if existing is None or connected > existing['connected']:
                    hits[key] = {
                        'host': host,
                        'port': port,
                        'banner': combined,
                        'connected': connected,
                    }

    return sorted(hits.values(), key=lambda r: (r['host'], r['port']))


def review_codepage_prompts(
    mud_issues, bbs_issues,
    logs_dir,
    report_only=False,
    dry_run=False,
):
    """Interactively review servers with unanswered codepage prompts.

    Offers to delete each server's log file so it is re-scanned using the
    updated fingerprint client that now auto-responds to these prompts.

    :param mud_issues: list of dicts from :func:`discover_codepage_prompts`
        for the MUD list
    :param bbs_issues: list of dicts from :func:`discover_codepage_prompts`
        for the BBS list
    :param logs_dir: path to logs directory
    :param report_only: if True, only print; no prompts or changes
    :param dry_run: if True, show what would change without writing
    """
    all_work = [('MUD', i) for i in mud_issues] + \
               [('BBS', i) for i in bbs_issues]
    total = len(all_work)
    print(f"\n  {total} server(s) with unanswered codepage selection"
          f" prompt:\n")

    if report_only:
        for label, issue in all_work:
            snip = _display_banner(issue['banner'], maxlines=2)
            print(f"  [{label}] {issue['host']} {issue['port']}")
            if snip:
                for line in snip.splitlines():
                    print(f"      {line}")
        return

    confirmed = []
    for idx, (label, issue) in enumerate(all_work, 1):
        host = issue['host']
        port = issue['port']
        snip = _display_banner(issue['banner'], maxlines=3)
        print(f"\n  [{idx}/{total}] [{label}] {host} {port}")
        if snip:
            for line in snip.splitlines():
                print(f"    {line}")

        ans = _prompt(
            "  Delete log for re-scan? [y/n/a(ll)/q(uit)] ",
            "yanq",
        )
        if ans is None or ans == 'q':
            print("  Stopped.")
            break
        if ans == 'a':
            remaining = all_work[idx - 1:]
            confirmed.extend(
                (rem['host'], rem['port']) for _, rem in remaining)
            print(f"  Accepting all remaining ({len(remaining)}).")
            break
        if ans == 'y':
            confirmed.append((host, port))

    if not confirmed:
        print("  Nothing to update.")
        return

    if dry_run:
        for host, port in confirmed:
            print(f"  [dry-run] would delete log for {host}:{port}")
        return

    deleted = _expunge_logs(logs_dir, confirmed)
    print(f"  Deleted {deleted} log file(s) — entries queued for re-scan")
