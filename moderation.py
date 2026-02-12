#!/usr/bin/env python
"""Interactive moderation tool for MUD and BBS server lists.

Combines dead-entry pruning, within-list duplicate detection, and
cross-list conflict resolution into a single interactive workflow.

Modes (run all by default, or select one):
  --only-dns      Only remove IP entries that duplicate a hostname (auto)
  --only-prune    Only prune dead servers (no fingerprint data)
  --only-dupes    Only find within-list duplicates
  --only-cross    Only find entries present in both MUD and BBS lists

Scope (moderate both by default, or select one):
  --mud           Only moderate the MUD list
  --bbs           Only moderate the BBS list

Other options:
  --report-only   Print report without interactive prompts
  --prune-data    Offer to delete data files for removed entries
  --dry-run       Show what would change without writing files
"""

import collections
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
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
DEFAULT_MUD_DATA = _HERE / "data-muds"
DEFAULT_BBS_DATA = _HERE / "data-bbs"
DEFAULT_LOGS = _HERE / "logs"
DEFAULT_DECISIONS = _HERE / "moderation_decisions.json"


# ── Utility helpers ──────────────────────────────────────────────────────

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


# ── DNS helpers ────────────────────────────────────────────────────────

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


# ── Decision cache ─────────────────────────────────────────────────────

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


# ── Server list I/O ─────────────────────────────────────────────────────

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


# ── Fingerprint data loading ────────────────────────────────────────────

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


# ── Duplicate grouping ──────────────────────────────────────────────────

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


# ── Interactive display ─────────────────────────────────────────────────

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


def _review_groups(groups, label, decisions=None, logs_dir=None):
    """Interactive review of duplicate groups.

    :param groups: dict of group key -> list of record dicts
    :param label: display label for the group type
    :param decisions: mutable decisions dict for caching, or None
    :param logs_dir: path to logs directory for rescan, or None
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
                logs_path = Path(logs_dir)
                deleted = 0
                for rec in members:
                    logfile = logs_path / f"{rec['host']}:{rec['port']}.log"
                    if logfile.is_file():
                        logfile.unlink()
                        deleted += 1
                print(f"    -> {deleted}/{len(members)} log(s) deleted for rescan")
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


# ── Prune dead servers ──────────────────────────────────────────────────

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

    answer = _prompt(f"\n  Remove {len(dead)} dead entries? [y/N] ", "yn")
    if answer != "y":
        print("  Skipped.")
        return set()

    removals = {(h, p) for h, p, _ in dead}
    write_filtered_list(list_path, entries, removals, dry_run=dry_run)
    return removals


# ── Within-list duplicates ──────────────────────────────────────────────

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
            logs_dir=logs_dir)
        removals.update(r)
    if extra_banner:
        r = _review_groups(
            extra_banner, "Banner similarity duplicates", decisions,
            logs_dir=logs_dir)
        removals.update(r)
    if extra_mssp:
        r = _review_groups(
            extra_mssp, "MSSP NAME duplicates", decisions,
            logs_dir=logs_dir)
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


# ── Cross-list conflicts ────────────────────────────────────────────────

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


# ── DNS deduplication ──────────────────────────────────────────────────

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


# ── CLI ─────────────────────────────────────────────────────────────────

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
        help=f"MUD data directory (default: {DEFAULT_MUD_DATA})",
    )
    paths.add_argument(
        "--bbs-data", default=str(DEFAULT_BBS_DATA),
        help=f"BBS data directory (default: {DEFAULT_BBS_DATA})",
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
    only_flags = (args.only_prune, args.only_dupes,
                  args.only_cross, args.only_dns)
    any_only = any(only_flags)
    do_prune = args.only_prune or not any_only
    do_dupes = args.only_dupes or not any_only
    do_cross = args.only_cross or not any_only
    do_dns = (args.only_dns or not any_only) and not args.skip_dns

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

    # Save decisions cache
    if decisions is not None:
        save_decisions(args.decisions, decisions)


if __name__ == "__main__":
    main()
