"""Duplicate grouping, interactive review, and dead-server pruning."""

import collections
import os
import re
import sys
from pathlib import Path

from .data import (
    _parse_host_port_set,
    build_alive_set,
    deduplicate_records,
    detect_failure_reason,
    load_server_list,
    load_server_records,
    write_filtered_list,
)
from .decisions import _group_cache_key
from .encoding import _expunge_logs, _expunge_server_json
from .util import (
    _display_banner,
    _is_ip_address,
    _normalize_mssp_name,
    _prompt,
    _resolve_hostnames,
)


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


def _print_group_member(idx, rec, removals, source_label=None):
    """Print one member of a duplicate group."""
    marker = (
        "x" if (rec["host"], rec["port"]) in removals else " "
    )
    mssp = (
        f"  name={rec['mssp_name']!r}" if rec["mssp_name"] else ""
    )
    source = f"  [{source_label}]" if source_label else ""
    print(f"  [{marker}] {idx}. {rec['host']}:{rec['port']}"
          f"  ip={rec['ip']}"
          f"  fp={rec['fingerprint'][:12]}{mssp}{source}")

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
    items = sorted(
        groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
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

        print("  Enter numbers to remove (e.g. '2 3'),"
              " [*] rescan all, [s]kip, [q]uit")
        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return removals

        if choice == "q":
            return removals
        if choice == "*":
            if logs_dir:
                servers = [
                    (r['host'], r['port']) for r in members
                ]
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
                decisions["dupes"][cache_key] = {
                    "action": "skip"}
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
                    print(f"    -> remove"
                          f" {rec['host']}:{rec['port']}")
            except ValueError:
                continue

        if decisions is not None:
            if removed:
                decisions["dupes"][cache_key] = {
                    "action": "remove",
                    "remove": removed,
                }
            else:
                decisions["dupes"][cache_key] = {
                    "action": "skip"}

    if cached_count:
        print(f"\n  ({cached_count} group(s)"
              f" auto-resolved from cache)")

    return removals


def _report_groups(groups, label):
    """Non-interactive report of duplicate groups."""
    items = sorted(
        groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    print(f"\n  {label}: {len(items)} group(s)")
    for key, members in items:
        if isinstance(key, tuple):
            print(f"\n    fp={key[0][:12]}  ip={key[1]}:")
        else:
            print(f"\n    {key}:")
        for rec in members:
            mssp = (
                f"  name={rec['mssp_name']!r}"
                if rec["mssp_name"] else ""
            )
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
            print(f"  error deleting {p}: {err}",
                  file=sys.stderr)


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
            reason = detect_failure_reason(
                host, str(port), logs_dir)
            dead.append((host, port, reason))

    total = sum(1 for h, _, _ in entries if h is not None)
    alive_count = total - len(dead)

    if not dead:
        print(f"  {total} entries, all alive."
              f" Nothing to prune.")
        return set()

    print()
    for host, port, reason in dead:
        print(f"  DEAD: {host}:{port} -- {reason}")

    print(f"\n  Total: {total}, Alive: {alive_count},"
          f" Dead: {len(dead)}")

    if report_only:
        return set()

    answer = _prompt(
        f"\n  Remove {len(dead)} dead entries? [y/N/x] ", "ynx")
    if answer == "x":
        servers = [(h, p) for h, p, _ in dead]
        deleted_logs = _expunge_logs(logs_dir, servers)
        deleted_json = _expunge_server_json(data_dir, servers)
        print(f"  Expunged {deleted_logs} log(s),"
              f" {deleted_json} data file(s) for rescan")
        answer = _prompt(
            f"  Now remove from list? [y/N] ", "yn")

    if answer != "y":
        print("  Skipped.")
        return set()

    removals = {(h, p) for h, p, _ in dead}
    write_filtered_list(
        list_path, entries, removals, dry_run=dry_run)
    return removals


def find_duplicates(list_path, data_dir, report_only=False,
                    prune_data=False, dry_run=False,
                    decisions=None, logs_dir=None):
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

    current_entries = _parse_host_port_set(list_path)
    records = [r for r in records
               if (r["host"].lower(), r["port"])
               in current_entries]

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

    total = (
        len(fp_ip_groups) + len(extra_banner) + len(extra_mssp)
    )
    print(f"  {len(fp_ip_groups)} groups by fingerprint + IP")
    if extra_banner:
        print(f"  {len(extra_banner)} additional"
              f" by banner similarity")
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
            fp_ip_groups, "Fingerprint + IP duplicates",
            decisions,
            logs_dir=logs_dir, data_dir=str(data_dir))
        removals.update(r)
    if extra_banner:
        r = _review_groups(
            extra_banner, "Banner similarity duplicates",
            decisions,
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

    print(f"\n  {len(removals)} entry/entries"
          f" marked for removal:")
    for host, port in sorted(removals):
        print(f"    {host}:{port}")

    answer = _prompt("\n  Apply changes? [y/N] ", "yn")
    if answer != "y":
        print("  Cancelled.")
        return set()

    entries = load_server_list(list_path)
    write_filtered_list(
        list_path, entries, removals, dry_run=dry_run)

    if prune_data:
        _prune_data_files(records, removals)

    return removals


_BBS_HOST_RE = re.compile(
    r'(bbs|synchro|board|commodore|c64|amiga|mystic'
    r'|renegade|wwiv|telegard)', re.IGNORECASE)
_BBS_BANNER_RE = re.compile(
    r'(synchronet|mystic\s*bbs|renegade|wwiv|telegard'
    r'|maximus|wildcat|pcboard|remote\s*access'
    r'|oblivion/2|iniquity|enthral|daydream'
    r'|eclipse\s*bbs|\bBBS\b)', re.IGNORECASE)


def _is_bbs_entry(host, port, bbs_lines, rec):
    """Determine whether a cross-list entry is a BBS.

    :param host: lowercase hostname
    :param port: port number
    :param bbs_lines: dict ``{(host, port): line_text}`` from BBS list
    :param rec: fingerprint record dict, or None
    :returns: True if entry looks like a BBS
    """
    if _BBS_HOST_RE.search(host):
        return True
    bbs_line = bbs_lines.get((host, port), "")
    parts = bbs_line.split()
    if len(parts) > 2:
        enc = parts[2].lower()
        if enc in ("cp437", "cp850", "petscii"):
            return True
    if rec:
        banner = ((rec.get("banner_before", "") or "")
                  + (rec.get("banner_after", "") or ""))
        if _BBS_BANNER_RE.search(banner):
            return True
    return False


def _batch_cross_resolve(conflicts, mud_records, bbs_records,
                         mud_list, bbs_list, decisions, dry_run):
    """Auto-resolve cross-list conflicts.

    Default: keep in MUD list (remove from BBS).  Entries are kept
    in the BBS list instead when any of these signals are present:

    - Hostname matches BBS keywords (bbs, synchro, mystic, etc.)
    - BBS list entry specifies a BBS encoding (cp437, cp850, petscii)
    - Banner contains BBS software identifiers (Synchronet, etc.)

    When no scan data exists in the primary data dirs, the ``.bak``
    directories are checked as a fallback for banner analysis.

    :returns: (mud_removals, bbs_removals) sets
    """
    # Load BBS list lines for encoding hints.
    bbs_lines = {}
    with open(bbs_list, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if len(parts) >= 2:
                try:
                    port_n = int(parts[1])
                    bbs_lines[(parts[0].lower(), port_n)] = s
                except ValueError:
                    pass

    mud_removals = set()
    bbs_removals = set()
    keep_mud = []
    keep_bbs = []

    for host, port in sorted(conflicts):
        rec = (mud_records.get((host, port))
               or bbs_records.get((host, port)))
        if _is_bbs_entry(host, port, bbs_lines, rec):
            mud_removals.add((host, port))
            keep_bbs.append(f"{host}:{port}")
        else:
            bbs_removals.add((host, port))
            keep_mud.append(f"{host}:{port}")

    print(f"\n  Batch cross-list resolution:")
    print(f"    {len(keep_mud)} -> keep in MUD list"
          f" (remove from BBS)")
    print(f"    {len(keep_bbs)} -> keep in BBS list"
          f" (remove from MUD)")

    if keep_bbs:
        print(f"\n  Identified as BBS ({len(keep_bbs)}):")
        for entry in keep_bbs:
            print(f"    {entry}")
    if keep_mud:
        print(f"\n  Default to MUD ({len(keep_mud)}):")
        for entry in keep_mud:
            print(f"    {entry}")

    answer = _prompt("\n  Apply changes? [y/N] ", "yn")
    if answer != "y":
        print("  Cancelled.")
        return set(), set()

    if decisions is not None:
        for host, port in bbs_removals:
            decisions["cross"][f"{host}:{port}"] = "m"
        for host, port in mud_removals:
            decisions["cross"][f"{host}:{port}"] = "b"

    if mud_removals:
        entries = load_server_list(mud_list)
        write_filtered_list(
            mud_list, entries, mud_removals, dry_run=dry_run)
    if bbs_removals:
        entries = load_server_list(bbs_list)
        write_filtered_list(
            bbs_list, entries, bbs_removals, dry_run=dry_run)

    return mud_removals, bbs_removals


def find_cross_list_conflicts(mud_list, bbs_list, mud_data_dir,
                              bbs_data_dir, report_only=False,
                              dry_run=False, decisions=None,
                              batch_cross=False):
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
    :param batch_cross: if True, auto-resolve using MSSP heuristic
    :returns: (mud_removals, bbs_removals) sets
    """
    mud_list = Path(mud_list)
    bbs_list = Path(bbs_list)

    print(f"\n--- Cross-list conflicts"
          f" (entries in both lists) ---")

    mud_set = _parse_host_port_set(mud_list)
    bbs_set = _parse_host_port_set(bbs_list)

    conflicts = mud_set & bbs_set
    if not conflicts:
        print("  No entries appear in both lists.")
        return set(), set()

    print(f"  {len(conflicts)} entries found in both lists")

    mud_records = {
        (r["host"].lower(), r["port"]): r
        for r in deduplicate_records(
            load_server_records(Path(mud_data_dir)))
    }
    bbs_records = {
        (r["host"].lower(), r["port"]): r
        for r in deduplicate_records(
            load_server_records(Path(bbs_data_dir)))
    }

    if report_only:
        for host, port in sorted(conflicts):
            rec = (mud_records.get((host, port))
                   or bbs_records.get((host, port)))
            fp = rec["fingerprint"][:12] if rec else "?"
            mssp = ""
            if rec and rec.get("mssp_name"):
                mssp = f"  name={rec['mssp_name']!r}"
            print(f"    {host}:{port}  fp={fp}{mssp}")
        return set(), set()

    mud_removals = set()
    bbs_removals = set()

    if batch_cross:
        return _batch_cross_resolve(
            conflicts, mud_records, bbs_records,
            mud_list, bbs_list, decisions, dry_run)
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

        print(f"\n--- Conflict {idx}/{len(conflicts)}:"
              f" {host}:{port} ---")

        rec = (mud_records.get((host, port))
               or bbs_records.get((host, port)))
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
        print("  Keep in: [m]ud, [b]bs,"
              " [k]eep both, [s]kip, [q]uit")

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

        if (decisions is not None
                and choice in ("m", "b", "k", "s")):
            decisions["cross"][cache_key] = choice

    if cached_count:
        print(f"\n  ({cached_count} conflict(s)"
              f" auto-resolved from cache)")

    if not mud_removals and not bbs_removals:
        print("\n  No changes.")
        return set(), set()

    if mud_removals:
        print(f"\n  {len(mud_removals)} to remove"
              f" from MUD list:")
        for host, port in sorted(mud_removals):
            print(f"    {host}:{port}")
    if bbs_removals:
        print(f"\n  {len(bbs_removals)} to remove"
              f" from BBS list:")
        for host, port in sorted(bbs_removals):
            print(f"    {host}:{port}")

    answer = _prompt("\n  Apply changes? [y/N] ", "yn")
    if answer != "y":
        print("  Cancelled.")
        return set(), set()

    if mud_removals:
        entries = load_server_list(mud_list)
        write_filtered_list(
            mud_list, entries, mud_removals, dry_run=dry_run)
    if bbs_removals:
        entries = load_server_list(bbs_list)
        write_filtered_list(
            bbs_list, entries, bbs_removals, dry_run=dry_run)

    return mud_removals, bbs_removals


def find_dns_duplicates(mud_list, bbs_list, report_only=False,
                        dry_run=False):
    """Remove IP entries that duplicate a hostname entry.

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

    print(f"\n--- DNS deduplication"
          f" (prefer hostname over IP) ---")

    mud_set = (
        _parse_host_port_set(mud_list)
        if mud_list.is_file() else set()
    )
    bbs_set = (
        _parse_host_port_set(bbs_list)
        if bbs_list.is_file() else set()
    )
    all_entries = set()
    for host, port in mud_set:
        all_entries.add((host, port, "mud"))
    for host, port in bbs_set:
        all_entries.add((host, port, "bbs"))

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

    print("  Resolving hostnames ...", file=sys.stderr)
    resolved = _resolve_hostnames(hostnames)

    ip_to_hostname = collections.defaultdict(list)
    for host, port, source in all_entries:
        if not _is_ip_address(host):
            for ip in resolved.get(host, ()):
                ip_to_hostname[(ip, port)].append(
                    (host, port, source))

    mud_removals = set()
    bbs_removals = set()
    for ip, port, source in ip_entries:
        hostname_entries = ip_to_hostname.get((ip, port))
        if hostname_entries:
            names = ", ".join(
                h for h, _, _ in hostname_entries[:3])
            print(f"  auto-remove {ip}:{port}"
                  f" [{source}] -> {names}")
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
        write_filtered_list(
            mud_list, entries, mud_removals, dry_run=dry_run)
    if bbs_removals and bbs_list.is_file():
        entries = load_server_list(bbs_list)
        write_filtered_list(
            bbs_list, entries, bbs_removals, dry_run=dry_run)

    return mud_removals, bbs_removals
