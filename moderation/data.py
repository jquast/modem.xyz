"""Server list I/O and fingerprint data loading."""

import json
import os
import re
from pathlib import Path

from .util import _banner_hash


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


def _parse_ssl_from_line(line):
    """Extract ssl keyword presence from a server list line.

    :param line: original line text from the server list
    :returns: True if ``ssl`` keyword is present after host and port
    """
    parts = line.split()
    return 'ssl' in parts[2:]


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


def _parse_host_port_ssl_set(path):
    """Parse a server list into a set of (host_lower, port, ssl) tuples.

    :param path: path to server list file
    :returns: set of (host, port, ssl_bool) tuples
    """
    result = set()
    for host, port, line in load_server_list(path):
        if host is not None:
            ssl = _parse_ssl_from_line(line)
            result.add((host.lower(), port, ssl))
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
    removals_lower = {(h.lower(), p) for h, p in removals}
    for host, port, original in entries:
        if host is not None and (host.lower(), port) in removals_lower:
            removed += 1
            continue
        lines.append(original + "\n")
        if host is not None:
            kept += 1

    if dry_run:
        print(f"  [dry-run] would write {output}:"
              f" kept {kept}, removed {removed}")
        return removed

    with open(output, "w", encoding="utf-8") as f:
        f.writelines(lines)

    os.replace(output, path)
    print(f"  wrote {path}: kept {kept}, removed {removed}")
    return removed


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
        mssp_name = (
            mssp.get("NAME", "") if isinstance(mssp, dict) else ""
        )

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
                "mssp": mssp if isinstance(mssp, dict) else {},
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

    :param data_dir: path to the ``server/`` directory containing
        fingerprints
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


def append_to_list(path, new_lines, dry_run=False):
    """Append new entries to a server list file.

    Uses atomic write via ``.new`` + :func:`os.replace`, same
    pattern as :func:`write_filtered_list`.

    :param path: path to server list file
    :param new_lines: list of line strings to append (without newlines)
    :param dry_run: if True, only print what would happen
    :returns: number of lines appended
    """
    if not new_lines:
        return 0
    path = Path(path)
    if dry_run:
        print(f"  [dry-run] would append {len(new_lines)}"
              f" line(s) to {path.name}")
        return len(new_lines)

    existing = path.read_text(encoding="utf-8")
    output = Path(str(path) + ".new")
    with open(output, "w", encoding="utf-8") as f:
        f.write(existing)
        if existing and not existing.endswith("\n"):
            f.write("\n")
        for line in new_lines:
            f.write(line + "\n")
    os.replace(output, path)
    print(f"  appended {len(new_lines)} line(s) to {path.name}")
    return len(new_lines)


def update_list_entry(path, host, port, add_keyword, dry_run=False):
    """Add a keyword to an existing server list entry.

    :param path: path to server list file
    :param host: server hostname to match
    :param port: server port to match
    :param add_keyword: keyword string to append (e.g. ``'ssl'``)
    :param dry_run: if True, don't write
    :returns: True if the entry was found and updated
    """
    entries = load_server_list(path)
    updated = False
    new_entries = []
    for h, p, line in entries:
        if h == host and p == port:
            parts = line.split()
            if add_keyword not in parts[2:]:
                parts.append(add_keyword)
            new_entries.append((h, p, ' '.join(parts)))
            updated = True
        else:
            new_entries.append((h, p, line))
    if updated and not dry_run:
        output = Path(str(path) + ".new")
        with open(output, "w", encoding="utf-8") as f:
            for _, _, line in new_entries:
                f.write(line + "\n")
        os.replace(output, path)
    return updated
