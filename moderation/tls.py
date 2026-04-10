"""TLS/SSL port discovery from MSSP data."""

import json
import os

from make_stats.common import _first_str

from .data import (
    _parse_host_port_ssl_set,
    append_to_list,
    load_server_list,
    update_list_entry,
)
from .util import _prompt


def _detect_tls_port(mssp):
    """Detect TLS/SSL port from MSSP fields.

    Checks the ``TLS`` and ``SSL`` MSSP keys.  Values of ``0`` and
    ``-1`` are treated as "not supported".  A value of ``1`` means TLS
    is on the same port.  Any other positive integer is the TLS port.

    :param mssp: MSSP dict from fingerprint data
    :returns: (port_int_or_None, same_port_bool)
    """
    for field in ('TLS', 'SSL'):
        val = _first_str(mssp.get(field, ''))
        if not val or val in ('0', '-1'):
            continue
        if val == '1':
            return 1, True
        try:
            port = int(val)
            if port > 0:
                return port, False
        except ValueError:
            continue
    return None, False


def discover_tls_ports(data_dir, list_path):
    """Scan fingerprint data for MSSP-advertised TLS ports not in the list.

    :param data_dir: path to data directory (containing ``server/``)
    :param list_path: path to server list file
    :returns: list of issue dicts
    """
    server_dir = os.path.join(str(data_dir), 'server')
    if not os.path.isdir(server_dir):
        return []

    ssl_entries = _parse_host_port_ssl_set(list_path)
    hp_set = {(h, p) for h, p, _ in ssl_entries}
    ssl_set = {(h, p) for h, p, s in ssl_entries if s}

    issues = []
    seen = set()

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
            session_data = probe.get('session_data', {})
            mssp = session_data.get('mssp', {})
            if not isinstance(mssp, dict):
                continue

            sessions = data.get('sessions', [])
            if not sessions:
                continue
            session = sessions[-1]
            host = session.get('host', '')
            port = session.get('port', 0)

            if not host or not port:
                continue
            if (host.lower(), port) not in hp_set:
                continue

            tls_port, same_port = _detect_tls_port(mssp)
            if tls_port is None:
                continue

            if same_port:
                key = (host.lower(), port)
            else:
                key = (host.lower(), tls_port)
            if key in seen:
                continue
            seen.add(key)

            mssp_name = (
                mssp.get('NAME', '') if isinstance(mssp, dict) else ''
            )

            existing_line = None
            for h, p, line in load_server_list(list_path):
                if h == host and p == port:
                    existing_line = line
                    break

            if same_port:
                if (host.lower(), port) in ssl_set:
                    continue
                issues.append({
                    'host': host,
                    'port': port,
                    'tls_port': port,
                    'same_port': True,
                    'mssp_name': mssp_name,
                    'existing_line': existing_line,
                })
            else:
                if (host.lower(), tls_port) in hp_set:
                    continue
                issues.append({
                    'host': host,
                    'port': port,
                    'tls_port': tls_port,
                    'same_port': False,
                    'mssp_name': mssp_name,
                    'existing_line': existing_line,
                })

    return issues


def _build_ssl_line(existing_line, host, tls_port):
    """Build a new server list line for a TLS port entry.

    Copies encoding and column overrides from the existing entry,
    swaps the port, and appends ``ssl``.

    :param existing_line: the original list line for the plaintext entry
    :param host: server hostname
    :param tls_port: TLS port number
    :returns: new line string
    """
    if not existing_line:
        return f"{host} {tls_port} ssl"
    parts = existing_line.split()
    parts[1] = str(tls_port)
    if 'ssl' not in parts[2:]:
        parts.append('ssl')
    return ' '.join(parts)


def review_tls_ports(mud_issues, bbs_issues, mud_list, bbs_list,
                     report_only=False, dry_run=False):
    """Review and apply MSSP-advertised TLS port discoveries.

    :param mud_issues: list of TLS issue dicts for MUDs
    :param bbs_issues: list of TLS issue dicts for BBSes
    :param mud_list: path to MUD server list
    :param bbs_list: path to BBS server list
    :param report_only: if True, only print report
    :param dry_run: if True, show changes without writing
    """
    all_sets = [
        ('MUD', mud_issues, mud_list),
        ('BBS', bbs_issues, bbs_list),
    ]

    for label, issues, list_path in all_sets:
        if not issues:
            continue

        same_port = [i for i in issues if i['same_port']]
        diff_port = [i for i in issues if not i['same_port']]

        print(f"\n--- {label} TLS discoveries ---")
        if diff_port:
            print(f"  {len(diff_port)} server(s) advertise TLS"
                  f" on a different port (new entry needed):")
            for issue in diff_port:
                name = (f"  ({issue['mssp_name']})"
                        if issue['mssp_name'] else "")
                print(f"    {issue['host']}:{issue['port']}"
                      f" -> TLS port {issue['tls_port']}{name}")

        if same_port:
            print(f"  {len(same_port)} server(s) advertise TLS"
                  f" on the same port (add ssl keyword):")
            for issue in same_port:
                name = (f"  ({issue['mssp_name']})"
                        if issue['mssp_name'] else "")
                print(f"    {issue['host']}:{issue['port']}{name}")

        if report_only:
            continue

        if diff_port:
            print(f"\n  [a]dd all {len(diff_port)} new TLS entries,"
                  f" [r]eview each, [s]kip")
            choice = _prompt("  > ", "ars")
            if choice == 'a':
                new_lines = []
                for issue in diff_port:
                    line = _build_ssl_line(
                        issue['existing_line'],
                        issue['host'], issue['tls_port'])
                    new_lines.append(line)
                    print(f"    + {line}")
                append_to_list(list_path, new_lines,
                               dry_run=dry_run)
            elif choice == 'r':
                new_lines = []
                for issue in diff_port:
                    line = _build_ssl_line(
                        issue['existing_line'],
                        issue['host'], issue['tls_port'])
                    name = (f"  ({issue['mssp_name']})"
                            if issue['mssp_name'] else "")
                    print(f"\n    {issue['host']}:{issue['port']}"
                          f" -> {issue['tls_port']}{name}")
                    print(f"    new line: {line}")
                    ans = _prompt("    [a]dd / [s]kip? ", "as")
                    if ans == 'a':
                        new_lines.append(line)
                if new_lines:
                    append_to_list(list_path, new_lines,
                                   dry_run=dry_run)

        if same_port:
            print(f"\n  [a]dd ssl keyword to all"
                  f" {len(same_port)} entries,"
                  f" [r]eview each, [s]kip")
            choice = _prompt("  > ", "ars")
            if choice == 'a':
                for issue in same_port:
                    updated = update_list_entry(
                        list_path, issue['host'],
                        issue['port'], 'ssl', dry_run=dry_run)
                    if updated:
                        print(f"    ~ {issue['host']}"
                              f":{issue['port']} +ssl")
            elif choice == 'r':
                for issue in same_port:
                    name = (f"  ({issue['mssp_name']})"
                            if issue['mssp_name'] else "")
                    print(f"\n    {issue['host']}"
                          f":{issue['port']}{name}")
                    ans = _prompt("    [a]dd ssl / [s]kip? ",
                                  "as")
                    if ans == 'a':
                        updated = update_list_entry(
                            list_path, issue['host'],
                            issue['port'], 'ssl',
                            dry_run=dry_run)
                        if updated:
                            print(f"    ~ {issue['host']}"
                                  f":{issue['port']} +ssl")
