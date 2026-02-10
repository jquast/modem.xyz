"""MUD-specific statistics generation."""

import contextlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import tabulate as tabulate_mod

from make_stats.common import (
    _PROJECT_ROOT, _URL_RE,
    TELNET_OPTIONS_OF_INTEREST,
    PLOT_BG, PLOT_FG, PLOT_GREEN, PLOT_CYAN, PLOT_YELLOW, PLOT_BLUE,
    _listify, _first_str, _parse_int, _format_scan_time,
    _parse_server_list, _load_encoding_overrides,
    _rst_escape, _strip_ansi, _is_garbled, _strip_mxp_sgml,
    _clean_log_line, _combine_banners, _truncate,
    _banner_to_html, _banner_to_png, _banner_alt_text, _telnet_url,
    _rst_heading, print_datatable,
    _group_shared_ip, _group_by_banner, _most_common_hostname,
    _clean_dir, deduplicate_servers,
    _setup_plot_style, _group_small_slices, _pie_colors,
    create_telnet_options_plot,
)

DOCS_PATH = os.path.join(_PROJECT_ROOT, "docs-muds")
PLOTS_PATH = os.path.join(DOCS_PATH, "_static", "plots")
DETAIL_PATH = os.path.join(DOCS_PATH, "server_detail")
MUD_DETAIL_PATH = os.path.join(DOCS_PATH, "mud_detail")
BANNERS_PATH = os.path.join(DOCS_PATH, "_static", "banners")
GITHUB_DATA_BASE = ("https://github.com/jquast/modem.xyz"
                     "/tree/master/data-muds/server")

_MSSP_URL_SKIP = frozenset(('DISCORD', 'ICON'))
LOCITERM_URL = 'https://lociterm.com/telnetsupport.json'

MUD_PROTOCOLS = [
    'MSSP', 'GMCP', 'MSDP', 'MCCP', 'MCCP2',
    'MXP', 'MSP', 'MCP', 'ZMP',
]


# ---------------------------------------------------------------------------
# LociTerm support
# ---------------------------------------------------------------------------

def _load_telnetsupport(data_dir):
    """Fetch or load the LociTerm telnetsupport.json server list.

    :param data_dir: path to data directory
    :returns: dict mapping ``(host, port)`` to entry dict
    """
    import urllib.request

    local_path = os.path.join(data_dir, 'telnetsupport.json')

    try:
        req = urllib.request.Request(
            LOCITERM_URL, headers={'User-Agent': 'muds.modem.xyz'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        with open(local_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  fetched telnetsupport.json ({len(data)} entries)",
              file=sys.stderr)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"  telnetsupport.json fetch failed ({exc}), "
              f"using local copy", file=sys.stderr)
        if os.path.isfile(local_path):
            with open(local_path) as f:
                data = json.load(f)
            print(f"  loaded local telnetsupport.json"
                  f" ({len(data)} entries)",
                  file=sys.stderr)
        else:
            print("  no local telnetsupport.json found, "
                  "LociTerm links disabled", file=sys.stderr)
            return {}

    by_host_port = {}
    for entry in data:
        key = (entry.get('host', ''), entry.get('port', 0))
        by_host_port[key] = entry
    return by_host_port


def _annotate_lociterm(servers, telnetsupport):
    """Mark each server with LociTerm availability and SSL status.

    :param servers: list of server records (modified in place)
    :param telnetsupport: dict from :func:`_load_telnetsupport`
    """
    for s in servers:
        entry = telnetsupport.get((s['host'], s['port']))
        if entry:
            s['_loci_supported'] = True
            s['_loci_ssl'] = entry.get('ssl') == 1
        else:
            s['_loci_supported'] = False
            s['_loci_ssl'] = False


def _lociterm_url(host, port, tls_port='', loci_ssl=False):
    """Build a LociTerm play URL, preferring TLS when available.

    :param host: hostname
    :param port: primary port number
    :param tls_port: TLS port string from MSSP, or '' if unavailable
    :param loci_ssl: True if telnetsupport.json indicates SSL
    :returns: LociTerm URL string
    """
    if tls_port and tls_port not in ('1', str(port)):
        return (f"https://lociterm.com/play/"
                f"?host={host}&port={tls_port}&ssl=1")
    if tls_port or loci_ssl:
        return (f"https://lociterm.com/play/"
                f"?host={host}&port={port}&ssl=1")
    return f"https://lociterm.com/play/?host={host}&port={port}"


# ---------------------------------------------------------------------------
# MSSP helpers
# ---------------------------------------------------------------------------

def _fix_mojibake(text):
    """Try to recover UTF-8 text that was decoded as Latin-1."""
    try:
        recovered = text.encode('latin-1').decode('utf-8')
        if recovered != text:
            return recovered
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    return text


def _clean_mssp_str(text):
    """Clean an MSSP string field: strip ANSI and fix mojibake."""
    return _fix_mojibake(_strip_ansi(text))


def _detect_tls_port(record):
    """Detect TLS/SSL port from MSSP fields.

    :returns: port string if TLS/SSL supported, '' otherwise
    """
    mssp = record['mssp']
    for field in ('TLS', 'SSL'):
        val = _first_str(mssp.get(field, ''))
        if not val or val in ('0', '-1'):
            continue
        try:
            port = int(val)
            if port > 0:
                return str(port)
        except ValueError:
            continue
    return ''


def _is_adult(record):
    """Infer whether a server has adult content from MSSP fields.

    :returns: True if MSSP ``ADULT MATERIAL`` is '1' or
        ``MINIMUM AGE`` >= 18
    """
    mssp = record['mssp']
    adult_material = _first_str(mssp.get('ADULT MATERIAL', ''))
    if adult_material == '1':
        return True
    min_age = _parse_int(mssp.get('MINIMUM AGE', ''))
    if min_age is not None and min_age >= 18:
        return True
    return False


def _is_pay_to_play(record):
    """Detect whether a server requires payment from MSSP fields.

    :returns: True if MSSP ``PAY TO PLAY`` or ``PAY FOR PERKS`` is
        non-zero
    """
    mssp = record['mssp']
    for field in ('PAY TO PLAY', 'PAY FOR PERKS'):
        val = _first_str(mssp.get(field, ''))
        if val and val not in ('0', 'no', 'No', 'NO', ''):
            return True
    return False


def _parse_uptime_days(uptime_val, connected_iso):
    """Parse MSSP UPTIME (Unix epoch of last boot) into days of uptime.

    :param uptime_val: MSSP UPTIME value (string or list)
    :param connected_iso: ISO 8601 timestamp of when the scan connected
    :returns: integer days of uptime, or None if unparseable
    """
    ts = _parse_int(uptime_val)
    if not ts or ts <= 0:
        return None
    if not connected_iso:
        return None
    try:
        connected_dt = datetime.fromisoformat(connected_iso)
        boot_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        delta = connected_dt.astimezone(timezone.utc) - boot_dt
        days = delta.days
        if days < 0:
            return None
        return days
    except (ValueError, TypeError, OSError):
        return None


def _find_mssp_url(mssp):
    """Find the first HTTP/HTTPS URL in any MSSP field value.

    :param mssp: dict of MSSP fields
    :returns: URL string, or ''
    """
    for key, val in mssp.items():
        if key in _MSSP_URL_SKIP or key == 'WEBSITE':
            continue
        for v in _listify(val):
            match = _URL_RE.search(str(v))
            if match:
                return match.group(0)
    return ''


def _detect_protocols(record):
    """Detect MUD protocol support from MSSP flags and telnet
    negotiation."""
    protocols = {}
    mssp = record['mssp']
    offered = set(record['offered'])
    requested = set(record['requested'])
    server_offered = record['server_offered']
    server_requested = record['server_requested']

    negotiated = set()
    for opt, accepted in server_offered.items():
        if accepted:
            negotiated.add(opt)
    for opt, accepted in server_requested.items():
        if accepted:
            negotiated.add(opt)

    for proto in MUD_PROTOCOLS:
        mssp_val = mssp.get(proto, '')
        if mssp_val and str(mssp_val) == '1':
            protocols[proto] = 'mssp'
        elif (proto in negotiated or proto in offered
              or proto in requested):
            protocols[proto] = 'negotiated'
        else:
            protocols[proto] = 'no'

    if record['has_mssp']:
        protocols['MSSP'] = 'mssp'
    elif 'MSSP' in negotiated:
        protocols['MSSP'] = 'negotiated'

    return protocols


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_server_data(data_dir, encoding_overrides=None):
    """Load all server fingerprint JSON files from the data directory.

    :param data_dir: path to telnetlib3 data directory
    :param encoding_overrides: dict mapping (host, port) to encoding
    :returns: list of parsed server record dicts
    """
    if encoding_overrides is None:
        encoding_overrides = {}

    server_dir = os.path.join(data_dir, "server")
    if not os.path.isdir(server_dir):
        print(f"Error: {server_dir} is not a directory",
              file=sys.stderr)
        sys.exit(1)

    records = []
    for fp_dir in sorted(os.listdir(server_dir)):
        fp_path = os.path.join(server_dir, fp_dir)
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

            probe = data.get('server-probe', {})
            sessions = data.get('sessions', [])
            if not sessions:
                continue

            fp_data = probe.get('fingerprint-data', {})
            session_data = probe.get('session_data', {})
            mssp = session_data.get('mssp', {})
            option_states = session_data.get('option_states', {})
            session = sessions[-1]

            record = {
                'host': session.get('host',
                                    session.get('ip', 'unknown')),
                'ip': session.get('ip', ''),
                'port': session.get('port', 0),
                'connected': session.get('connected', ''),
                'fingerprint': probe.get('fingerprint', fp_dir),
                'data_path': f"{fp_dir}/{fname}",
                'offered': fp_data.get('offered-options', []),
                'requested': fp_data.get('requested-options', []),
                'refused': fp_data.get('refused-options', []),
                'server_offered': option_states.get(
                    'server_offered', {}),
                'server_requested': option_states.get(
                    'server_requested', {}),
                'encoding': session_data.get('encoding', 'unknown'),
                'banner_before': session_data.get(
                    'banner_before_return', ''),
                'banner_after': session_data.get(
                    'banner_after_return', ''),
                'timing': session_data.get('timing', {}),
                'has_mssp': bool(mssp),
                'mssp': mssp,
                'name': _clean_mssp_str(
                    _first_str(mssp.get('NAME', ''))),
                'codebase': ', '.join(
                    _listify(mssp.get('CODEBASE', ''))),
                'family': ', '.join(
                    _listify(mssp.get('FAMILY', ''))),
                'genre': ', '.join(
                    _listify(mssp.get('GENRE', ''))),
                'gameplay': ', '.join(
                    _listify(mssp.get('GAMEPLAY', ''))),
                'players': _parse_int(mssp.get('PLAYERS', '')),
                'created': _first_str(mssp.get('CREATED', '')),
                'status': ', '.join(
                    _listify(mssp.get('STATUS', ''))),
                'website': _first_str(mssp.get('WEBSITE', '')),
                'description': _first_str(
                    mssp.get('DESCRIPTION', '')),
                'location': ', '.join(
                    _listify(mssp.get('LOCATION', ''))),
                'language': ', '.join(
                    _listify(mssp.get('LANGUAGE', ''))),
                'discord': _first_str(mssp.get('DISCORD', '')),
            }

            record['encoding_override'] = encoding_overrides.get(
                (record['host'], record['port']), '')
            record['display_encoding'] = (
                record['encoding_override']
                or record['encoding']).lower()

            record['tls_port'] = _detect_tls_port(record)
            record['uptime_days'] = _parse_uptime_days(
                mssp.get('UPTIME', ''), record['connected'])

            if not record['website']:
                record['website'] = _find_mssp_url(mssp)

            if not record['website']:
                for banner_key in ('banner_before', 'banner_after'):
                    banner_text = record[banner_key]
                    if banner_text:
                        match = _URL_RE.search(
                            _strip_ansi(banner_text))
                        if match:
                            record['website'] = match.group(0)
                            break

            record['protocols'] = _detect_protocols(record)
            record['adult'] = _is_adult(record)
            record['pay_to_play'] = _is_pay_to_play(record)

            records.append(record)

    return records


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def compute_statistics(servers):
    """Compute aggregate statistics from server list.

    :param servers: list of deduplicated server records
    :returns: dict of statistics
    """
    connected_times = sorted(
        s['connected'] for s in servers if s['connected'])
    stats = {
        'total_servers': len(servers),
        'with_mssp': sum(1 for s in servers if s['has_mssp']),
        'unique_fingerprints': len(
            set(s['fingerprint'] for s in servers)),
        'total_players': sum(s['players'] or 0 for s in servers),
        'unique_codebases': len(
            set(s['codebase'] for s in servers if s['codebase'])),
        'unique_families': len(
            set(s['family'] for s in servers if s['family'])),
        'scan_time_first': (connected_times[0]
                            if connected_times else ''),
        'scan_time_last': (connected_times[-1]
                           if connected_times else ''),
    }

    proto_counts = Counter()
    for s in servers:
        for proto, status in s['protocols'].items():
            if status != 'no':
                proto_counts[proto] += 1
    stats['protocol_counts'] = dict(proto_counts)

    family_counts = Counter()
    for s in servers:
        if s['family']:
            for fam in _listify(s['mssp'].get('FAMILY', '')):
                if fam:
                    family_counts[fam] += 1
    stats['family_counts'] = dict(family_counts)

    codebase_counts = Counter()
    for s in servers:
        if s['codebase']:
            for cb in _listify(s['mssp'].get('CODEBASE', '')):
                if cb:
                    codebase_counts[cb] += 1
    stats['codebase_counts'] = dict(codebase_counts)

    year_counts = Counter()
    for s in servers:
        year = s['created']
        if year:
            try:
                year_counts[int(year)] += 1
            except ValueError:
                pass
    stats['year_counts'] = dict(year_counts)

    option_offered = Counter()
    option_requested = Counter()
    option_refused = Counter()
    for s in servers:
        for opt in s['offered']:
            option_offered[opt] += 1
        for opt in s['requested']:
            option_requested[opt] += 1
        for opt in s['refused']:
            option_refused[opt] += 1
    stats['option_offered'] = dict(option_offered)
    stats['option_requested'] = dict(option_requested)
    stats['option_refused'] = dict(option_refused)

    return stats


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------

def create_protocol_support_plot(stats, output_path):
    """Create horizontal bar chart of MUD protocol support counts."""
    proto_counts = stats['protocol_counts']
    if not proto_counts:
        return

    protocols = sorted(proto_counts.keys(),
                       key=lambda p: proto_counts[p])
    counts = [proto_counts[p] for p in protocols]
    total = stats['total_servers']

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(protocols, counts, color=PLOT_GREEN,
                   edgecolor=PLOT_CYAN, linewidth=0.5, alpha=0.85)

    for bar, count in zip(bars, counts):
        pct = count / total * 100 if total else 0
        ax.text(bar.get_width() + 0.5,
                bar.get_y() + bar.get_height() / 2,
                f' {count} ({pct:.0f}%)',
                va='center', color=PLOT_FG, fontsize=10)

    ax.set_xlabel('Number of Servers', fontsize=12)
    ax.set_xlim(0, max(counts) * 1.3 if counts else 10)
    ax.grid(True, axis='x')

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_codebase_families_plot(stats, output_path):
    """Create pie chart of codebase families."""
    family_counts = stats['family_counts']
    if not family_counts:
        return

    sorted_items = sorted(family_counts.items(),
                          key=lambda x: x[1], reverse=True)
    labels = [f for f, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(labels, counts)
    colors = _pie_colors(len(labels), labels)

    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(
        counts, labels=None, autopct='%1.0f%%', startangle=140,
        colors=colors, pctdistance=0.82,
        wedgeprops={'edgecolor': '#222222', 'linewidth': 1.5})
    for t in autotexts:
        t.set_color('#222222')
        t.set_fontsize(9)
        t.set_fontweight('bold')

    ax.legend(
        wedges,
        [f'{l} ({c})' for l, c in zip(labels, counts)],
        loc='center left', bbox_to_anchor=(1, 0.5),
        fontsize=9, facecolor='none', edgecolor=PLOT_FG,
        labelcolor=PLOT_FG)

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_codebases_plot(stats, output_path, top_n=15):
    """Create pie chart of top N specific codebases."""
    codebase_counts = stats['codebase_counts']
    if not codebase_counts:
        return

    top = sorted(codebase_counts.items(),
                 key=lambda x: x[1], reverse=True)[:top_n]
    labels = [cb for cb, _ in top]
    counts = [c for _, c in top]
    labels, counts = _group_small_slices(
        labels, counts, min_count=2)
    colors = _pie_colors(len(labels), labels)

    fig, ax = plt.subplots(figsize=(10, 8))
    wedges, texts, autotexts = ax.pie(
        counts, labels=None, autopct='%1.0f%%', startangle=140,
        colors=colors, pctdistance=0.82,
        wedgeprops={'edgecolor': '#222222', 'linewidth': 1.5})
    for t in autotexts:
        t.set_color('#222222')
        t.set_fontsize(9)
        t.set_fontweight('bold')

    ax.legend(
        wedges,
        [f'{l} ({c})' for l, c in zip(labels, counts)],
        loc='center left', bbox_to_anchor=(1, 0.5),
        fontsize=9, facecolor='none', edgecolor=PLOT_FG,
        labelcolor=PLOT_FG)

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_creation_years_plot(stats, output_path):
    """Create vertical bar chart of MUD creation years."""
    year_counts = stats['year_counts']
    if not year_counts:
        return

    min_year = min(year_counts.keys())
    max_year = max(year_counts.keys())
    all_years = range(min_year, max_year + 1)
    counts = [year_counts.get(y, 0) for y in all_years]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar([str(y) for y in all_years], counts,
           color=PLOT_GREEN, edgecolor=PLOT_CYAN,
           linewidth=0.5, alpha=0.85)

    ax.set_xlabel('Year Created', fontsize=12)
    ax.set_ylabel('Number of MUDs', fontsize=12)
    ax.grid(True, axis='y')
    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_all_plots(stats):
    """Generate all matplotlib plots."""
    os.makedirs(PLOTS_PATH, exist_ok=True)
    _setup_plot_style()

    create_protocol_support_plot(
        stats, os.path.join(PLOTS_PATH, 'protocol_support.png'))
    create_codebase_families_plot(
        stats, os.path.join(PLOTS_PATH, 'codebase_families.png'))
    create_codebases_plot(
        stats, os.path.join(PLOTS_PATH, 'codebases.png'))
    create_creation_years_plot(
        stats, os.path.join(PLOTS_PATH, 'creation_years.png'))
    create_telnet_options_plot(
        stats, os.path.join(PLOTS_PATH, 'telnet_options.png'))


# ---------------------------------------------------------------------------
# Filename assignment
# ---------------------------------------------------------------------------

def _mud_filename(server):
    """Generate a filesystem-safe filename for a MUD detail page."""
    host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', server['host'])
    return f"{host_safe}_{server['port']}"


def _assign_mud_filenames(servers, ip_groups):
    """Assign ``_mud_file`` and ``_mud_toc_label`` to each server.

    :param servers: list of server records (modified in place)
    :param ip_groups: dict from :func:`_group_shared_ip`
    """
    grouped_keys = {}
    for ip, members in ip_groups.items():
        ip_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', ip)
        filename = f"ip_{ip_safe}"
        hostname_hint = _most_common_hostname(members)
        if hostname_hint == ip:
            toc_label = ip
        else:
            toc_label = f"{ip} ({hostname_hint})"
        for s in members:
            grouped_keys[(s['host'], s['port'])] = (
                filename, toc_label)

    for s in servers:
        key = (s['host'], s['port'])
        if key in grouped_keys:
            s['_mud_file'], s['_mud_toc_label'] = grouped_keys[key]
        else:
            s['_mud_file'] = _mud_filename(s)
            s['_mud_toc_label'] = _strip_ansi(
                s['name'] or s['host'])


# ---------------------------------------------------------------------------
# RST display functions
# ---------------------------------------------------------------------------

def display_summary_stats(stats):
    """Print summary statistics section."""
    print("Statistics")
    print("==========")
    print()
    scan_date = datetime.now().strftime('%Y-%m-%d')
    print(f"*Data collected {scan_date}*")
    print()
    print(f"- **Servers responding**: {stats['total_servers']}")
    print(f"- **With MSSP data**: {stats['with_mssp']}")
    print(f"- **Unique protocol fingerprints**:"
          f" {stats['unique_fingerprints']}")
    print(f"- **Unique codebases**: {stats['unique_codebases']}")
    print(f"- **Unique codebase families**:"
          f" {stats['unique_families']}")
    footnotes = []
    if stats['total_players']:
        print(f"- **Total players online**:"
              f" {stats['total_players']} [#scan]_")
        scan_time = _format_scan_time(stats['scan_time_last'])
        if scan_time:
            footnotes.append(f".. [#scan] measured {scan_time}")
    print()
    print("These statistics reflect the most recent scan of all"
          " servers in the")
    print("`mudlist.txt "
          "<https://github.com/jquast/muds.modem.xyz/blob/master/"
          "data/mudlist.txt>`_ input list.")
    print("Each server is probed using `telnetlib3 "
          "<https://github.com/jquast/telnetlib3>`_,")
    print("which connects to each address, performs Telnet option"
          " negotiation,")
    print("and collects any MSSP metadata the server provides.")
    print()
    return footnotes


def display_plots():
    """Print figure directives for all plots."""
    print("The charts below summarize data from servers that report")
    print("MSSP metadata. Servers without MSSP appear in the")
    print(":doc:`server_list` but are not included in these"
          " breakdowns.")
    print()

    print("Codebase Families")
    print("------------------")
    print()
    print(".. figure:: _static/plots/codebase_families.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of MUD"
          " codebase families such as DikuMUD, LPMud, or TinyMUD,"
          " with the proportion of servers using each.")
    print()
    print("   Distribution of MUD codebase families"
          " (from MSSP data).")
    print()

    print("Top Codebases")
    print("--------------")
    print()
    print(".. figure:: _static/plots/codebases.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the most common specific"
          " codebase versions across all servers reporting"
          " MSSP data.")
    print()
    print("   Most common specific codebase versions.")
    print()

    print("Creation Years")
    print("---------------")
    print()
    print(".. figure:: _static/plots/creation_years.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Bar chart showing when MUDs were created,"
          " by year,"
          " spanning from the earliest to the most recent.")
    print()
    print("   When MUDs were created, by year, as reported"
          " via MSSP data.")
    print()

    print("Protocol Support")
    print("-----------------")
    print()
    print(".. figure:: _static/plots/protocol_support.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Horizontal bar chart showing how many servers"
          " support"
          " each MUD protocol such as MSSP, GMCP, MSDP, and MCCP.")
    print()
    print("   MUD protocol support across all responding servers.")
    print()

    print("Telnet Option Negotiation")
    print("--------------------------")
    print()
    print(".. figure:: _static/plots/telnet_options.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Grouped bar chart comparing how many servers"
          " offer"
          " versus request each Telnet option during negotiation.")
    print()
    print("   Telnet options offered vs requested by servers"
          " during negotiation.")
    print()


def display_server_table(servers):
    """Print the main server listing table with telnet:// links."""
    print("MUD Servers")
    print("===========")
    print()
    print("All servers that responded to a Telnet connection"
          " during the most")
    print("recent scan. Click a column header to sort. Use the"
          " search box to")
    print("filter by name, codebase family, or genre.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Players**")
    print("     - Number of players online at scan time, reported"
          " via"
          " MSSP. Blank if the server does not report MSSP.")
    print("   * - **Name**")
    print("     - Server name (from MSSP) or hostname. Links to"
          " a detail page.")
    print("   * - **Code/Family**")
    print("     - Codebase and codebase family -- the server"
          " software and its lineage (e.g. PennMUSH/TinyMUD,"
          " FluffOS/LPMud).")
    print("   * - **Genre**")
    print("     - Game genre or theme (e.g. Fantasy, Sci-Fi,"
          " Social)."
          " Servers detected as adult content (MSSP"
          " ``ADULT MATERIAL``"
          " or ``MINIMUM AGE`` >= 18) are tagged with"
          " ``/Adult``.")
    print("   * - **Created**")
    print("     - Year the MUD was originally created, from"
          " MSSP data.")
    print()

    rows = []
    for s in servers:
        name = s['name'] or s['host']
        mud_file = s['_mud_file']
        name_cell = (f":doc:`{_rst_escape(name)}"
                     f" <mud_detail/{mud_file}>`")
        host = s['host']
        sport = s['port']
        if s.get('_loci_supported'):
            loci = _lociterm_url(host, sport, s['tls_port'],
                                 s.get('_loci_ssl'))
            name_cell += f' `\U0001f5a5 <{loci}>`__'
        if s['website']:
            href = s['website']
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            name_cell += f' `\U0001f310 <{href}>`__'
        if s['tls_port']:
            name_cell += ' :tls-lock:`\U0001f512`'
        if s['pay_to_play']:
            name_cell += ' :pay-icon:`$`'

        codebase = s['codebase'] or ''
        family = s['family'] or ''
        if (codebase and family
                and codebase.lower() != family.lower()):
            code_family = f"{codebase}/{family}"
        else:
            code_family = codebase or family

        genre = s['genre'] or ''
        if s['adult'] and 'adult' not in genre.lower():
            genre = f"{genre}/Adult" if genre else 'Adult'

        players = (str(s['players'])
                   if s['players'] is not None else '')
        created = s['created'] or ''

        rows.append({
            'Players': players,
            'Name': name_cell,
            'Code/Family': _rst_escape(code_family[:30]),
            'Genre': _rst_escape(genre[:25]),
            'Created': created,
        })

    table_str = tabulate_mod.tabulate(
        rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="MUD Servers")


def display_fingerprint_summary(servers):
    """Print summary table of protocol fingerprints."""
    print("MUDs by Fingerprint")
    print("===================")
    print()
    print("A fingerprint is a hash of a server's Telnet option"
          " negotiation")
    print("behavior -- which options it offers to the client,"
          " which it requests")
    print("from the client, and which it refuses. Servers running"
          " the same software")
    print("version typically produce identical fingerprints."
          " A majority of servers")
    print("perform no negotiation at all and share the same"
          " empty fingerprint.")
    print()
    print("Click a fingerprint link to see the full negotiation"
          " details and all")
    print("servers in that group.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Fingerprint**")
    print("     - Truncated hash identifying the negotiation"
          " pattern."
          " Click to see the full detail page.")
    print("   * - **Servers**")
    print("     - Number of servers sharing this exact"
          " negotiation behavior.")
    print("   * - **Offers**")
    print("     - Telnet options the server offers"
          " (WILL) to the client during negotiation.")
    print("   * - **Requests**")
    print("     - Telnet options the server requests (DO)"
          " from the client.")
    print("   * - **Examples**")
    print("     - Sample server names sharing this fingerprint.")
    print()

    by_fp = {}
    for s in servers:
        fp = s['fingerprint']
        by_fp.setdefault(fp, []).append(s)

    rows = []
    for fp, fp_servers in sorted(by_fp.items(),
                                  key=lambda x: len(x[1]),
                                  reverse=True):
        offered = ', '.join(fp_servers[0]['offered']) or 'none'
        requested = (', '.join(fp_servers[0]['requested'])
                     or 'none')
        server_names = ', '.join(
            s['name'] or s['host'] for s in fp_servers[:3])
        if len(fp_servers) > 3:
            server_names += f', ... (+{len(fp_servers) - 3})'

        rows.append({
            'Fingerprint': f':ref:`{fp[:16]}... <fp_{fp}>`',
            'Servers': str(len(fp_servers)),
            'Offers': _rst_escape(offered[:30]),
            'Requests': _rst_escape(requested[:30]),
            'Examples': _rst_escape(server_names[:50]),
        })

    table_str = tabulate_mod.tabulate(
        rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="Protocol Fingerprints")

    print()
    print(".. toctree::")
    print("   :maxdepth: 1")
    print("   :hidden:")
    print()
    for fp in sorted(by_fp.keys()):
        print(f"   server_detail/{fp}")
    print()


def display_encoding_groups(servers):
    """Print MUDs by Encoding page."""
    _rst_heading("MUDs by Encoding", '=')
    print("Servers grouped by their detected or configured"
          " character encoding.")
    print()

    by_encoding = {}
    for s in servers:
        key = s['display_encoding']
        by_encoding.setdefault(key, []).append(s)

    for name, members in sorted(by_encoding.items(),
                                 key=lambda x: (-len(x[1]),
                                                x[0])):
        print(f"- `{_rst_escape(name)}`_: {len(members)}")
    print()

    for name, members in sorted(by_encoding.items(),
                                 key=lambda x: (-len(x[1]),
                                                x[0])):
        _rst_heading(name, '-')
        for s in sorted(members,
                        key=lambda s: (s['name']
                                       or s['host']).lower()):
            mud_file = s['_mud_file']
            label = s['name'] or f"{s['host']}:{s['port']}"
            tls = (' :tls-lock:`\U0001f512`'
                   if s.get('tls_port') else '')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <mud_detail/{mud_file}>`{tls}")
        print()


# ---------------------------------------------------------------------------
# RST generation
# ---------------------------------------------------------------------------

def generate_summary_rst(stats):
    """Generate the statistics.rst file with stats and plots."""
    rst_path = os.path.join(DOCS_PATH, "statistics.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        footnotes = display_summary_stats(stats)
        display_plots()
        for fn in footnotes:
            print(fn)
            print()
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_server_list_rst(servers):
    """Generate the server_list.rst file."""
    rst_path = os.path.join(DOCS_PATH, "server_list.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_server_table(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_fingerprints_rst(servers):
    """Generate the fingerprints.rst file."""
    rst_path = os.path.join(DOCS_PATH, "fingerprints.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_fingerprint_summary(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_encoding_rst(servers):
    """Generate the encodings.rst file."""
    rst_path = os.path.join(DOCS_PATH, "encodings.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_encoding_groups(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def display_banner_gallery(servers):
    """Print the Banner Gallery page grouping servers by shared banner."""
    _rst_heading("Banner Gallery", '=')
    print("A gallery of ANSI connection banners collected from responding")
    print("MUD servers. Servers that display identical visible banner text")
    print("are grouped together. Each group shows the shared banner image")
    print("and a list of all servers in that group.")
    print()

    groups = _group_by_banner(servers)
    sorted_groups = sorted(
        groups.values(),
        key=lambda g: (-len(g['servers']),
                       (g['servers'][0].get('name')
                        or g['servers'][0]['host']).lower()))

    total = sum(len(g['servers']) for g in sorted_groups)
    print(f"{len(sorted_groups)} unique banners across {total} servers.")
    print()

    for group in sorted_groups:
        members = group['servers']
        count = len(members)
        rep = members[0]
        banner = group['banner']

        name = rep.get('name') or rep['host']
        mud_file = rep['_mud_file']
        port = rep['port']
        if count > 1:
            heading = f"{name} (+{count - 1} more)"
        else:
            heading = name
        _rst_heading(heading, '-')

        banner_fname = f"{mud_file}_{port}.png"
        banner_path = os.path.join(BANNERS_PATH, banner_fname)
        if os.path.isfile(banner_path):
            print(f".. image:: /_static/banners/{banner_fname}")
            print(f"   :alt: {_rst_escape(_banner_alt_text(banner))}")
            print(f"   :class: ansi-banner")
            print()
        else:
            banner_html = _banner_to_html(
                banner, name=name, wrap_width=100,
                brighten_blue=True,
                default_aria='MUD server')
            print(".. raw:: html")
            print()
            for line in banner_html.split('\n'):
                print(f"   {line}")
            print()

        for s in members:
            label = s.get('name') or f"{s['host']}:{s['port']}"
            tls = (' :tls-lock:`\U0001f512`'
                   if s.get('tls_port') else '')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <mud_detail/{s['_mud_file']}>`{tls}")
        print()


def generate_banner_gallery_rst(servers):
    """Generate the banner_gallery.rst file."""
    rst_path = os.path.join(DOCS_PATH, "banner_gallery.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_banner_gallery(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_details_rst(servers):
    """Generate the servers.rst index page with toctree."""
    rst_path = os.path.join(DOCS_PATH, "servers.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        print("Servers")
        print("=======")
        print()
        print("Individual detail pages for each MUD server"
              " scanned in this")
        print("census. Each page shows the server's ANSI login"
              " banner,")
        print("MSSP metadata (if available), protocol support,")
        print("fingerprint data, the raw JSON scan record,"
              " and the")
        print("full Telnet negotiation log.")
        print()
        mudlist_url = ("https://github.com/jquast/muds.modem.xyz"
                       "/blob/master/data/mudlist.txt")
        print(f"Missing a MUD? `Submit a pull request "
              f"<{mudlist_url}>`_ to add it.")
        print()
        print(".. toctree::")
        print("   :maxdepth: 1")
        print()
        seen_files = set()
        for s in servers:
            mud_file = s['_mud_file']
            if mud_file in seen_files:
                continue
            seen_files.add(mud_file)
            label = s.get('_mud_toc_label',
                          s['name'] or s['host'])
            print(f"   {label} <mud_detail/{mud_file}>")
        print()
    print(f"  wrote {rst_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Detail pages
# ---------------------------------------------------------------------------

def generate_mud_detail(server, logs_dir=None, data_dir=None,
                        fp_counts=None):
    """Generate a detail page for one MUD server.

    :param server: server record dict
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    mud_file = server['_mud_file']
    detail_path = os.path.join(MUD_DETAIL_PATH, f"{mud_file}.rst")
    name = _strip_ansi(server['name'] or server['host'])
    footnotes = []

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(name)
        _rst_heading(escaped_name, '=')

        host = server['host']
        port = server['port']
        url = _telnet_url(host, port)

        print("Server URLs")
        print("-----------")
        print()
        print(f".. raw:: html")
        print()
        print(f'   <ul class="mud-connect">')
        print(f'   <li><strong>Telnet</strong>: '
              f'<a href="{url}" class="telnet-link">'
              f'{url}</a>')
        print(f'   <button class="copy-btn"'
              f' data-host="{host}"'
              f' data-port="{port}"'
              f' title="Copy host and port"'
              f' aria-label="Copy {host} port {port}'
              f' to clipboard">')
        print(f'   <span class="copy-icon"'
              f' aria-hidden="true">'
              f'&#x1F4CB;</span>')
        print(f'   </button></li>')
        if server.get('_loci_supported'):
            loci_url = _lociterm_url(
                host, port, server['tls_port'],
                server.get('_loci_ssl'))
            print(f'   <li><strong>Play in Browser'
                  f'</strong>: <a href="{loci_url}">'
                  f'LociTerm</a></li>')
        if server['website']:
            href = server['website']
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            print(f'   <li><strong>Website</strong>: '
                  f'<a href="{href}">'
                  f'{_rst_escape(server["website"])}'
                  f'</a></li>')
        if server['tls_port']:
            tls_port = server['tls_port']
            if tls_port == '1' or tls_port == str(port):
                tls_url = f"telnets://{host}:{port}"
            else:
                tls_url = f"telnets://{host}:{tls_port}"
            print(f'   <li><strong>TLS/SSL</strong>: '
                  f'<a href="{tls_url}">{tls_url}</a>'
                  f'</li>')
        print(f'   </ul>')
        print()

        if server['has_mssp'] and server['description']:
            print(f"*{_rst_escape(server['description'][:300])}*")
            print()

        banner = _combine_banners(server)
        effective_enc = server['display_encoding']
        if banner and not _is_garbled(banner):
            banner_fname = f"{mud_file}_{port}.png"
            banner_path = os.path.join(BANNERS_PATH, banner_fname)
            if _banner_to_png(banner, banner_path, effective_enc):
                print("**Connection Banner:**")
                print()
                print(f".. image:: "
                      f"/_static/banners/{banner_fname}")
                print(f"   :alt: {_rst_escape(_banner_alt_text(banner))}")
                print(f"   :class: ansi-banner")
                print()
            else:
                print("**Connection Banner:**")
                print()
                banner_html = _banner_to_html(
                    banner, name=name, wrap_width=100,
                    brighten_blue=True,
                    default_aria='MUD server')
                print(".. raw:: html")
                print()
                for line in banner_html.split('\n'):
                    print(f"   {line}")
                print()
        elif banner:
            print("*Banner not shown -- this server likely"
                  " uses a legacy encoding such as CP437.*")
            print()

        is_legacy_encoding = effective_enc not in (
            'ascii', 'utf-8', 'unknown')
        banner_garbled = banner and _is_garbled(banner)

        has_info = (server['has_mssp'] or is_legacy_encoding
                    or banner_garbled)
        if has_info:
            print("Server Info")
            print("-----------")
            print()
            if server['codebase']:
                print(f"- **Codebase**:"
                      f" {_rst_escape(server['codebase'])}")
            if server['family']:
                print(f"- **Family**:"
                      f" {_rst_escape(server['family'])}")
            if server['genre']:
                print(f"- **Genre**:"
                      f" {_rst_escape(server['genre'])}")
            if server['gameplay']:
                print(f"- **Gameplay**:"
                      f" {_rst_escape(server['gameplay'])}")
            if server['players'] is not None:
                scan_time = _format_scan_time(server['connected'])
                if scan_time:
                    print(f"- **Players online**:"
                          f" {server['players']} [#scan]_")
                    footnotes.append(
                        f".. [#scan] measured {scan_time}")
                else:
                    print(f"- **Players online**:"
                          f" {server['players']}")
            if server['uptime_days'] is not None:
                print(f"- **Uptime**:"
                      f" {server['uptime_days']} days")
            if server['created']:
                print(f"- **Created**: {server['created']}")
            if server['status']:
                print(f"- **Status**:"
                      f" {_rst_escape(server['status'])}")
            if server['discord']:
                discord_url = server['discord']
                if not discord_url.startswith(
                        ('http://', 'https://')):
                    discord_url = f'https://{discord_url}'
                print(f"- **Discord**:"
                      f" `{_rst_escape(server['discord'])}"
                      f" <{discord_url}>`_")
            if server['location']:
                print(f"- **Location**:"
                      f" {_rst_escape(server['location'])}")
            if server['language']:
                print(f"- **Language**:"
                      f" {_rst_escape(server['language'])}")
            if is_legacy_encoding or banner_garbled:
                enc_label = (effective_enc
                             if is_legacy_encoding else 'cp437')
                print(f"- **Encoding**: {enc_label}")
                print()
                print(f"  This server uses a legacy encoding:")
                print()
                print(f"  ``telnetlib3-client --encoding"
                      f" {enc_label} --force-binary"
                      f" {host} {port}``")
                print()
            if server['pay_to_play']:
                pay_play = _first_str(
                    server['mssp'].get('PAY TO PLAY', ''))
                pay_perks = _first_str(
                    server['mssp'].get('PAY FOR PERKS', ''))
                if (pay_play
                        and pay_play not in
                        ('0', 'no', 'No', 'NO', '')):
                    print("- **Pay to Play**: :pay-icon:`$` Yes")
                if (pay_perks
                        and pay_perks not in
                        ('0', 'no', 'No', 'NO', '')):
                    print("- **Pay for Perks**: :pay-icon:`$` Yes")
            print()

        proto_flags = [
            p for p in MUD_PROTOCOLS
            if server['protocols'].get(p, 'no') != 'no'
        ]
        if proto_flags:
            print("Protocol Support")
            print("----------------")
            print()
            print("MUD-specific protocols detected via MSSP"
                  " flags or")
            print("Telnet negotiation.")
            print()
            for proto in MUD_PROTOCOLS:
                status = server['protocols'].get(proto, 'no')
                if status == 'mssp':
                    print(f"- **{proto}**:"
                          f" :proto-yes:`Yes` (MSSP)")
                elif status == 'negotiated':
                    print(f"- **{proto}**:"
                          f" :proto-negotiated:`Negotiated`")
                else:
                    print(f"- **{proto}**: :proto-no:`No`")
            print()

        fp = server['fingerprint']
        print("Telnet Fingerprint")
        print("------------------")
        print()
        print(f":ref:`{fp[:16]}... <fp_{fp}>`")
        print()
        if fp_counts:
            other_count = fp_counts.get(fp, 1) - 1
            if other_count > 0:
                print(f"*This fingerprint is shared by"
                      f" {other_count} other "
                      f"{'server' if other_count == 1 else 'servers'}.*")
            else:
                print("*This fingerprint is unique to"
                      " this server.*")
            print()
        if server['offered']:
            print("**Options offered by server**: "
                  + ', '.join(f"``{o}``"
                              for o in sorted(server['offered'])))
            print()
        if server['requested']:
            print("**Options requested from client**: "
                  + ', '.join(
                      f"``{o}``"
                      for o in sorted(server['requested'])))
            print()

        data_path = server.get('data_path', '')
        if data_path and data_dir:
            json_file = os.path.join(
                data_dir, "server", data_path)
            github_url = f"{GITHUB_DATA_BASE}/{data_path}"
            print(f"**Data source**: `{data_path}"
                  f" <{github_url}>`_")
            print()
            print("The complete JSON record collected during"
                  " the scan,")
            print("including Telnet negotiation results and any")
            print("MSSP metadata.")
            print()
            if os.path.isfile(json_file):
                with open(json_file) as jf:
                    raw_json = jf.read().rstrip()
                if raw_json:
                    print(".. code-block:: json")
                    print()
                    for line in raw_json.split('\n'):
                        print(f"   {line}")
                    print()

        if logs_dir:
            log_path = os.path.join(
                logs_dir,
                f"{server['host']}:{server['port']}.log")
            if os.path.isfile(log_path):
                with open(log_path) as lf:
                    log_text = lf.read().rstrip()
                if log_text:
                    print("Connection Log")
                    print("--------------")
                    print()
                    print("Debug-level log of the Telnet"
                          " negotiation session,")
                    print("showing each IAC (Interpret As"
                          " Command) exchange")
                    print("between client and server.")
                    print()
                    print(".. code-block:: text")
                    print()
                    for line in log_text.split('\n'):
                        for wrapped in _clean_log_line(line):
                            print(f"   {wrapped}")
                    print()
                    print(f"*Generated by* "
                          f"`telnetlib3-fingerprint "
                          f"<https://github.com/jquast/"
                          f"telnetlib3>`_")
                    print()
                    print(".. code-block:: shell")
                    print()
                    print(f"   telnetlib3-fingerprint "
                          f"--loglevel=debug {host} {port}")
                    print()

        for fn in footnotes:
            print(fn)
            print()


def _write_mud_port_section(server, sec_char, logs_dir=None,
                            data_dir=None, fp_counts=None,
                            fn_suffix=''):
    """Write detail content sections for one server port.

    :param server: server record dict
    :param sec_char: RST underline character for section headings
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    :param fn_suffix: suffix for footnote labels to avoid clashes
    :returns: list of footnote strings to print at page end
    """
    footnotes = []
    name = _strip_ansi(server['name'] or server['host'])
    host = server['host']
    port = server['port']

    url = _telnet_url(host, port)
    _rst_heading("Server URLs", sec_char)
    print(f".. raw:: html")
    print()
    print(f'   <ul class="mud-connect">')
    print(f'   <li><strong>Telnet</strong>: '
          f'<a href="{url}" class="telnet-link">'
          f'{url}</a>')
    print(f'   <button class="copy-btn"'
          f' data-host="{host}"'
          f' data-port="{port}"'
          f' title="Copy host and port"'
          f' aria-label="Copy {host} port {port}'
          f' to clipboard">')
    print(f'   <span class="copy-icon"'
          f' aria-hidden="true">'
          f'&#x1F4CB;</span>')
    print(f'   </button></li>')
    if server.get('_loci_supported'):
        loci_url = _lociterm_url(
            host, port, server['tls_port'],
            server.get('_loci_ssl'))
        print(f'   <li><strong>Play in Browser'
              f'</strong>: <a href="{loci_url}">'
              f'LociTerm</a></li>')
    if server['website']:
        href = server['website']
        if not href.startswith(('http://', 'https://')):
            href = f'http://{href}'
        print(f'   <li><strong>Website</strong>: '
              f'<a href="{href}">'
              f'{_rst_escape(server["website"])}'
              f'</a></li>')
    if server['tls_port']:
        tls_port = server['tls_port']
        if tls_port == '1' or tls_port == str(port):
            tls_url = f"telnets://{host}:{port}"
        else:
            tls_url = f"telnets://{host}:{tls_port}"
        print(f'   <li><strong>TLS/SSL</strong>: '
              f'<a href="{tls_url}">{tls_url}</a>'
              f'</li>')
    print(f'   </ul>')
    print()

    if server['has_mssp'] and server['description']:
        print(f"*{_rst_escape(server['description'][:300])}*")
        print()

    banner = _combine_banners(server)
    effective_enc = server['display_encoding']
    if banner and not _is_garbled(banner):
        mud_file = server['_mud_file']
        banner_fname = f"{mud_file}_{port}.png"
        banner_path = os.path.join(BANNERS_PATH, banner_fname)
        if _banner_to_png(banner, banner_path, effective_enc):
            print("**Connection Banner:**")
            print()
            print(f".. image:: "
                  f"/_static/banners/{banner_fname}")
            print(f"   :alt: {_rst_escape(_banner_alt_text(banner))}")
            print(f"   :class: ansi-banner")
            print()
        else:
            print("**Connection Banner:**")
            print()
            banner_html = _banner_to_html(
                banner, name=name, wrap_width=100,
                brighten_blue=True,
                default_aria='MUD server')
            print(".. raw:: html")
            print()
            for line in banner_html.split('\n'):
                print(f"   {line}")
            print()
    elif banner:
        print("*Banner not shown -- this server likely"
              " uses a legacy encoding such as CP437.*")
        print()

    is_legacy_encoding = effective_enc not in (
        'ascii', 'utf-8', 'unknown')
    banner_garbled = banner and _is_garbled(banner)

    has_info = (server['has_mssp'] or is_legacy_encoding
                or banner_garbled)
    if has_info:
        _rst_heading("Server Info", sec_char)
        if server['codebase']:
            print(f"- **Codebase**:"
                  f" {_rst_escape(server['codebase'])}")
        if server['family']:
            print(f"- **Family**:"
                  f" {_rst_escape(server['family'])}")
        if server['genre']:
            print(f"- **Genre**:"
                  f" {_rst_escape(server['genre'])}")
        if server['gameplay']:
            print(f"- **Gameplay**:"
                  f" {_rst_escape(server['gameplay'])}")
        if server['players'] is not None:
            scan_time = _format_scan_time(server['connected'])
            fn_label = f"scan{fn_suffix}"
            if scan_time:
                print(f"- **Players online**:"
                      f" {server['players']}"
                      f" [#{fn_label}]_")
                footnotes.append(
                    f".. [#{fn_label}] measured {scan_time}")
            else:
                print(f"- **Players online**:"
                      f" {server['players']}")
        if server['uptime_days'] is not None:
            print(f"- **Uptime**:"
                  f" {server['uptime_days']} days")
        if server['created']:
            print(f"- **Created**: {server['created']}")
        if server['status']:
            print(f"- **Status**:"
                  f" {_rst_escape(server['status'])}")
        if server['discord']:
            discord_url = server['discord']
            if not discord_url.startswith(
                    ('http://', 'https://')):
                discord_url = f'https://{discord_url}'
            print(f"- **Discord**:"
                  f" `{_rst_escape(server['discord'])}"
                  f" <{discord_url}>`_")
        if server['location']:
            print(f"- **Location**:"
                  f" {_rst_escape(server['location'])}")
        if server['language']:
            print(f"- **Language**:"
                  f" {_rst_escape(server['language'])}")
        if is_legacy_encoding or banner_garbled:
            enc_label = (effective_enc
                         if is_legacy_encoding else 'cp437')
            print(f"- **Encoding**: {enc_label}")
            print()
            print(f"  This server uses a legacy encoding:")
            print()
            print(f"  ``telnetlib3-client --encoding"
                  f" {enc_label} --force-binary"
                  f" {host} {port}``")
            print()
        if server['pay_to_play']:
            pay_play = _first_str(
                server['mssp'].get('PAY TO PLAY', ''))
            pay_perks = _first_str(
                server['mssp'].get('PAY FOR PERKS', ''))
            if (pay_play
                    and pay_play not in
                    ('0', 'no', 'No', 'NO', '')):
                print("- **Pay to Play**: :pay-icon:`$` Yes")
            if (pay_perks
                    and pay_perks not in
                    ('0', 'no', 'No', 'NO', '')):
                print("- **Pay for Perks**: :pay-icon:`$` Yes")
        print()

    proto_flags = [
        p for p in MUD_PROTOCOLS
        if server['protocols'].get(p, 'no') != 'no'
    ]
    if proto_flags:
        _rst_heading("Protocol Support", sec_char)
        print("MUD-specific protocols detected via MSSP flags or")
        print("Telnet negotiation.")
        print()
        for proto in MUD_PROTOCOLS:
            status = server['protocols'].get(proto, 'no')
            if status == 'mssp':
                print(f"- **{proto}**:"
                      f" :proto-yes:`Yes` (MSSP)")
            elif status == 'negotiated':
                print(f"- **{proto}**:"
                      f" :proto-negotiated:`Negotiated`")
            else:
                print(f"- **{proto}**: :proto-no:`No`")
        print()

    fp = server['fingerprint']
    _rst_heading("Telnet Fingerprint", sec_char)
    print(f":ref:`{fp[:16]}... <fp_{fp}>`")
    print()
    if fp_counts:
        other_count = fp_counts.get(fp, 1) - 1
        if other_count > 0:
            print(f"*This fingerprint is shared by"
                  f" {other_count} other "
                  f"{'server' if other_count == 1 else 'servers'}.*")
        else:
            print("*This fingerprint is unique to this server.*")
        print()
    if server['offered']:
        print("**Options offered by server**: "
              + ', '.join(f"``{o}``"
                          for o in sorted(server['offered'])))
        print()
    if server['requested']:
        print("**Options requested from client**: "
              + ', '.join(f"``{o}``"
                          for o in sorted(server['requested'])))
        print()

    data_path = server.get('data_path', '')
    if data_path and data_dir:
        json_file = os.path.join(data_dir, "server", data_path)
        github_url = f"{GITHUB_DATA_BASE}/{data_path}"
        print(f"**Data source**: `{data_path} <{github_url}>`_")
        print()
        print("The complete JSON record collected during the scan,")
        print("including Telnet negotiation results and any")
        print("MSSP metadata.")
        print()
        if os.path.isfile(json_file):
            with open(json_file) as jf:
                raw_json = jf.read().rstrip()
            if raw_json:
                print(".. code-block:: json")
                print()
                for line in raw_json.split('\n'):
                    print(f"   {line}")
                print()

    if logs_dir:
        log_path = os.path.join(logs_dir, f"{host}:{port}.log")
        if os.path.isfile(log_path):
            with open(log_path) as lf:
                log_text = lf.read().rstrip()
            if log_text:
                _rst_heading("Connection Log", sec_char)
                print("Debug-level log of the Telnet negotiation"
                      " session,")
                print("showing each IAC (Interpret As Command)"
                      " exchange")
                print("between client and server.")
                print()
                print(".. code-block:: text")
                print()
                for line in log_text.split('\n'):
                    for wrapped in _clean_log_line(line):
                        print(f"   {wrapped}")
                print()
                print(f"*Generated by* "
                      f"`telnetlib3-fingerprint "
                      f"<https://github.com/jquast/telnetlib3>`_")
                print()
                print(".. code-block:: shell")
                print()
                print(f"   telnetlib3-fingerprint "
                      f"--loglevel=debug {host} {port}")
                print()

    return footnotes


def generate_mud_detail_group(ip, group_servers, logs_dir=None,
                              data_dir=None, fp_counts=None):
    """Generate a combined detail page for servers sharing an IP.

    :param ip: shared IP address
    :param group_servers: list of server records sharing this IP
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    mud_file = group_servers[0]['_mud_file']
    detail_path = os.path.join(MUD_DETAIL_PATH, f"{mud_file}.rst")
    hostname_hint = _most_common_hostname(group_servers)
    if hostname_hint == ip:
        display_name = ip
    else:
        display_name = f"{ip} ({hostname_hint})"

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(display_name)
        _rst_heading(escaped_name, '=')

        all_footnotes = []
        for server in group_servers:
            name = _strip_ansi(server['name'])
            host = server['host']
            port = server['port']
            if name:
                sub_title = f"{name} ({host}:{port})"
            else:
                sub_title = f"{host}:{port}"
            escaped_sub = _rst_escape(sub_title)
            _rst_heading(escaped_sub, '-')

            footnotes = _write_mud_port_section(
                server, '~', logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts,
                fn_suffix=f'_{host}_{port}')
            all_footnotes.extend(footnotes)

        for fn in all_footnotes:
            print(fn)
            print()


def generate_mud_details(servers, logs_dir=None, data_dir=None,
                         ip_groups=None):
    """Generate all per-MUD detail pages.

    :param servers: list of server records
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param ip_groups: dict from :func:`_group_shared_ip`
    """
    _clean_dir(MUD_DETAIL_PATH)
    os.makedirs(MUD_DETAIL_PATH, exist_ok=True)

    fp_counts = Counter(s['fingerprint'] for s in servers)

    grouped_keys = set()
    if ip_groups:
        for members in ip_groups.values():
            for s in members:
                grouped_keys.add((s['host'], s['port']))

    rebuilt = 0
    for s in servers:
        if (s['host'], s['port']) in grouped_keys:
            continue
        result = generate_mud_detail(
            s, logs_dir=logs_dir, data_dir=data_dir,
            fp_counts=fp_counts)
        if result is not False:
            rebuilt += 1

    if ip_groups:
        for ip, members in sorted(ip_groups.items()):
            generate_mud_detail_group(
                ip, members, logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts)
            rebuilt += 1

    total = (len(servers) - len(grouped_keys)
             + len(ip_groups or {}))
    if rebuilt < total:
        print(f"  wrote {rebuilt}/{total} MUD detail pages"
              f" to {MUD_DETAIL_PATH}"
              f" ({total - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} MUD detail pages"
              f" to {MUD_DETAIL_PATH}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Fingerprint detail pages
# ---------------------------------------------------------------------------

def generate_fingerprint_detail(fp_hash, fp_servers):
    """Generate a detail page for one fingerprint group.

    :param fp_hash: fingerprint hash string
    :param fp_servers: list of server records sharing this fingerprint
    """
    detail_path = os.path.join(DETAIL_PATH, f"{fp_hash}.rst")
    sample = fp_servers[0]

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        print(f".. _fp_{fp_hash}:")
        print()
        title = f"{fp_hash[:16]}"
        _rst_heading(title, '=')

        print(f"**Full hash**: ``{fp_hash}``")
        print()
        print(f"**Servers sharing this fingerprint**:"
              f" {len(fp_servers)}")
        print()

        print("Telnet Options")
        print("--------------")
        print()

        if sample['offered']:
            print("**Offered by server**: "
                  + ', '.join(f"``{o}``"
                              for o in sorted(sample['offered'])))
        else:
            print("**Offered by server**: none")
        print()

        if sample['requested']:
            print("**Requested from client**: "
                  + ', '.join(
                      f"``{o}``"
                      for o in sorted(sample['requested'])))
        else:
            print("**Requested from client**: none")
        print()

        refused_display = [
            o for o in sorted(sample['refused'])
            if o in TELNET_OPTIONS_OF_INTEREST
        ]
        other_refused = (len(sample['refused'])
                         - len(refused_display))
        if refused_display:
            print("**Refused (notable)**: "
                  + ', '.join(
                      f"``{o}``" for o in refused_display))
            if other_refused > 0:
                print(f"  *(and {other_refused} other"
                      f" standard options)*")
        print()

        negotiated_offered = {
            k: v for k, v in sample['server_offered'].items()
            if v
        }
        negotiated_requested = {
            k: v for k, v in sample['server_requested'].items()
            if v
        }
        if negotiated_offered or negotiated_requested:
            print("Negotiation Results")
            print("~~~~~~~~~~~~~~~~~~~")
            print()
            if negotiated_offered:
                print("**Server offered (accepted)**: "
                      + ', '.join(
                          f"``{o}``"
                          for o in sorted(negotiated_offered)))
                print()
            if negotiated_requested:
                print("**Server requested (accepted)**: "
                      + ', '.join(
                          f"``{o}``"
                          for o in sorted(negotiated_requested)))
                print()

        print("Servers")
        print("-------")
        print()

        for s in fp_servers:
            name = s['name'] or s['host']
            mud_file = s['_mud_file']
            tls = (' :tls-lock:`\U0001f512`'
                   if s['tls_port'] else '')
            print(f":doc:`{_rst_escape(name)}"
                  f" <../mud_detail/{mud_file}>`{tls}")
            print()

            if s['has_mssp']:
                if s['codebase']:
                    print(f"  - Codebase:"
                          f" {_rst_escape(s['codebase'])}")
                if s['family']:
                    print(f"  - Family:"
                          f" {_rst_escape(s['family'])}")
                if s['genre']:
                    print(f"  - Genre:"
                          f" {_rst_escape(s['genre'])}")
                if s['players'] is not None:
                    print(f"  - Players: {s['players']}")
                if s['created']:
                    print(f"  - Created: {s['created']}")
                if s['status']:
                    print(f"  - Status:"
                          f" {_rst_escape(s['status'])}")
                if s['website']:
                    href = s['website']
                    if not href.startswith(
                            ('http://', 'https://')):
                        href = f'http://{href}'
                    print(f"  - Website:"
                          f" `{_rst_escape(s['website'])}"
                          f" <{href}>`_")
                if s['location']:
                    print(f"  - Location:"
                          f" {_rst_escape(s['location'])}")

                proto_flags = [
                    p for p in MUD_PROTOCOLS
                    if s['protocols'].get(p, 'no') != 'no'
                ]
                if proto_flags:
                    print(f"  - Protocols:"
                          f" {', '.join(proto_flags)}")
                print()

            banner = _combine_banners(s)
            if banner and not _is_garbled(banner):
                banner_html = _banner_to_html(
                    banner, maxlen=300, maxlines=10,
                    name=(s['name'] or s['host']),
                    wrap_width=100, brighten_blue=True,
                    default_aria='MUD server')
                print("  .. raw:: html")
                print()
                for line in banner_html.split('\n'):
                    print(f"     {line}")
                print()


def generate_fingerprint_details(servers):
    """Generate all fingerprint detail pages.

    :param servers: list of server records
    """
    _clean_dir(DETAIL_PATH)
    os.makedirs(DETAIL_PATH, exist_ok=True)

    by_fp = {}
    for s in servers:
        by_fp.setdefault(s['fingerprint'], []).append(s)

    rebuilt = 0
    for fp_hash, fp_servers in sorted(by_fp.items()):
        result = generate_fingerprint_detail(fp_hash, fp_servers)
        if result is not False:
            rebuilt += 1

    if rebuilt < len(by_fp):
        print(f"  wrote {rebuilt}/{len(by_fp)} fingerprint detail"
              f" pages to {DETAIL_PATH}"
              f" ({len(by_fp) - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} fingerprint detail pages"
              f" to {DETAIL_PATH}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(args):
    """Run the MUD statistics pipeline.

    :param args: parsed argparse namespace
    """
    data_dir = os.path.abspath(
        args.data_dir
        or os.path.join(_PROJECT_ROOT, 'data-muds'))
    logs_dir = os.path.abspath(
        args.logs_dir
        or os.path.join(_PROJECT_ROOT, 'logs'))
    server_list = (
        args.server_list
        or os.path.join(data_dir, 'mudlist.txt'))

    if os.path.isdir(logs_dir):
        print(f"Using logs from {logs_dir}", file=sys.stderr)
    else:
        logs_dir = None

    encoding_overrides = _load_encoding_overrides(server_list)
    if encoding_overrides:
        print(f"Loaded {len(encoding_overrides)} encoding"
              f" overrides from {server_list}", file=sys.stderr)

    print(f"Loading data from {data_dir} ...", file=sys.stderr)

    records = load_server_data(data_dir, encoding_overrides)
    print(f"  loaded {len(records)} session records",
          file=sys.stderr)

    servers = deduplicate_servers(
        records,
        sort_key=lambda r: (r['name'] or r['host']).lower())
    print(f"  {len(servers)} unique servers after deduplication",
          file=sys.stderr)

    listed = _parse_server_list(server_list)
    servers = [s for s in servers
               if (s['host'], s['port']) in listed]
    print(f"  {len(servers)} servers after filtering"
          f" by {server_list}", file=sys.stderr)

    telnetsupport = _load_telnetsupport(data_dir)
    _annotate_lociterm(servers, telnetsupport)

    ip_groups = _group_shared_ip(servers)
    _assign_mud_filenames(servers, ip_groups)
    if ip_groups:
        n_groups = len(ip_groups)
        n_combined = sum(len(m) for m in ip_groups.values())
        print(f"  {n_groups} IP groups"
              f" ({n_combined} servers combined)",
              file=sys.stderr)

    stats = compute_statistics(servers)

    print("Generating plots ...", file=sys.stderr)
    create_all_plots(stats)
    print(f"  wrote plots to {PLOTS_PATH}", file=sys.stderr)

    os.makedirs(BANNERS_PATH, exist_ok=True)

    print("Generating RST ...", file=sys.stderr)
    generate_summary_rst(stats)
    generate_server_list_rst(servers)
    generate_fingerprints_rst(servers)
    generate_encoding_rst(servers)
    generate_details_rst(servers)
    generate_mud_details(servers, logs_dir=logs_dir,
                         data_dir=data_dir,
                         ip_groups=ip_groups)
    generate_fingerprint_details(servers)
    generate_banner_gallery_rst(servers)

    old_results = os.path.join(DOCS_PATH, "results.rst")
    if os.path.exists(old_results):
        os.remove(old_results)
        print(f"  removed old {old_results}", file=sys.stderr)

    print("Done. Run sphinx-build to generate HTML.",
          file=sys.stderr)
