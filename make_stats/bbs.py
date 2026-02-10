"""BBS-specific statistics generation."""

import contextlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import tabulate as tabulate_mod

from make_stats.common import (
    _PROJECT_ROOT, _URL_RE,
    TELNET_OPTIONS_OF_INTEREST,
    PLOT_BG, PLOT_FG, PLOT_GREEN, PLOT_CYAN, PLOT_YELLOW, PLOT_BLUE,
    _listify, _first_str, _parse_int, _format_scan_time,
    _parse_server_list,
    _rst_escape, _strip_ansi, _is_garbled, _strip_mxp_sgml,
    _clean_log_line, _combine_banners, _truncate,
    _banner_to_html, _banner_to_png, _banner_alt_text, _telnet_url,
    _rst_heading, print_datatable,
    _group_shared_ip, _most_common_hostname,
    _clean_dir, _remove_stale_rst, _needs_rebuild,
    deduplicate_servers,
    _setup_plot_style, _group_small_slices, _pie_colors,
    create_telnet_options_plot,
)

DOCS_PATH = os.path.join(_PROJECT_ROOT, "docs-bbs")
PLOTS_PATH = os.path.join(DOCS_PATH, "_static", "plots")
DETAIL_PATH = os.path.join(DOCS_PATH, "server_detail")
BBS_DETAIL_PATH = os.path.join(DOCS_PATH, "bbs_detail")
BANNERS_PATH = os.path.join(DOCS_PATH, "_static", "banners")
GITHUB_DATA_BASE = ("https://github.com/jquast/modem.xyz"
                     "/tree/master/data-bbs/server")

# Default encoding assumed for all BBSes unless overridden
DEFAULT_ENCODING = 'cp437'

# Known BBS software patterns (case-insensitive match against banner text)
BBS_SOFTWARE_PATTERNS = [
    (re.compile(r'Synchronet', re.IGNORECASE), 'Synchronet'),
    (re.compile(r'Mystic\s*BBS', re.IGNORECASE), 'Mystic BBS'),
    (re.compile(r'WWIV', re.IGNORECASE), 'WWIV'),
    (re.compile(r'Renegade', re.IGNORECASE), 'Renegade'),
    (re.compile(r'ENiGMA.*BBS', re.IGNORECASE), 'ENiGMA'),
    (re.compile(r'Talisman', re.IGNORECASE), 'Talisman'),
    (re.compile(r'Wildcat!?', re.IGNORECASE), 'Wildcat!'),
    (re.compile(r'PCBoard', re.IGNORECASE), 'PCBoard'),
    (re.compile(r'Telegard', re.IGNORECASE), 'Telegard'),
    (re.compile(r'Maximus', re.IGNORECASE), 'Maximus'),
    (re.compile(r'Remote\s*Access', re.IGNORECASE),
     'RemoteAccess'),
    (re.compile(r'Oblivion/?2|Obv/?2', re.IGNORECASE),
     'Oblivion/2'),
    (re.compile(r'MBBS|Major\s*BBS', re.IGNORECASE), 'MajorBBS'),
    (re.compile(r'TBBS|TriBBS', re.IGNORECASE), 'TriBBS'),
    (re.compile(r'EleBBS', re.IGNORECASE), 'EleBBS'),
    (re.compile(r'Iniquity', re.IGNORECASE), 'Iniquity'),
    (re.compile(r'Citadel', re.IGNORECASE), 'Citadel'),
    (re.compile(r'TAG\s*BBS', re.IGNORECASE), 'TAG BBS'),
    (re.compile(r'Hermes\s*II?', re.IGNORECASE), 'Hermes'),
    (re.compile(r'SBBS', re.IGNORECASE), 'SBBS'),
]


# ---------------------------------------------------------------------------
# BBS helpers
# ---------------------------------------------------------------------------

def detect_bbs_software(banner_text):
    """Detect BBS software from banner text using pattern matching.

    :param banner_text: combined banner text (stripped of ANSI)
    :returns: software name string, or ''
    """
    if not banner_text:
        return ''
    clean = _strip_ansi(banner_text)
    for pattern, name in BBS_SOFTWARE_PATTERNS:
        if pattern.search(clean):
            return name
    return ''


def load_bbslist_encodings(bbslist_path):
    """Load encoding overrides from bbslist.txt.

    :param bbslist_path: path to bbslist.txt
    :returns: dict mapping (host, port) to encoding string
    """
    overrides = {}
    if not os.path.isfile(bbslist_path):
        return overrides
    with open(bbslist_path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides[(host, port)] = parts[2].strip()
    return overrides


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
            option_states = session_data.get('option_states', {})
            session = sessions[-1]
            host = session.get('host',
                               session.get('ip', 'unknown'))
            port = session.get('port', 0)

            record = {
                'host': host,
                'ip': session.get('ip', ''),
                'port': port,
                'connected': session.get('connected', ''),
                'fingerprint': probe.get('fingerprint', fp_dir),
                'data_path': f"{fp_dir}/{fname}",
                'offered': fp_data.get('offered-options', []),
                'requested': fp_data.get(
                    'requested-options', []),
                'refused': fp_data.get('refused-options', []),
                'server_offered': option_states.get(
                    'server_offered', {}),
                'server_requested': option_states.get(
                    'server_requested', {}),
                'encoding': session_data.get(
                    'encoding', 'unknown'),
                'encoding_override': encoding_overrides.get(
                    (host, port), ''),
                'banner_before': session_data.get(
                    'banner_before_return', ''),
                'banner_after': session_data.get(
                    'banner_after_return', ''),
                'timing': session_data.get('timing', {}),
            }

            banner = _combine_banners(
                record, default_encoding=DEFAULT_ENCODING)
            record['bbs_software'] = detect_bbs_software(banner)

            record['website'] = ''
            for banner_key in ('banner_before', 'banner_after'):
                banner_text = record[banner_key]
                if banner_text:
                    match = _URL_RE.search(
                        _strip_ansi(banner_text))
                    if match:
                        record['website'] = match.group(0)
                        break

            offered = set(record['offered'])
            requested = set(record['requested'])
            record['tls_support'] = (
                'TLS' in offered or 'TLS' in requested)

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
        'unique_fingerprints': len(
            set(s['fingerprint'] for s in servers)),
        'scan_time_first': (connected_times[0]
                            if connected_times else ''),
        'scan_time_last': (connected_times[-1]
                           if connected_times else ''),
    }

    software_counts = Counter()
    for s in servers:
        if s['bbs_software']:
            software_counts[s['bbs_software']] += 1
    stats['bbs_software_counts'] = dict(software_counts)
    stats['bbs_software_detected'] = sum(software_counts.values())

    encoding_counts = Counter()
    for s in servers:
        enc = s.get('encoding_override') or DEFAULT_ENCODING
        encoding_counts[enc] += 1
    stats['encoding_counts'] = dict(encoding_counts)

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

def create_bbs_software_plot(stats, output_path):
    """Create pie chart of BBS software distribution."""
    software_counts = stats['bbs_software_counts']
    if not software_counts:
        return

    sorted_items = sorted(software_counts.items(),
                          key=lambda x: x[1], reverse=True)
    labels = [s for s, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(
        labels, counts, min_count=1)
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


def create_encoding_plot(stats, output_path):
    """Create pie chart of encoding distribution."""
    encoding_counts = stats['encoding_counts']
    if not encoding_counts:
        return

    sorted_items = sorted(encoding_counts.items(),
                          key=lambda x: x[1], reverse=True)
    labels = [e for e, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(
        labels, counts, min_count=1)
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


def create_all_plots(stats):
    """Generate all matplotlib plots."""
    os.makedirs(PLOTS_PATH, exist_ok=True)
    _setup_plot_style()

    create_bbs_software_plot(
        stats, os.path.join(PLOTS_PATH, 'bbs_software.png'))
    create_encoding_plot(
        stats, os.path.join(PLOTS_PATH, 'encoding_distribution.png'))
    create_telnet_options_plot(
        stats, os.path.join(PLOTS_PATH, 'telnet_options.png'))


# ---------------------------------------------------------------------------
# Filename assignment
# ---------------------------------------------------------------------------

def _bbs_filename(server):
    """Generate a filesystem-safe filename for a BBS detail page."""
    host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', server['host'])
    return f"{host_safe}_{server['port']}"


def _assign_bbs_filenames(servers, ip_groups):
    """Assign ``_bbs_file`` and ``_bbs_toc_label`` to each server.

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
            s['_bbs_file'], s['_bbs_toc_label'] = (
                grouped_keys[key])
        else:
            s['_bbs_file'] = _bbs_filename(s)
            s['_bbs_toc_label'] = f"{s['host']}:{s['port']}"


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
    print(f"- **BBSes responding**: {stats['total_servers']}")
    print(f"- **Unique protocol fingerprints**:"
          f" {stats['unique_fingerprints']}")
    if stats['bbs_software_detected']:
        print(f"- **BBS software detected**:"
              f" {stats['bbs_software_detected']}"
              f" ({len(stats['bbs_software_counts'])}"
              f" unique packages)")
    print()
    print("These statistics reflect the most recent scan of all"
          " servers in the")
    print("`bbslist.txt "
          "<https://github.com/jquast/bbs.modem.xyz/blob/master/"
          "data/bbslist.txt>`_ input list.")
    print("Each server is probed using `telnetlib3 "
          "<https://github.com/jquast/telnetlib3>`_,")
    print("which connects to each address, performs Telnet option"
          " negotiation,")
    print("and captures the login banner.")
    print()


def display_plots():
    """Print figure directives for all plots."""
    print("The charts below summarize data from all responding"
          " servers.")
    print()

    print("BBS Software")
    print("-------------")
    print()
    print(".. figure:: _static/plots/bbs_software.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of"
          " detected BBS"
          " software packages across all responding servers.")
    print()
    print("   BBS software detected from login banners.")
    print()

    print("Encoding Distribution")
    print("----------------------")
    print()
    print(".. figure:: _static/plots/encoding_distribution.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of"
          " character"
          " encodings across all servers.")
    print()
    print("   Character encoding distribution"
          " (default: CP437).")
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
    print("BBS Servers")
    print("===========")
    print()
    print("All servers that responded to a Telnet connection"
          " during the most")
    print("recent scan. Click a column header to sort. Use the"
          " search box to")
    print("filter by host, software, or encoding.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Host**")
    print("     - Hostname and port. Links to a detail page"
          " with banner,"
          " fingerprint, and connection log.")
    print("   * - **Software**")
    print("     - BBS software detected from the login banner"
          " (e.g. Synchronet, Mystic BBS).")
    print("   * - **Encoding**")
    print("     - Character encoding. Defaults to CP437 unless"
          " overridden"
          " in bbslist.txt.")
    print("   * - **Fingerprint**")
    print("     - Truncated hash of the server's Telnet option"
          " negotiation"
          " behavior.")
    print("   * - **Banner**")
    print("     - First line of the server's login banner text.")
    print()

    rows = []
    for s in servers:
        bbs_file = s['_bbs_file']
        host_display = f"{s['host']}:{s['port']}"
        host_cell = (f":doc:`{_rst_escape(host_display)}"
                     f" <bbs_detail/{bbs_file}>`")
        if s['website']:
            href = s['website']
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            host_cell += f' `\U0001f310 <{href}>`__'
        if s['tls_support']:
            host_cell += ' :tls-lock:`\U0001f512`'

        software = s['bbs_software'] or ''
        encoding = s.get('encoding_override') or DEFAULT_ENCODING
        fp = s['fingerprint'][:12] + '...'

        banner = _combine_banners(
            s, default_encoding=DEFAULT_ENCODING)
        banner_excerpt = (_truncate(banner, maxlen=60).split('\n')[0]
                          if banner else '')

        rows.append({
            'Host': host_cell,
            'Software': _rst_escape(software),
            'Encoding': encoding,
            'Fingerprint': f':ref:`{fp} <fp_{s["fingerprint"]}>`',
            'Banner': _rst_escape(banner_excerpt[:50]),
        })

    table_str = tabulate_mod.tabulate(
        rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="BBS Servers")


def display_fingerprint_summary(servers):
    """Print summary table of protocol fingerprints."""
    print("BBS by Fingerprint")
    print("==================")
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
    print("     - Sample server addresses sharing this"
          " fingerprint.")
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
        server_addrs = ', '.join(
            f"{s['host']}:{s['port']}" for s in fp_servers[:3])
        if len(fp_servers) > 3:
            server_addrs += f', ... (+{len(fp_servers) - 3})'

        rows.append({
            'Fingerprint': f':ref:`{fp[:16]}... <fp_{fp}>`',
            'Servers': str(len(fp_servers)),
            'Offers': _rst_escape(offered[:30]),
            'Requests': _rst_escape(requested[:30]),
            'Examples': _rst_escape(server_addrs[:50]),
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


def display_bbs_software_groups(servers):
    """Print BBS by Software page."""
    _rst_heading("BBS by Software", '=')
    print("Servers grouped by the BBS software detected from"
          " their login")
    print("banner. Detection is based on pattern matching against"
          " known")
    print("software names. Servers whose software could not be"
          " identified")
    print("are listed under *Unidentified*.")
    print()

    by_software = {}
    for s in servers:
        key = s['bbs_software'] or 'Unidentified'
        by_software.setdefault(key, []).append(s)

    rows = []
    for name, members in sorted(by_software.items(),
                                 key=lambda x: (-len(x[1]),
                                                x[0])):
        rows.append({
            'Software': (
                f'`{_rst_escape(name)}`_'
                if name != 'Unidentified'
                else '`Unidentified`_'),
            'Servers': str(len(members)),
        })
    table_str = tabulate_mod.tabulate(
        rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="BBS Software")

    for name, members in sorted(by_software.items(),
                                 key=lambda x: (-len(x[1]),
                                                x[0])):
        _rst_heading(name, '-')
        for s in sorted(members,
                        key=lambda s: s['host'].lower()):
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            tls = (' :tls-lock:`\U0001f512`'
                   if s['tls_support'] else '')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <bbs_detail/{bbs_file}>`{tls}")
        print()


# ---------------------------------------------------------------------------
# RST generation
# ---------------------------------------------------------------------------

def generate_summary_rst(stats):
    """Generate the statistics.rst file."""
    rst_path = os.path.join(DOCS_PATH, "statistics.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_summary_stats(stats)
        display_plots()
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


def generate_bbs_software_rst(servers):
    """Generate the bbs_software.rst file."""
    rst_path = os.path.join(DOCS_PATH, "bbs_software.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        display_bbs_software_groups(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_details_rst(servers):
    """Generate the servers.rst index page with toctree."""
    rst_path = os.path.join(DOCS_PATH, "servers.rst")
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        print("Servers")
        print("=======")
        print()
        print("Individual detail pages for each BBS scanned"
              " in this")
        print("census. Each page shows the server's ANSI login"
              " banner,")
        print("detected encoding, BBS software (if identified),")
        print("fingerprint data, the raw JSON scan record,"
              " and the")
        print("full Telnet negotiation log.")
        print()
        bbslist_url = ("https://github.com/jquast/bbs.modem.xyz"
                       "/blob/master/data/bbslist.txt")
        print(f"Missing a BBS? `Submit a pull request "
              f"<{bbslist_url}>`_ to add it.")
        print()
        print(".. toctree::")
        print("   :maxdepth: 1")
        print()
        seen_files = set()
        for s in servers:
            bbs_file = s['_bbs_file']
            if bbs_file in seen_files:
                continue
            seen_files.add(bbs_file)
            label = s.get('_bbs_toc_label',
                          f"{s['host']}:{s['port']}")
            print(f"   {label} <bbs_detail/{bbs_file}>")
        print()
    print(f"  wrote {rst_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Detail pages
# ---------------------------------------------------------------------------

def _write_bbs_port_section(server, sec_char, logs_dir=None,
                             data_dir=None, fp_counts=None):
    """Write detail content sections for one BBS port.

    :param server: server record dict
    :param sec_char: RST underline character for section headings
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    host = server['host']
    port = server['port']
    title = f"{host}:{port}"

    url = _telnet_url(host, port)
    _rst_heading("Server URLs", sec_char)
    print(f".. raw:: html")
    print()
    print(f'   <ul class="mud-connect">')
    print(f'   <li><a href="{url}" class="telnet-link">'
          f'{host}:{port}</a>')
    print(f'   <button class="copy-btn"'
          f' data-host="{host}"'
          f' data-port="{port}"'
          f' title="Copy host and port"'
          f' aria-label="Copy {host} port {port}'
          f' to clipboard">')
    print(f'   <span class="copy-icon"'
          f' aria-hidden="true">'
          f'&#x2398;</span>')
    print(f'   </button>')
    if server['tls_support']:
        print(f'   <span class="tls-lock"'
              f' title="Supports TLS">'
              f'&#x1f512;</span>')
    print(f'   </li>')
    if server['website']:
        href = server['website']
        if not href.startswith(('http://', 'https://')):
            href = f'http://{href}'
        print(f'   <li><strong>Website</strong>: '
              f'<a href="{href}">'
              f'{_rst_escape(server["website"])}'
              f'</a></li>')
    print(f'   </ul>')
    print()

    banner = _combine_banners(
        server, default_encoding=DEFAULT_ENCODING)
    if banner and not _is_garbled(banner):
        effective_enc = (
            server.get('encoding_override')
            or DEFAULT_ENCODING)
        bbs_file = server['_bbs_file']
        banner_fname = f"{bbs_file}_{port}.png"
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
                banner, name=title)
            print(".. raw:: html")
            print()
            for line in banner_html.split('\n'):
                print(f"   {line}")
            print()
    elif banner:
        print("*Banner not shown (legacy encoding"
              " not supported).*")
        print()

    if server['bbs_software']:
        _rst_heading("BBS Software", sec_char)
        print(f"**Detected**:"
              f" {_rst_escape(server['bbs_software'])}")
        print()

    effective_enc = (server.get('encoding_override')
                     or DEFAULT_ENCODING)
    scanner_enc = server.get('encoding', 'unknown')
    _rst_heading("Encoding", sec_char)
    print(f"- **Effective encoding**: {effective_enc}")
    if server.get('encoding_override'):
        print(f"- **Override**: {server['encoding_override']}"
              " (from bbslist.txt)")
    print(f"- **Scanner detected**: {scanner_enc}")
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
              + ', '.join(
                  f"``{o}``"
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
        json_file = os.path.join(data_dir, "server", data_path)
        github_url = f"{GITHUB_DATA_BASE}/{data_path}"
        print(f"**Data source**: `{data_path} <{github_url}>`_")
        print()
        print("The complete JSON record collected during the"
              " scan,")
        print("including Telnet negotiation results and"
              " banner data.")
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
            logs_dir, f"{host}:{port}.log")
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


def generate_bbs_detail(server, logs_dir=None, force=False,
                         data_dir=None, fp_counts=None):
    """Generate a detail page for one BBS server.

    :param server: server record dict
    :param logs_dir: path to log directory
    :param force: if True, skip mtime checks
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    bbs_file = server['_bbs_file']
    detail_path = os.path.join(BBS_DETAIL_PATH,
                               f"{bbs_file}.rst")

    if not force and data_dir:
        json_path = os.path.join(
            data_dir, "server", server.get('data_path', ''))
        log_path = (os.path.join(
            logs_dir,
            f"{server['host']}:{server['port']}.log")
                    if logs_dir else None)
        if not _needs_rebuild(
                detail_path, json_path, log_path, __file__):
            return False

    host = server['host']
    port = server['port']
    title = f"{host}:{port}"

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        escaped_title = _rst_escape(title)
        _rst_heading(escaped_title, '=')

        _write_bbs_port_section(
            server, '-', logs_dir=logs_dir, data_dir=data_dir,
            fp_counts=fp_counts)


def generate_bbs_detail_group(ip, group_servers, logs_dir=None,
                               data_dir=None, fp_counts=None):
    """Generate a combined detail page for BBSes sharing an IP.

    :param ip: shared IP address
    :param group_servers: list of server records sharing this IP
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    bbs_file = group_servers[0]['_bbs_file']
    detail_path = os.path.join(BBS_DETAIL_PATH,
                               f"{bbs_file}.rst")
    hostname_hint = _most_common_hostname(group_servers)
    if hostname_hint == ip:
        display_name = ip
    else:
        display_name = f"{ip} ({hostname_hint})"

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(display_name)
        _rst_heading(escaped_name, '=')

        for server in group_servers:
            host = server['host']
            port = server['port']
            sub_title = f"{host}:{port}"
            escaped_sub = _rst_escape(sub_title)
            _rst_heading(escaped_sub, '-')

            _write_bbs_port_section(
                server, '~', logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts)


def generate_bbs_details(servers, logs_dir=None, force=False,
                          data_dir=None, ip_groups=None):
    """Generate all per-BBS detail pages.

    :param servers: list of server records
    :param logs_dir: path to log directory
    :param force: if True, regenerate all files
    :param data_dir: path to data directory
    :param ip_groups: dict from :func:`_group_shared_ip`
    """
    if force:
        _clean_dir(BBS_DETAIL_PATH)
    os.makedirs(BBS_DETAIL_PATH, exist_ok=True)

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
        result = generate_bbs_detail(
            s, logs_dir=logs_dir, force=force, data_dir=data_dir,
            fp_counts=fp_counts)
        if result is not False:
            rebuilt += 1

    if ip_groups:
        for ip, members in sorted(ip_groups.items()):
            generate_bbs_detail_group(
                ip, members, logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts)
            rebuilt += 1

    total = (len(servers) - len(grouped_keys)
             + len(ip_groups or {}))
    if rebuilt < total:
        print(f"  wrote {rebuilt}/{total} BBS detail pages"
              f" to {BBS_DETAIL_PATH}"
              f" ({total - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} BBS detail pages"
              f" to {BBS_DETAIL_PATH}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Fingerprint detail pages
# ---------------------------------------------------------------------------

def generate_fingerprint_detail(fp_hash, fp_servers, force=False,
                                 data_dir=None):
    """Generate a detail page for one fingerprint group.

    :param fp_hash: fingerprint hash string
    :param fp_servers: list of server records sharing this fingerprint
    :param force: if True, skip mtime checks
    :param data_dir: path to data directory
    """
    detail_path = os.path.join(DETAIL_PATH, f"{fp_hash}.rst")

    if not force and data_dir:
        source_paths = [
            os.path.join(data_dir, "server",
                         s.get('data_path', ''))
            for s in fp_servers
        ]
        if not _needs_rebuild(detail_path, *source_paths,
                              __file__):
            return False

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
                  + ', '.join(
                      f"``{o}``"
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
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            tls = (' :tls-lock:`\U0001f512`'
                   if s['tls_support'] else '')
            print(f":doc:`{_rst_escape(label)}"
                  f" <../bbs_detail/{bbs_file}>`{tls}")
            print()

            if s['bbs_software']:
                print(f"  - Software:"
                      f" {_rst_escape(s['bbs_software'])}")
            enc = s.get('encoding_override') or DEFAULT_ENCODING
            print(f"  - Encoding: {enc}")
            if s['website']:
                href = s['website']
                if not href.startswith(
                        ('http://', 'https://')):
                    href = f'http://{href}'
                print(f"  - Website:"
                      f" `{_rst_escape(s['website'])}"
                      f" <{href}>`_")
            print()

            banner = _combine_banners(
                s, default_encoding=DEFAULT_ENCODING)
            if banner and not _is_garbled(banner):
                bfname = f"{bbs_file}_{s['port']}.png"
                bpath = os.path.join(BANNERS_PATH, bfname)
                if os.path.isfile(bpath):
                    print(f"  .. image:: "
                          f"/_static/banners/{bfname}")
                    print(f"     :alt: "
                          f"{_rst_escape(_banner_alt_text(banner))}")
                    print(f"     :class: ansi-banner")
                    print()
                else:
                    banner_html = _banner_to_html(
                        banner, maxlen=300, maxlines=10,
                        name=label)
                    print("  .. raw:: html")
                    print()
                    for line in banner_html.split('\n'):
                        print(f"     {line}")
                    print()


def generate_fingerprint_details(servers, force=False,
                                  data_dir=None):
    """Generate all fingerprint detail pages.

    :param servers: list of server records
    :param force: if True, regenerate all files
    :param data_dir: path to data directory
    """
    if force:
        _clean_dir(DETAIL_PATH)
    os.makedirs(DETAIL_PATH, exist_ok=True)

    by_fp = {}
    for s in servers:
        by_fp.setdefault(s['fingerprint'], []).append(s)

    rebuilt = 0
    for fp_hash, fp_servers in sorted(by_fp.items()):
        result = generate_fingerprint_detail(
            fp_hash, fp_servers, force=force,
            data_dir=data_dir)
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
    """Run the BBS statistics pipeline.

    :param args: parsed argparse namespace
    """
    data_dir = os.path.abspath(
        args.data_dir
        or os.path.join(_PROJECT_ROOT, 'data-bbs'))
    logs_dir = os.path.abspath(
        args.logs_dir
        or os.path.join(_PROJECT_ROOT, 'logs'))
    bbslist = (
        args.server_list
        or os.path.join(data_dir, 'bbslist.txt'))
    force = args.force

    if os.path.isdir(logs_dir):
        print(f"Using logs from {logs_dir}", file=sys.stderr)
    else:
        logs_dir = None

    encoding_overrides = load_bbslist_encodings(bbslist)
    if encoding_overrides:
        print(f"Loaded {len(encoding_overrides)} encoding"
              f" overrides from {bbslist}", file=sys.stderr)

    print(f"Loading data from {data_dir} ...", file=sys.stderr)
    records = load_server_data(data_dir, encoding_overrides)
    print(f"  loaded {len(records)} session records",
          file=sys.stderr)

    servers = deduplicate_servers(records)
    print(f"  {len(servers)} unique servers after deduplication",
          file=sys.stderr)

    listed = _parse_server_list(bbslist)
    servers = [s for s in servers
               if (s['host'], s['port']) in listed]
    print(f"  {len(servers)} servers after filtering"
          f" by {bbslist}", file=sys.stderr)

    ip_groups = _group_shared_ip(servers)
    _assign_bbs_filenames(servers, ip_groups)
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
    generate_bbs_software_rst(servers)
    generate_details_rst(servers)
    generate_bbs_details(servers, logs_dir=logs_dir,
                          force=force, data_dir=data_dir,
                          ip_groups=ip_groups)
    generate_fingerprint_details(servers, force=force,
                                  data_dir=data_dir)

    _remove_stale_rst(BBS_DETAIL_PATH,
                      {s['_bbs_file'] for s in servers})
    _remove_stale_rst(DETAIL_PATH,
                      {s['fingerprint'] for s in servers})

    print("Done. Run sphinx-build to generate HTML.",
          file=sys.stderr)
