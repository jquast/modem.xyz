"""BBS-specific statistics generation."""

import codecs
import contextlib
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

import tabulate as tabulate_mod

from make_stats.common import (
    _PROJECT_ROOT, _URL_RE, _URL_SCANNER_DOMAINS,
    _parse_server_list, _load_encoding_overrides, _load_column_overrides,
    _load_row_overrides, _load_no_ambig_overrides, _load_ssh_overrides,
    _load_base_records, _generate_rst,
    _render_banner_section, _render_similar_banners,
    _render_json_section,
    _render_log_section, _render_fingerprint_section,
    _find_similar_banners,
    _rst_escape, _strip_ansi, _is_garbled,
    _clean_log_line, _combine_banners,
    _has_encoding_issues, _truncate,
    _banner_to_png, _banner_alt_text, _telnet_url,
    init_renderer, close_renderer, purge_failed_banners,
    _rst_heading, print_datatable, display_top_sequences,
    _group_shared_ip, _most_common_hostname,
    _clean_dir, _remove_stale_rst, _needs_rebuild,
    _rst_references_missing_images,
    deduplicate_servers,
    _setup_plot_style, _create_pie_chart,
    create_telnet_options_plot, create_location_plot,
    create_option_pie_chart,
    display_charset_section as _display_charset_section,
    _assign_filenames,
    display_fingerprint_summary as _display_fingerprint_summary,
    _write_fingerprint_options_section,
    display_encoding_groups as _display_encoding_groups,
    display_location_groups as _display_location_groups,
    generate_banner_gallery as _generate_banner_gallery,
    generate_fingerprint_details as _generate_fingerprint_details,
)
from make_stats.geoip import lookup_countries, _country_flag

DOCS_PATH = os.path.join(_PROJECT_ROOT, "docs-bbs")
PLOTS_PATH = os.path.join(DOCS_PATH, "_static", "plots")
DETAIL_PATH = os.path.join(DOCS_PATH, "server_detail")
BBS_DETAIL_PATH = os.path.join(DOCS_PATH, "bbs_detail")
BANNERS_PATH = os.path.join(DOCS_PATH, "_static", "banners")

# Default encoding assumed for all BBSes unless overridden
DEFAULT_ENCODING = 'cp437'

# nmap banner-scan chunk directory.
_NMAP_CHUNK_DIR = os.path.join(
    _PROJECT_ROOT, 'nmap', 'data', 'banner-scan', 'chunks')

# Well-known BBS-adjacent service ports: (display_name, url_scheme).
# url_scheme=None means no standard clickable URL — just label + host:port.
# Telnet/RLogin ports are intentionally excluded; those are handled separately.
_EXTRA_SERVICE_PORTS = {
    21:    ('FTP',       'ftp'),
    70:    ('Gopher',    'gopher'),
    79:    ('Finger',    'finger'),
    80:    ('HTTP',      'http'),
    119:   ('NNTP',      'nntp'),
    443:   ('HTTPS',     'https'),
    1123:  ('WebSocket',        'ws'),
    6667:  ('IRC',              'irc'),
    11235: ('Secure WebSocket', 'wss'),
    24553: ('BINKP',     None),
    24554: ('BINKP',     None),
}

# Default ports for each URL scheme (omit port from URL when it matches).
_SCHEME_DEFAULT_PORTS = {
    'ftp': 21, 'gopher': 70, 'finger': 79,
    'http': 80, 'nntp': 119, 'https': 443, 'irc': 6667,
    'ws': 80, 'wss': 443,
}


def _ensure_banner(server):
    """Generate the banner PNG for a server without writing RST.

    Called for servers whose detail pages are unchanged, to ensure
    the banner PNG exists on disk and ``server['_banner_png']`` is set.
    """
    banner = _combine_banners(server, default_encoding=DEFAULT_ENCODING)
    if banner and not _is_garbled(banner):
        effective_enc = (
            server.get('encoding_override') or DEFAULT_ENCODING)
        banner_fname, display_w = _banner_to_png(
            banner, BANNERS_PATH, effective_enc,
            columns=server.get('column_override'),
            rows=server.get('row_override'),
            no_ambig=server.get('no_ambig_override', False),
            ice_colors=True)
        if banner_fname:
            server['_banner_png'] = banner_fname
            if display_w:
                server['_banner_display_width'] = display_w

# Known BBS software patterns (case-insensitive match against banner text)
BBS_SOFTWARE_PATTERNS = [
    (re.compile(r'Synchronet', re.IGNORECASE), 'Synchronet'),
    (re.compile(r'Mystic\s*BBS', re.IGNORECASE), 'Mystic BBS'),
    (re.compile(r'WWIV', re.IGNORECASE), 'WWIV'),
    (re.compile(r'Renegade', re.IGNORECASE), 'Renegade BBS'),
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
    (re.compile(r'MBBS|Major\s*BBS|GALACTICOMM', re.IGNORECASE), 'MajorBBS'),
    (re.compile(r'CNet PRO', re.IGNORECASE), 'CNET'),
    (re.compile(r'TriBBS', re.IGNORECASE), 'TriBBS'),
    (re.compile(r'EleBBS', re.IGNORECASE), 'EleBBS'),
    (re.compile(r'Iniquity', re.IGNORECASE), 'Iniquity'),
    (re.compile(r'Citadel', re.IGNORECASE), 'Citadel'),
    (re.compile(r'TAG\s*BBS', re.IGNORECASE), 'TAG BBS'),
    (re.compile(r'Hermes\s*II?', re.IGNORECASE), 'Hermes'),
    (re.compile(r'bbs100', re.IGNORECASE), 'bbs100'),
    (re.compile(r'SBBS', re.IGNORECASE), 'SBBS'),
]

# EMSI / FidoNet detection patterns
_EMSI_RE = re.compile(r'\*\*EMSI_')
_FIDONET_ADDR_RE = re.compile(r'(\d+:\d+/\d+(?:\.\d+)?(?:@\w+)?)')
_EMSI_MAILER_RE = re.compile(r'\*\*EMSI_MD5[0-9A-Fa-f]{4}<[^>]*-([^>]+)>')


def detect_fidonet(banner_before, banner_after):
    """Detect EMSI handshake and extract FidoNet information from banners.

    :param banner_before: raw banner text before carriage return
    :param banner_after: raw banner text after carriage return
    :returns: dict with ``has_emsi``, ``fidonet_addresses``, ``emsi_mailer``
    """
    full = (banner_before or '') + (banner_after or '')
    has_emsi = bool(_EMSI_RE.search(full))
    addresses = []
    mailer = ''
    if has_emsi:
        addresses = sorted(set(_FIDONET_ADDR_RE.findall(full)))
        mailer_match = _EMSI_MAILER_RE.search(full)
        if mailer_match:
            mailer = mailer_match.group(1)
    return {
        'has_emsi': has_emsi,
        'fidonet_addresses': addresses,
        'emsi_mailer': mailer,
    }


# ---------------------------------------------------------------------------
# nmap service data
# ---------------------------------------------------------------------------

def _load_nmap_host_services(chunk_dir=None):
    """Load non-telnet open service ports per host IP from nmap banner-scan XMLs.

    Reads all chunk XML files and returns a mapping of IP address to the
    extra (non-telnet/rlogin) services detected, restricted to the ports
    listed in :data:`_EXTRA_SERVICE_PORTS`.

    :param chunk_dir: path to nmap banner-scan chunks directory
    :returns: dict mapping IP string to dict {service_name: [port, ...]}
    """
    import glob as _glob
    import xml.etree.ElementTree as ET

    if chunk_dir is None:
        chunk_dir = _NMAP_CHUNK_DIR
    result = {}
    if not os.path.isdir(chunk_dir):
        return result
    for xml_path in sorted(_glob.glob(os.path.join(chunk_dir, '*.xml'))):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        for host_el in tree.getroot().findall('host'):
            ip = None
            for addr in host_el.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr')
                    break
            if not ip:
                continue
            ports_el = host_el.find('ports')
            if ports_el is None:
                continue
            services = result.setdefault(ip, {})
            for port_el in ports_el.findall('port'):
                portid = int(port_el.get('portid'))
                info = _EXTRA_SERVICE_PORTS.get(portid)
                if info is None:
                    continue
                state = port_el.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                svc_name, _ = info
                port_list = services.setdefault(svc_name, [])
                if portid not in port_list:
                    port_list.append(portid)
    return result


def _is_rlogin(server):
    """Return True if the server connection is RLogin rather than Telnet.

    Port 513 is definitively RLogin.  For other ports, absence of any
    telnet option negotiation during the scan is used as the signal —
    the scanner connected but no IAC exchange occurred.

    :param server: server record dict
    :returns: bool
    """
    if server['port'] == 513:
        return True
    return not server.get('offered') and not server.get('requested')


def _extra_service_url(host, svc_name, port):
    """Build a URL string for a non-telnet BBS service.

    :param host: hostname
    :param svc_name: display service name (e.g. ``'FTP'``)
    :param port: port number
    :returns: URL string, or None if the service has no standard URL scheme
    """
    _, scheme = _EXTRA_SERVICE_PORTS.get(port, (svc_name, None))
    if not scheme:
        return None
    if _SCHEME_DEFAULT_PORTS.get(scheme) == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


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
    return _load_encoding_overrides(bbslist_path)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_ibbs_metadata(csv_path):
    """Load ibbs BBS metadata from cached bbslist.csv.

    :param csv_path: path to ibbs_bbslist.csv
    :returns: dict {host_lower: {'name', 'sysop', 'website', 'software', 'location'}}
    """
    import csv as _csv
    result = {}
    if not os.path.isfile(csv_path):
        return result
    with open(csv_path, encoding='utf-8', errors='replace') as f:
        reader = _csv.DictReader(f)
        for row in reader:
            row = {k.strip(): (v.strip() if v else '')
                   for k, v in row.items()}
            host = row.get('TelnetAddress', '').strip().lower()
            if not host:
                continue
            result[host] = {
                'name': row.get('bbsName', ''),
                'sysop': row.get('bbsSysop', ''),
                'website': row.get('WebAddress', ''),
                'software': row.get('software', ''),
                'location': row.get('location', ''),
            }
    return result


def load_server_data(data_dir, encoding_overrides=None,
                     column_overrides=None, row_overrides=None,
                     no_ambig_overrides=None,
                     ssh_overrides=None, ibbs_meta=None,
                     nmap_services=None):
    """Load all server fingerprint JSON files from the data directory.

    :param data_dir: path to telnetlib3 data directory
    :param encoding_overrides: dict mapping (host, port) to encoding
    :param column_overrides: dict mapping (host, port) to column width
    :param row_overrides: dict mapping (host, port) to row height
    :param no_ambig_overrides: dict mapping (host, port) to True
    :param ssh_overrides: dict mapping host_lower to ssh_port int
    :param ibbs_meta: dict mapping host_lower to ibbs metadata dict
    :param nmap_services: dict from :func:`_load_nmap_host_services`
    :returns: list of parsed server record dicts
    """
    if ssh_overrides is None:
        ssh_overrides = {}
    if ibbs_meta is None:
        ibbs_meta = {}
    if nmap_services is None:
        nmap_services = {}

    base_records = _load_base_records(
        data_dir, encoding_overrides, column_overrides, row_overrides,
        no_ambig_overrides)

    records = []
    for record in base_records:
        record.pop('_session_data', None)

        banner = _combine_banners(
            record, default_encoding=DEFAULT_ENCODING)
        record['bbs_software'] = detect_bbs_software(banner)
        record['bbs_software_source'] = (
            'detected' if record['bbs_software'] else '')

        stripped = _strip_ansi(banner) if banner else ''
        has_replacement = (
            '\ufffd' in (record['banner_before'] or '')
            or '\ufffd' in (record['banner_after'] or ''))
        record['display_encoding'] = (
            record['encoding_override']
            or ('ascii' if stripped and stripped.isascii()
                and not has_replacement
                else DEFAULT_ENCODING))

        fidonet = detect_fidonet(
            record['banner_before'], record['banner_after'])
        record.update(fidonet)

        record['website'] = ''
        for banner_key in ('banner_before', 'banner_after'):
            banner_text = record[banner_key]
            if banner_text:
                match = _URL_RE.search(
                    _strip_ansi(banner_text))
                if match:
                    url = match.group(0)
                    domain = url.split('/')[ 0].lower().lstrip('.')
                    if domain not in _URL_SCANNER_DOMAINS:
                        record['website'] = url
                        break

        offered = set(record['offered'])
        requested = set(record['requested'])
        record['tls_support'] = (
            'TLS' in offered or 'TLS' in requested)

        host_lower = record['host'].lower()
        record['ssh_port'] = ssh_overrides.get(host_lower)
        meta = ibbs_meta.get(host_lower, {})
        if not record['website']:
            record['website'] = meta.get('website', '')
        if not record['bbs_software']:
            record['bbs_software'] = meta.get('software', '')
            if record['bbs_software']:
                record['bbs_software_source'] = 'reported'
        record['ibbs_name'] = meta.get('name', '')
        record['ibbs_sysop'] = meta.get('sysop', '')
        record['ibbs_location'] = meta.get('location', '')

        # Extra (non-telnet) services from nmap, keyed by the server's IP.
        record['extra_services'] = nmap_services.get(
            record.get('ip', ''), {})

        # Whether the connection is RLogin rather than Telnet.
        record['is_rlogin'] = _is_rlogin(record)

        # Peer telnet/rlogin ports — populated later in main() once the
        # full filtered server list is known.
        record['_peer_servers'] = []

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
        'unique_hosts': len(set(s['host'] for s in servers)),
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
        enc = s['display_encoding']
        try:
            enc = codecs.lookup(enc).name
        except LookupError:
            pass
        encoding_counts[enc] += 1
    stats['encoding_counts'] = dict(encoding_counts)

    country_counts = Counter()
    for s in servers:
        country_counts[s.get('_country_name', 'Unknown')] += 1
    stats['country_counts'] = dict(country_counts)

    protocol_counts = Counter()
    for s in servers:
        proto = 'RLogin' if s.get('is_rlogin') else 'Telnet'
        protocol_counts[proto] += 1
        for svc_name in s.get('extra_services', {}):
            protocol_counts[svc_name] += 1
    stats['protocol_counts'] = dict(protocol_counts)

    stats['emsi_count'] = sum(1 for s in servers if s['has_emsi'])

    port_counts = Counter()
    for s in servers:
        port_counts[s['port']] += 1
    stats['port_counts'] = dict(port_counts)

    option_offered = Counter()
    option_requested = Counter()
    option_both = Counter()
    option_refused = Counter()
    for s in servers:
        offered_set = set(s['offered'])
        requested_set = set(s['requested'])
        for opt in offered_set & requested_set:
            option_both[opt] += 1
        for opt in offered_set - requested_set:
            option_offered[opt] += 1
        for opt in requested_set - offered_set:
            option_requested[opt] += 1
        for opt in s['refused']:
            option_refused[opt] += 1
    stats['option_offered'] = dict(option_offered)
    stats['option_requested'] = dict(option_requested)
    stats['option_both'] = dict(option_both)
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
    _create_pie_chart(sorted_items, output_path)


def create_bbs_protocol_plot(stats, output_path):
    """Create pie chart of BBS connection protocol distribution."""
    protocol_counts = stats.get('protocol_counts', {})
    if not protocol_counts:
        return
    sorted_items = sorted(protocol_counts.items(),
                          key=lambda x: x[1], reverse=True)
    _create_pie_chart(sorted_items, output_path)


def create_encoding_plot(stats, output_path):
    """Create pie chart of encoding distribution."""
    encoding_counts = stats['encoding_counts']
    if not encoding_counts:
        return
    sorted_items = sorted(encoding_counts.items(),
                          key=lambda x: x[1], reverse=True)
    _create_pie_chart(sorted_items, output_path)


def create_port_plot(stats, output_path):
    """Create pie chart of most popular ports."""
    port_counts = stats.get('port_counts', {})
    if not port_counts:
        return
    sorted_items = sorted(port_counts.items(),
                          key=lambda x: x[1], reverse=True)
    _create_pie_chart(sorted_items, output_path, min_count=3)


def create_all_plots(stats):
    """Generate all matplotlib plots."""
    os.makedirs(PLOTS_PATH, exist_ok=True)
    _setup_plot_style()

    create_bbs_software_plot(
        stats, os.path.join(PLOTS_PATH, 'bbs_software.png'))
    create_bbs_protocol_plot(
        stats, os.path.join(PLOTS_PATH, 'bbs_protocols.png'))
    create_encoding_plot(
        stats, os.path.join(PLOTS_PATH, 'encoding_distribution.png'))
    create_port_plot(
        stats, os.path.join(PLOTS_PATH, 'port_distribution.png'))
    create_telnet_options_plot(
        stats, os.path.join(PLOTS_PATH, 'telnet_options.png'))
    create_location_plot(
        stats, os.path.join(PLOTS_PATH, 'server_locations.png'))


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
    _assign_filenames(
        servers, ip_groups,
        file_key='_bbs_file', toc_key='_bbs_toc_label',
        filename_fn=_bbs_filename,
        standalone_label_fn=lambda s: f"{s['host']}:{s['port']}")


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
    print(f"- **BBSes responding**: {stats['unique_hosts']}")
    print(f"- **Unique protocol fingerprints**:"
          f" {stats['unique_fingerprints']}")
    if stats['bbs_software_detected']:
        print(f"- **BBS software detected**:"
              f" {stats['bbs_software_detected']}"
              f" ({len(stats['bbs_software_counts'])}"
              f" unique packages)")
    if stats['emsi_count']:
        print(f"- **FidoNet (EMSI) detected**:"
              f" {stats['emsi_count']}")
    print()
    print("These statistics reflect the most recent scan of all"
          " servers in the")
    print("`bbslist.txt "
          "<https://github.com/jquast/modem.xyz/blob/master/"
          "bbslist.txt>`_ input list.")
    print("Each server is probed using `telnetlib3 "
          "<https://github.com/jquast/telnetlib3>`_,")
    print("which connects to each address, performs Telnet option"
          " negotiation,")
    print("and captures the login banner.")
    print()


def display_plots(servers):
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

    print("Port Distribution")
    print("------------------")
    print()
    print(".. figure:: _static/plots/port_distribution.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the most popular"
          " ports used by BBS servers.")
    print()
    print("   Most popular ports across all BBS servers.")
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

    _display_charset_section(servers)

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

    print("Server Locations")
    print("-----------------")
    print()
    print(".. figure:: _static/plots/server_locations.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the geographic distribution"
          " of servers by country.")
    print()
    print("   Server locations by country.")
    print()


def display_server_table(servers):
    """Print the main server listing table with telnet:// links."""
    print("Server List")
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
    print("   * - **\U0001f30d**")
    print("     - Country flag from GeoIP lookup.")
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
        flag = _country_flag(s.get('_country_code', ''))
        host_cell = (f":doc:`{_rst_escape(host_display)}"
                     f" <bbs_detail/{bbs_file}>`")
        if s['website']:
            href = s['website']
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            host_cell += f' `\U0001f310 <{href}>`__'
        if s['tls_support']:
            host_cell += f' :tls-lock:`{s["host"]} {s["port"]}`'
        else:
            host_cell += f' :copy-btn:`{s["host"]} {s["port"]}`'

        software = s['bbs_software'] or ''
        encoding = s['display_encoding']
        fp = s['fingerprint'][:12] + '\u2026'

        banner = _combine_banners(
            s, default_encoding=DEFAULT_ENCODING)
        banner_excerpt = (_truncate(banner, maxlen=60).split('\n')[0]
                          if banner else '')

        rows.append({
            'Host': host_cell,
            '\U0001f30d': flag,
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
    _display_fingerprint_summary(
        servers,
        server_label_fn=lambda s: f"{s['host']}:{s['port']}")


def display_bbs_software_groups(servers):
    """Print BBS by Software page."""
    _rst_heading("Software", '=')
    print("Servers grouped by the BBS software detected from"
          " their login")
    print("banner. Detection is based on pattern matching against"
          " known")
    print("software names. Servers whose software could not be"
          " identified")
    print("are listed under *Unidentified*.")
    print()
    print(".. figure:: _static/plots/bbs_software.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of"
          " detected BBS software.")
    print()
    print("   BBS software detected from login banners.")
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
    print(table_str)
    print()

    for name, members in sorted(by_software.items(),
                                 key=lambda x: (-len(x[1]),
                                                x[0])):
        _rst_heading(name, '-')
        for s in sorted(members,
                        key=lambda s: s['host'].lower()):
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            if s['tls_support']:
                tls = f' :tls-lock:`{s["host"]} {s["port"]}`'
            else:
                tls = f' :copy-btn:`{s["host"]} {s["port"]}`'
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <bbs_detail/{bbs_file}>`{tls}")
        print()


def display_encoding_groups(servers):
    """Print BBS by Encoding page."""
    _display_encoding_groups(
        servers,
        detail_subdir='bbs_detail',
        file_key='_bbs_file',
        server_label_fn=lambda s: f"{s['host']}:{s['port']}",
        server_sort_key=lambda s: s['host'].lower(),
        tls_fn=lambda s: s['tls_support'],
        figure_path='_static/plots/encoding_distribution.png')


def display_location_groups(servers):
    """Print BBS by Location page."""
    _display_location_groups(
        servers,
        detail_subdir='bbs_detail',
        file_key='_bbs_file',
        server_label_fn=lambda s: f"{s['host']}:{s['port']}",
        server_sort_key=lambda s: s['host'].lower(),
        tls_fn=lambda s: s['tls_support'],
        figure_path='_static/plots/server_locations.png')


def display_fidonet_servers(servers):
    """Print FidoNet/EMSI servers page."""
    emsi_servers = [s for s in servers if s['has_emsi']]
    _rst_heading("FidoNet", '=')
    print(f"{len(emsi_servers)} servers responded with an"
          " `EMSI <http://ftsc.org/docs/fsc-0056.001>`_")
    print("handshake sequence, indicating FidoNet"
          " capability.")
    print()

    rows = []
    for s in sorted(emsi_servers,
                    key=lambda s: s['host'].lower()):
        bbs_file = s['_bbs_file']
        label = f"{s['host']}:{s['port']}"
        host_cell = (f":doc:`{_rst_escape(label)}"
                     f" <bbs_detail/{bbs_file}>`")
        if s['tls_support']:
            host_cell += f' :tls-lock:`{s["host"]} {s["port"]}`'
        else:
            host_cell += f' :copy-btn:`{s["host"]} {s["port"]}`'
        addrs = ', '.join(s['fidonet_addresses']) or ''
        software = s['bbs_software'] or ''
        mailer = s['emsi_mailer'] or ''
        if software and mailer:
            sw_mailer = f"{software}/{mailer}"
        else:
            sw_mailer = software or mailer
        binkp_ports = s.get('extra_services', {}).get('BINKP', [])
        binkp_str = ', '.join(str(p) for p in sorted(binkp_ports))
        rows.append({
            'Host': host_cell,
            'FidoNet Address': addrs,
            'Software/Mailer': _rst_escape(sw_mailer),
            'BINKP': binkp_str,
        })

    table_str = tabulate_mod.tabulate(
        rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="FidoNet (EMSI) Servers")
    print()


# ---------------------------------------------------------------------------
# RST generation
# ---------------------------------------------------------------------------

def generate_summary_rst(stats, servers):
    """Generate the statistics.rst file."""

    def _display(stats, servers):
        display_summary_stats(stats)
        display_plots(servers)
        display_top_sequences(servers)

    _generate_rst(
        os.path.join(DOCS_PATH, "statistics.rst"),
        _display, stats, servers)


def generate_server_list_rst(servers):
    """Generate the server_list.rst file with detail page toctree."""

    def _display(servers):
        display_server_table(servers)
        print()
        print(".. toctree::")
        print("   :maxdepth: 1")
        print("   :hidden:")
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

    _generate_rst(
        os.path.join(DOCS_PATH, "server_list.rst"),
        _display, servers)


def generate_fingerprints_rst(servers):
    """Generate the fingerprints.rst file."""
    _generate_rst(
        os.path.join(DOCS_PATH, "fingerprints.rst"),
        display_fingerprint_summary, servers)


def generate_fidonet_rst(servers):
    """Generate the fidonet.rst file."""
    _generate_rst(
        os.path.join(DOCS_PATH, "fidonet.rst"),
        display_fidonet_servers, servers)


def display_protocols(servers):
    """Print the protocol index page."""
    _rst_heading("Protocols", '=')
    print("BBSes grouped by detected connection protocol.")
    print("A BBS may appear in multiple groups.")
    print()
    print(".. figure:: _static/plots/bbs_protocols.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of"
          " connection protocols across all BBSes.")
    print()
    print("   Primary connection protocols detected across all BBSes.")
    print()

    # Build protocol → server list.  Order: Telnet, RLogin, then alpha.
    proto_servers = defaultdict(list)
    for s in servers:
        if s.get('is_rlogin'):
            proto_servers['RLogin'].append(s)
        else:
            proto_servers['Telnet'].append(s)
        for svc_name in s.get('extra_services', {}):
            proto_servers[svc_name].append(s)

    ordered = ['Telnet', 'RLogin']
    for name in sorted(proto_servers):
        if name not in ordered:
            ordered.append(name)

    rows = []
    for proto in ordered:
        srvs = proto_servers.get(proto, [])
        if srvs:
            rows.append({
                'Protocol': proto,
                'Servers': str(len(srvs)),
            })
    table_str = tabulate_mod.tabulate(
        rows, headers='keys', tablefmt='rst')
    print_datatable(table_str, caption="Protocol Distribution")

    for proto in ordered:
        srvs = proto_servers.get(proto, [])
        if not srvs:
            continue
        _rst_heading(f"{proto} ({len(srvs)})", '-')
        rows = []
        seen = set()
        for s in sorted(srvs, key=lambda x: x['host'].lower()):
            key = (s['host'], s['port'])
            if key in seen:
                continue
            seen.add(key)
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            host_cell = (f":doc:`{_rst_escape(label)}"
                         f" <bbs_detail/{bbs_file}>`")
            software = _rst_escape(s.get('bbs_software', ''))
            rows.append({
                'Host': host_cell,
                'Software': software,
            })
        table_str = tabulate_mod.tabulate(
            rows, headers='keys', tablefmt='rst')
        print_datatable(table_str, caption=f"{proto} Servers")
        print()


def generate_protocols_rst(servers):
    """Generate the protocols.rst index page."""
    _generate_rst(
        os.path.join(DOCS_PATH, "protocols.rst"),
        display_protocols, servers)


def generate_bbs_software_rst(servers):
    """Generate the bbs_software.rst file."""
    _generate_rst(
        os.path.join(DOCS_PATH, "bbs_software.rst"),
        display_bbs_software_groups, servers)


def generate_encoding_rst(servers):
    """Generate the encodings.rst file."""
    _generate_rst(
        os.path.join(DOCS_PATH, "encodings.rst"),
        display_encoding_groups, servers)


def generate_locations_rst(servers):
    """Generate the locations.rst file."""
    _generate_rst(
        os.path.join(DOCS_PATH, "locations.rst"),
        display_location_groups, servers)


def generate_banner_gallery_rst(servers):
    """Generate paginated banner_gallery*.rst files."""
    _generate_banner_gallery(
        servers,
        docs_path=DOCS_PATH,
        entity_name='BBSes',
        file_key='_bbs_file',
        banners_path=BANNERS_PATH,
        detail_subdir='bbs_detail',
        default_encoding=DEFAULT_ENCODING,
        server_name_fn=lambda s: f"{s['host']}:{s['port']}",
        server_sort_key=lambda g: g['servers'][0]['host'].lower(),
        tls_fn=lambda s: s['tls_support'])


def generate_details_rst(servers):
    """Generate the servers.rst index page with toctree."""

    def _display(servers):
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
        bbslist_url = ("https://github.com/jquast/modem.xyz"
                       "/blob/master/bbslist.txt")
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

    _generate_rst(
        os.path.join(DOCS_PATH, "servers.rst"),
        _display, servers)


# ---------------------------------------------------------------------------
# Detail pages
# ---------------------------------------------------------------------------

def _copy_button(host, port):
    """Emit HTML for a clipboard copy button for host:port.

    :param host: hostname
    :param port: port number
    """
    print(f'   <button class="copy-btn"'
          f' data-host="{host}"'
          f' data-port="{port}"'
          f' title="Copy host and port"'
          f' aria-label="Copy {host} port {port} to clipboard">')
    print(f'   <span class="copy-icon" aria-hidden="true">'
          f'&#x1F4CB;</span>')
    print(f'   </button>')


def _write_bbs_server_urls(server, sec_char, show_peers=True,
                           show_extras=True):
    """Write server URLs section for a BBS server.

    Shows the primary telnet/rlogin connection, any peer connections at
    the same host, non-interactive service links from nmap (FTP, Gopher,
    NNTP, IRC, …), and the BBS website if known.

    :param server: server record dict
    :param sec_char: RST underline character
    :param show_peers: if False, suppress peer server links
    :param show_extras: if False, suppress extra services and website
    """
    host = server['host']
    port = server['port']
    is_rl = server.get('is_rlogin', False)
    proto_label = 'RLogin' if is_rl else 'Telnet'
    conn_url = (f"rlogin://{host}:{port}"
                if is_rl else _telnet_url(host, port))

    _rst_heading("Server URLs", sec_char)
    print(".. raw:: html")
    print()
    print('   <ul class="mud-connect">')

    # Primary connection.
    print(f'   <li><strong>{proto_label}</strong>:'
          f' <a href="{conn_url}" class="telnet-link">'
          f'{host}:{port}</a>')
    _copy_button(host, port)
    print('   </li>')

    # Peer telnet/rlogin ports at the same host (other entries in
    # bbslist.txt that resolve to the same IP).
    for peer in (server.get('_peer_servers', []) if show_peers else []):
        peer_host = peer['host']
        peer_port = peer['port']
        peer_rl = peer.get('is_rlogin', False)
        peer_label = 'RLogin' if peer_rl else 'Telnet'
        peer_url = (f"rlogin://{peer_host}:{peer_port}"
                    if peer_rl else _telnet_url(peer_host, peer_port))
        print(f'   <li><strong>{peer_label}</strong>:'
              f' <a href="{peer_url}" class="telnet-link">'
              f'{peer_host}:{peer_port}</a>')
        _copy_button(peer_host, peer_port)
        print('   </li>')

    # TLS/SSL.
    if server['tls_support']:
        tls_url = f"telnets://{host}:{port}"
        print(f'   <li><strong>TLS/SSL</strong>:'
              f' <a href="{tls_url}">{tls_url}</a>')
        _copy_button(host, port)
        print('   </li>')

    # SSH.
    if server.get('ssh_port'):
        ssh_port = server['ssh_port']
        ssh_url = f"ssh://{host}:{ssh_port}"
        print(f'   <li><strong>SSH</strong>:'
              f' <a href="{ssh_url}">{host}:{ssh_port}</a>')
        _copy_button(host, ssh_port)
        print('   </li>')

    if show_extras:
        # Extra services from nmap (FTP, Gopher, NNTP, IRC, BINKP, …).
        # HTTP/HTTPS are shown as Website if no other website is known.
        extra = server.get('extra_services', {})
        website_from_nmap = ''
        for svc_name in sorted(extra):
            for svc_port in sorted(extra[svc_name]):
                if svc_name in ('HTTP', 'HTTPS'):
                    if not server['website'] and not website_from_nmap:
                        website_from_nmap = _extra_service_url(
                            host, svc_name, svc_port)
                    continue
                url_str = _extra_service_url(host, svc_name, svc_port)
                if url_str:
                    print(f'   <li><strong>{svc_name}</strong>:'
                          f' <a href="{url_str}">'
                          f'{url_str}</a></li>')
                else:
                    print(f'   <li><strong>{svc_name}</strong>:'
                          f' {host}:{svc_port}</li>')

        # Website (from banner/IBBS metadata, or inferred from HTTP/HTTPS).
        website = server['website'] or website_from_nmap
        if website:
            href = website
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            print(f'   <li><strong>Website</strong>:'
                  f' <a href="{href}">'
                  f'{_rst_escape(website)}'
                  f'</a></li>')

    print('   </ul>')
    print()


def _write_bbs_server_info(server, sec_char, show_listing=True):
    """Write BBS-specific server info sections.

    :param server: server record dict
    :param sec_char: RST underline character
    :param show_listing: if False, suppress the Listing section
    """
    geoip_loc = server.get('_country_name', '')
    geoip_flag = _country_flag(
        server.get('_country_code', ''))
    if geoip_loc and geoip_loc != 'Unknown':
        loc_display = f"{_rst_escape(geoip_loc)}"
        if geoip_flag:
            loc_display = f"{geoip_flag} {loc_display}"
        print(f"**Server Location**: {loc_display} (GeoIP)")
        print()

    if show_listing and (server.get('ibbs_name') or server.get('ibbs_sysop')
                         or server.get('ibbs_location')):
        _rst_heading("Listing", sec_char)
        if server.get('ibbs_name'):
            print(f"- **BBS Name**: {_rst_escape(server['ibbs_name'])}"
                  f" (from listing)")
        if server.get('ibbs_sysop'):
            print(f"- **Sysop**: {_rst_escape(server['ibbs_sysop'])}")
        if server.get('ibbs_location'):
            print(f"- **Listed Location**:"
                  f" {_rst_escape(server['ibbs_location'])}")
        print()

    if server['bbs_software']:
        _rst_heading("BBS Software", sec_char)
        source = server.get('bbs_software_source', 'detected')
        label = 'Reported' if source == 'reported' else 'Detected'
        print(f"**{label}**:"
              f" {_rst_escape(server['bbs_software'])}")
        print()

    if server['has_emsi']:
        _rst_heading("FidoNet", sec_char)
        print("This server responded with an EMSI handshake"
              " sequence.")
        print()
        if server['fidonet_addresses']:
            print("- **Address**: "
                  + ', '.join(
                      f"``{a}``"
                      for a in server['fidonet_addresses']))
        if server['emsi_mailer']:
            print(f"- **Mailer**:"
                  f" {_rst_escape(server['emsi_mailer'])}")
        print()

    display_enc = server['display_encoding']
    scanner_enc = server.get('encoding', 'unknown')
    _rst_heading("Encoding", sec_char)
    enc_note = ''
    enc_norm = display_enc.lower().replace('-', '_')
    if enc_norm in ('big5', 'gbk', 'shift_jis', 'euc_kr',
                    'euc_jp', 'gb2312'):
        if server.get('no_ambig_override'):
            enc_note = ' (CJK, narrow ambiguous width)'
        else:
            enc_note = ' (with ambiguous width as wide)'
    print(f"- **Effective encoding**: {display_enc}{enc_note}")
    if server.get('encoding_override'):
        print(f"- **Override**: {server['encoding_override']}"
              " (from bbslist.txt)")
    print(f"- **Scanner detected**: {scanner_enc}")
    print()


def _write_bbs_port_section(server, sec_char, logs_dir=None,
                             data_dir=None, fp_counts=None,
                             show_peers=True, show_extras=True,
                             show_listing=True,
                             similar_banners=None):
    """Write detail content sections for one BBS port.

    :param server: server record dict
    :param sec_char: RST underline character for section headings
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    :param show_peers: if False, suppress peer server links (used on IP-group
        pages where all peers are already shown as sibling sections)
    :param show_extras: if False, suppress extra services and website
    :param show_listing: if False, suppress the Listing section
    :param similar_banners: dict from :func:`_find_similar_banners`
    """
    banner_rst = _render_banner_section(
        server, BANNERS_PATH,
        default_encoding=DEFAULT_ENCODING,
        ice_colors=True)
    if banner_rst:
        print(banner_rst)
    sim_rst = _render_similar_banners(
        server, similar_banners, '_bbs_file')
    if sim_rst:
        print(sim_rst)

    _write_bbs_server_urls(server, sec_char, show_peers=show_peers,
                           show_extras=show_extras)

    _write_bbs_server_info(server, sec_char, show_listing=show_listing)

    fp_rst = _render_fingerprint_section(
        server, sec_char, fp_counts)
    print(fp_rst)

    json_rst = _render_json_section(
        server, data_dir, 'bbs')
    if json_rst:
        print(json_rst)

    log_rst = _render_log_section(server, logs_dir, sec_char)
    if log_rst:
        print(log_rst)


def generate_bbs_detail(server, logs_dir=None, force=False,
                         data_dir=None, fp_counts=None,
                         similar_banners=None):
    """Generate a detail page for one BBS server.

    :param server: server record dict
    :param logs_dir: path to log directory
    :param force: if True, skip mtime checks
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    :param similar_banners: dict from :func:`_find_similar_banners`
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
                detail_path, json_path, log_path, __file__) \
                and not _rst_references_missing_images(
                    detail_path, DOCS_PATH):
            _ensure_banner(server)
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
            fp_counts=fp_counts,
            similar_banners=similar_banners)


def generate_bbs_detail_group(ip, group_servers, logs_dir=None,
                               data_dir=None, fp_counts=None,
                               similar_banners=None):
    """Generate a combined detail page for BBSes sharing an IP.

    :param ip: shared IP address
    :param group_servers: list of server records sharing this IP
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    :param similar_banners: dict from :func:`_find_similar_banners`
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

        for idx, server in enumerate(group_servers):
            host = server['host']
            port = server['port']
            sub_title = f"{host}:{port}"
            anchor = server.get('_detail_anchor', '')
            if anchor:
                print(f".. _{anchor}:")
                print()
            escaped_sub = _rst_escape(sub_title)
            _rst_heading(escaped_sub, '-')

            _write_bbs_port_section(
                server, '~', logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts,
                show_peers=False, show_extras=(idx == 0),
                show_listing=(idx == 0),
                similar_banners=similar_banners)


def generate_bbs_details(servers, logs_dir=None, force=False,
                          data_dir=None, ip_groups=None,
                          similar_banners=None):
    """Generate all per-BBS detail pages.

    :param servers: list of server records
    :param logs_dir: path to log directory
    :param force: if True, regenerate all files
    :param data_dir: path to data directory
    :param ip_groups: dict from :func:`_group_shared_ip`
    :param similar_banners: dict from :func:`_find_similar_banners`
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
            fp_counts=fp_counts,
            similar_banners=similar_banners)
        if result is not False:
            rebuilt += 1

    if ip_groups:
        for ip, members in sorted(ip_groups.items()):
            generate_bbs_detail_group(
                ip, members, logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts,
                similar_banners=similar_banners)
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
                              __file__) \
                and not _rst_references_missing_images(
                    detail_path, DOCS_PATH):
            return False

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        _write_fingerprint_options_section(fp_hash, fp_servers)

        print("Servers")
        print("-------")
        print()

        for s in fp_servers:
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            if s['tls_support']:
                tls = f' :tls-lock:`{s["host"]} {s["port"]}`'
            else:
                tls = f' :copy-btn:`{s["host"]} {s["port"]}`'
            print(f":doc:`{_rst_escape(label)}"
                  f" <../bbs_detail/{bbs_file}>`{tls}")
            print()

            if s['bbs_software']:
                print(f"  - Software:"
                      f" {_rst_escape(s['bbs_software'])}")
            enc = s['display_encoding']
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

            bfname = s.get('_banner_png')
            if bfname:
                banner = _combine_banners(
                    s, default_encoding=DEFAULT_ENCODING)
                print(f"  .. image:: "
                      f"/_static/banners/{bfname}")
                print(f"     :alt: "
                      f"{_rst_escape(_banner_alt_text(banner))}")
                print(f"     :class: ansi-banner")
                bdw = s.get('_banner_display_width')
                if bdw:
                    print(f"     :width: {bdw}px")
                print(f"     :loading: lazy")
                print()


def generate_fingerprint_details(servers, force=False,
                                  data_dir=None):
    """Generate all fingerprint detail pages.

    :param servers: list of server records
    :param force: if True, regenerate all files
    :param data_dir: path to data directory
    """
    def _gen(fp_hash, fp_servers):
        return generate_fingerprint_detail(
            fp_hash, fp_servers, force=force,
            data_dir=data_dir)

    _generate_fingerprint_details(
        servers, DETAIL_PATH, _gen, force=force)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(args):
    """Run the BBS statistics pipeline.

    :param args: parsed argparse namespace
    """
    data_dir = os.path.abspath(
        args.data_dir
        or os.path.join(_PROJECT_ROOT))
    logs_dir = os.path.abspath(
        args.logs_dir
        or os.path.join(_PROJECT_ROOT, 'logs'))
    bbslist = (
        args.server_list
        or os.path.join(_PROJECT_ROOT, 'bbslist.txt'))
    force = args.force

    if os.path.isdir(logs_dir):
        print(f"Using logs from {logs_dir}", file=sys.stderr)
    else:
        logs_dir = None

    encoding_overrides = load_bbslist_encodings(bbslist)
    if encoding_overrides:
        print(f"Loaded {len(encoding_overrides)} encoding"
              f" overrides from {bbslist}", file=sys.stderr)

    column_overrides = _load_column_overrides(bbslist)
    if column_overrides:
        print(f"Loaded {len(column_overrides)} column width"
              f" overrides from {bbslist}", file=sys.stderr)

    row_overrides = _load_row_overrides(bbslist)
    if row_overrides:
        print(f"Loaded {len(row_overrides)} tall terminal"
              f" overrides from {bbslist}", file=sys.stderr)

    no_ambig_overrides = _load_no_ambig_overrides(bbslist)
    if no_ambig_overrides:
        print(f"Loaded {len(no_ambig_overrides)} no_ambig"
              f" overrides from {bbslist}", file=sys.stderr)

    ssh_overrides = _load_ssh_overrides(bbslist)
    ibbs_csv = os.path.join(os.path.dirname(bbslist), 'ibbs_bbslist.csv')
    ibbs_meta = _load_ibbs_metadata(ibbs_csv) if os.path.isfile(ibbs_csv) else {}
    print(f"  {len(ssh_overrides)} SSH overrides,"
          f" {len(ibbs_meta)} ibbs entries", file=sys.stderr)

    nmap_services = _load_nmap_host_services()
    print(f"  nmap extra-service data for"
          f" {len(nmap_services)} hosts", file=sys.stderr)

    print(f"Loading data from {data_dir} ...", file=sys.stderr)
    records = load_server_data(data_dir, encoding_overrides,
                               column_overrides, row_overrides,
                               no_ambig_overrides,
                               ssh_overrides=ssh_overrides,
                               ibbs_meta=ibbs_meta,
                               nmap_services=nmap_services)
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

    # Attach peer telnet/rlogin ports: other bbslist.txt entries that
    # resolve to the same IP, so the URL section can show all of them.
    _ip_to_servers = defaultdict(list)
    for s in servers:
        if s.get('ip'):
            _ip_to_servers[s['ip']].append(s)
    for s in servers:
        s['_peer_servers'] = [
            p for p in _ip_to_servers.get(s.get('ip', ''), [])
            if p is not s
        ]

    ip_groups = _group_shared_ip(servers)
    _assign_bbs_filenames(servers, ip_groups)
    if ip_groups:
        n_groups = len(ip_groups)
        n_combined = sum(len(m) for m in ip_groups.values())
        print(f"  {n_groups} IP groups"
              f" ({n_combined} servers combined)",
              file=sys.stderr)

    lookup_countries(servers)

    stats = compute_statistics(servers)

    print("Generating plots ...", file=sys.stderr)
    create_all_plots(stats)
    create_option_pie_chart(
        servers, 'CHARSET',
        os.path.join(PLOTS_PATH, 'charset.png'))
    create_option_pie_chart(
        servers, 'BINARY',
        os.path.join(PLOTS_PATH, 'binary.png'))
    print(f"  wrote plots to {PLOTS_PATH}", file=sys.stderr)

    os.makedirs(BANNERS_PATH, exist_ok=True)
    purge_failed_banners(BANNERS_PATH)
    init_renderer(rows=25,
                  check_dupes=getattr(args, 'check_dupes', False))
    try:
        print("Generating RST ...", file=sys.stderr)
        generate_summary_rst(stats, servers)
        generate_server_list_rst(servers)
        generate_fingerprints_rst(servers)
        generate_bbs_software_rst(servers)
        generate_encoding_rst(servers)
        generate_locations_rst(servers)
        generate_fidonet_rst(servers)
        generate_protocols_rst(servers)
        similar_banners = _find_similar_banners(
            servers, default_encoding=DEFAULT_ENCODING)
        generate_bbs_details(servers, logs_dir=logs_dir,
                              force=force, data_dir=data_dir,
                              ip_groups=ip_groups,
                              similar_banners=similar_banners)
        generate_fingerprint_details(servers, force=force,
                                      data_dir=data_dir)
        generate_banner_gallery_rst(servers)
    finally:
        close_renderer()

    _remove_stale_rst(BBS_DETAIL_PATH,
                      {s['_bbs_file'] for s in servers})
    _remove_stale_rst(DETAIL_PATH,
                      {s['fingerprint'] for s in servers})

    print("Done. Run sphinx-build to generate HTML.",
          file=sys.stderr)
