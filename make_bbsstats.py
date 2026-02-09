#!/usr/bin/env python
"""Generate RST documentation and matplotlib plots from BBS server fingerprint data.

Reads JSON session files from telnetlib3's data directory and produces:
- docs/statistics.rst: summary stats and plots
- docs/server_list.rst: searchable server table
- docs/fingerprints.rst: fingerprint summary with links to detail pages
- docs/servers.rst: index of per-BBS detail pages
- docs/server_detail/*.rst: per-fingerprint detail pages
- docs/bbs_detail/*.rst: per-BBS detail pages
- docs/_static/plots/*.png: matplotlib charts
"""

import argparse
import contextlib
import json
import os
import re
import sys
import textwrap
from collections import Counter
from datetime import datetime
from pathlib import Path

import bbs_encodings  # noqa: F401 -- registers cp437_art, amiga, etc.

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import tabulate as tabulate_mod
import wcwidth
from ansi2html import Ansi2HTMLConverter

_ANSI_CONV = Ansi2HTMLConverter(inline=True, dark_bg=True, scheme='xterm')

DOCS_PATH = os.path.join(os.path.dirname(__file__), "docs-bbs")
PLOTS_PATH = os.path.join(DOCS_PATH, "_static", "plots")
STATIC_PATH = os.path.join(DOCS_PATH, "_static")
DETAIL_PATH = os.path.join(DOCS_PATH, "server_detail")
BBS_DETAIL_PATH = os.path.join(DOCS_PATH, "bbs_detail")
LINK_REGEX = re.compile(r'[^a-zA-Z0-9]')
_URL_RE = re.compile(r'https?://[^\s<>"\']+')
GITHUB_DATA_BASE = ("https://github.com/jquast/modem.xyz"
                     "/tree/master/data-bbs/server")

# Default encoding assumed for all BBSes unless overridden
DEFAULT_ENCODING = 'cp437'

# Telnet options we care about for display
TELNET_OPTIONS_OF_INTEREST = [
    'BINARY', 'ECHO', 'SGA', 'STATUS', 'TTYPE', 'TSPEED',
    'NAWS', 'NEW_ENVIRON', 'CHARSET', 'EOR', 'LINEMODE',
    'SNDLOC', 'COM_PORT', 'TLS', 'ENCRYPT', 'AUTHENTICATION',
]

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
    (re.compile(r'Remote\s*Access', re.IGNORECASE), 'RemoteAccess'),
    (re.compile(r'Oblivion/?2|Obv/?2', re.IGNORECASE), 'Oblivion/2'),
    (re.compile(r'MBBS|Major\s*BBS', re.IGNORECASE), 'MajorBBS'),
    (re.compile(r'TBBS|TriBBS', re.IGNORECASE), 'TriBBS'),
    (re.compile(r'EleBBS', re.IGNORECASE), 'EleBBS'),
    (re.compile(r'Iniquity', re.IGNORECASE), 'Iniquity'),
    (re.compile(r'Citadel', re.IGNORECASE), 'Citadel'),
    (re.compile(r'TAG\s*BBS', re.IGNORECASE), 'TAG BBS'),
    (re.compile(r'Hermes\s*II?', re.IGNORECASE), 'Hermes'),
    (re.compile(r'SBBS', re.IGNORECASE), 'SBBS'),
]

# Plot styling (muted palette, transparent background)
PLOT_BG = 'none'
PLOT_FG = '#999999'
PLOT_GREEN = '#66AA66'
PLOT_CYAN = '#6699AA'
PLOT_YELLOW = '#AA9955'
PLOT_BLUE = '#6666AA'
PLOT_GRID = '#444444'


def _parse_server_list(path):
    """Parse a server list file into a set of (host, port) tuples.

    :param path: path to server list file (host port [encoding])
    :returns: set of (host, port_int) tuples
    """
    result = set()
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    result.add((parts[0], int(parts[1])))
                except ValueError:
                    pass
    return result


def _remove_stale_rst(dirpath, expected_stems):
    """Remove .rst files from *dirpath* not in *expected_stems*.

    :param dirpath: directory containing .rst files
    :param expected_stems: set of filename stems (without .rst) to keep
    """
    if not os.path.isdir(dirpath):
        return
    removed = 0
    for fname in os.listdir(dirpath):
        if fname.endswith('.rst'):
            stem = fname[:-4]
            if stem not in expected_stems:
                os.remove(os.path.join(dirpath, fname))
                removed += 1
    if removed:
        print(f"  removed {removed} stale .rst from {dirpath}",
              file=sys.stderr)


def make_link(text):
    """Convert text to a valid RST link target."""
    return LINK_REGEX.sub('_', text.lower())


def _listify(value):
    """Ensure value is a list."""
    if isinstance(value, list):
        return value
    return [value] if value else []


def _first_str(value):
    """Return the first string from a value that may be a list."""
    if isinstance(value, list):
        return value[0] if value else ''
    return value or ''


def _parse_int(value):
    """Parse an integer from a string, returning None on failure."""
    if isinstance(value, list):
        value = value[0] if value else ''
    if not value:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _format_scan_time(iso_str):
    """Format an ISO 8601 timestamp as 'YYYY-MM-DD at HH:MM UTC'.

    :param iso_str: ISO 8601 datetime string
    :returns: formatted string, or '' if unparseable
    """
    if not iso_str:
        return ''
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime('%Y-%m-%d at %H:%M UTC')
    except (ValueError, TypeError):
        return ''


def _needs_rebuild(output_path, *source_paths):
    """Check if output file needs rebuilding based on source file mtimes.

    :param output_path: path to the output file
    :param source_paths: paths to source files
    :returns: True if output is missing or older than any source or this script
    """
    if not os.path.isfile(output_path):
        return True
    out_mtime = os.path.getmtime(output_path)
    for src in (*source_paths, __file__):
        if src and os.path.isfile(src) and os.path.getmtime(src) > out_mtime:
            return True
    return False


_RST_SECTION_RE = re.compile(r'([=\-~#+^"]{4,})')


def _rst_escape(text):
    """Escape text for safe RST inline use."""
    if not text:
        return ''
    result = (text.replace('\\', '\\\\').replace('`', '\\`')
              .replace('*', '\\*').replace('|', '\\|'))
    # Break up runs of RST section/transition characters (=-~#+^") so
    # docutils does not interpret them as headings or transitions.
    result = _RST_SECTION_RE.sub(lambda m: m.group(0)[0] + '\u200B' + m.group(0)[1:], result)
    if result.endswith('_'):
        result = result[:-1] + '\\_'
    return result


def _strip_ansi(text):
    """Remove ANSI escape sequences from text."""
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def _is_garbled(text, threshold=0.3):
    """Detect text that is mostly Unicode replacement characters.

    :param text: text to check
    :param threshold: fraction of visible chars that are U+FFFD to be garbled
    :returns: True if text appears to be garbled
    """
    visible = _strip_ansi(text).replace('\r', '').replace('\n', '')
    if not visible:
        return False
    return visible.count('\ufffd') / len(visible) > threshold


def _strip_mxp_sgml(text):
    """Remove MXP/SGML protocol artifacts from banner text.

    :param text: banner text possibly containing MXP/SGML
    :returns: cleaned text
    """
    text = re.sub(r'\x1b\[\d+z', '', text)
    text = re.sub(r'<!--.*?-->', '', text)
    text = re.sub(r'<!(ELEMENT|ATTLIST|ENTITY)\b.*', '', text, flags=re.DOTALL)
    return text.rstrip()


def _clean_log_line(line, width=130):
    """Wrap long log lines.

    :param line: raw log line
    :param width: maximum line width for wrapping
    :returns: list of wrapped output lines
    """
    if not line:
        return ['']
    return textwrap.wrap(
        line,
        width=width,
        subsequent_indent='    ',
        break_long_words=True,
        break_on_hyphens=False,
    )


def _redecode_banner(text, from_encoding, to_encoding):
    """Re-decode banner text from one encoding to another.

    When the scanner decoded bytes using the wrong encoding, this attempts
    to reverse the decode and re-decode with the correct one.

    :param text: decoded banner string
    :param from_encoding: encoding the scanner used
    :param to_encoding: correct encoding to use
    :returns: re-decoded text, or original text if conversion fails
    """
    if not text or from_encoding == to_encoding:
        return text
    try:
        raw = text.encode(from_encoding, errors='surrogateescape')
        return raw.decode(to_encoding, errors='replace')
    except (UnicodeDecodeError, UnicodeEncodeError, LookupError):
        return text


def _combine_banners(server):
    """Combine banner_before and banner_after when they contain unique content.

    If an encoding override is set and differs from the scanner's detected
    encoding, attempt to re-decode the banner with the correct encoding.

    :param server: server record dict
    :returns: combined banner text
    """
    banner_before = (server['banner_before'] or '').replace('\ufffd', '')
    banner_after = (server['banner_after'] or '').replace('\ufffd', '')

    # Re-decode if encoding override differs from scanner encoding
    effective_enc = server.get('encoding_override') or DEFAULT_ENCODING
    scanner_enc = server.get('encoding', 'ascii')
    if effective_enc != scanner_enc and scanner_enc in ('ascii', 'utf-8', 'unknown'):
        banner_before = _redecode_banner(banner_before, scanner_enc, effective_enc)
        banner_after = _redecode_banner(banner_after, scanner_enc, effective_enc)

    before_clean = _strip_mxp_sgml(_strip_ansi(banner_before)).strip()
    after_clean = _strip_mxp_sgml(_strip_ansi(banner_after)).strip()
    if before_clean and after_clean and after_clean not in before_clean:
        return banner_before.rstrip() + '\r\n' + banner_after.lstrip()
    return banner_before or banner_after


def _truncate(text, maxlen=200):
    """Truncate text to maxlen characters, filtering non-printable bytes."""
    text = _strip_ansi(text)
    text = text.replace('\r\n', '\n').replace('\n\r', '\n').replace('\r', '\n')
    text = ''.join(
        c for c in text
        if c == '\n' or (c.isprintable() and ord(c) < 0xFFFD)
    )
    if len(text) > maxlen:
        return text[:maxlen] + '...'
    return text


def _banner_to_html(text, maxlen=5000, maxlines=250, name=''):
    """Convert ANSI banner text to inline-styled HTML.

    :param text: raw banner text with possible ANSI escape sequences
    :param maxlen: maximum character length after stripping ANSI for truncation
    :param maxlines: maximum number of lines to include
    :param name: server name for the aria-label attribute
    :returns: HTML string suitable for ``.. raw:: html`` embedding
    """
    import html as html_mod

    text = text.replace('\r\n', '\n').replace('\n\r', '\n').replace('\r', '\n')
    text = _strip_mxp_sgml(text)
    # Strip DEC private mode sequences (e.g. \x1b[?1000h mouse tracking)
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)
    cleaned = []
    i = 0
    while i < len(text):
        if text[i] == '\x1b':
            j = i + 1
            while j < len(text) and not text[j].isalpha():
                j += 1
            if j < len(text):
                j += 1
            cleaned.append(text[i:j])
            i = j
        elif text[i] == '\n' or (text[i].isprintable() and ord(text[i]) < 0xFFFD):
            cleaned.append(text[i])
            i += 1
        else:
            i += 1
    text = ''.join(cleaned)

    lines = text.split('\n')[:maxlines]
    text = '\n'.join(lines)

    visible_len = len(_strip_ansi(text))
    if visible_len > maxlen:
        result = []
        count = 0
        i = 0
        while i < len(text) and count < maxlen:
            if text[i] == '\x1b':
                j = i + 1
                while j < len(text) and not text[j].isalpha():
                    j += 1
                if j < len(text):
                    j += 1
                result.append(text[i:j])
                i = j
            else:
                result.append(text[i])
                count += 1
                i += 1
        text = ''.join(result) + '\x1b[0m...'

    wrapped_lines = []
    for line in text.split('\n'):
        wrapped = wcwidth.wrap(
            line, width=80, drop_whitespace=False,
            break_long_words=True, break_on_hyphens=False,
        )
        wrapped_lines.extend(wrapped if wrapped else [''])
    text = '\n'.join(wrapped_lines)

    html_content = _ANSI_CONV.convert(text, full=False)
    aria_name = html_mod.escape(name or 'BBS')
    return (f'<pre class="ansi-banner" role="img"'
            f' aria-label="ANSI art banner for {aria_name}">'
            f'{html_content}</pre>')


def _rst_heading(title, char):
    """Print an RST section heading with the given underline character."""
    print(title)
    print(char * max(len(title), 4))
    print()


def _telnet_url(host, port):
    """Build a telnet:// URL string.

    :param host: hostname
    :param port: port number
    :returns: telnet URL, omitting port if default (23)
    """
    if port == 23:
        return f"telnet://{host}"
    return f"telnet://{host}:{port}"


def _bbs_filename(server):
    """Generate a unique, filesystem-safe filename for a BBS detail page.

    :param server: server record dict
    :returns: sanitized filename string (without .rst extension)
    """
    host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', server['host'])
    return f"{host_safe}_{server['port']}"


def _group_shared_ip(servers):
    """Group servers sharing the same resolved IP address.

    Servers with the same non-empty IP are grouped for a combined detail
    page.  Groups with only one member are excluded -- those servers get
    standalone pages.

    :param servers: list of deduplicated server records
    :returns: dict mapping IP address string to list of servers,
              only for groups with 2+ members
    """
    by_ip = {}
    for s in servers:
        ip = s['ip']
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(s)

    return {
        ip: sorted(members, key=lambda s: (s['host'], s['port']))
        for ip, members in by_ip.items()
        if len(members) >= 2
    }


def _most_common_hostname(group_servers):
    """Return the most common hostname among grouped servers.

    :param group_servers: list of server records sharing an IP
    :returns: most frequent hostname string
    """
    counts = Counter(s['host'] for s in group_servers)
    return counts.most_common(1)[0][0]


def _assign_bbs_filenames(servers, ip_groups):
    """Assign ``_bbs_file`` and ``_bbs_toc_label`` to each server.

    Grouped servers share an IP-based filename.  Ungrouped servers use
    the ``host_port`` format from :func:`_bbs_filename`.

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
            grouped_keys[(s['host'], s['port'])] = (filename, toc_label)

    for s in servers:
        key = (s['host'], s['port'])
        if key in grouped_keys:
            s['_bbs_file'], s['_bbs_toc_label'] = grouped_keys[key]
        else:
            s['_bbs_file'] = _bbs_filename(s)
            s['_bbs_toc_label'] = f"{s['host']}:{s['port']}"


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


def load_server_data(data_dir, encoding_overrides=None):
    """Load all server fingerprint JSON files from the data directory.

    :param data_dir: path to telnetlib3 data directory
    :param encoding_overrides: dict mapping (host, port) to encoding string
    :returns: list of parsed server record dicts
    """
    if encoding_overrides is None:
        encoding_overrides = {}

    server_dir = os.path.join(data_dir, "server")
    if not os.path.isdir(server_dir):
        print(f"Error: {server_dir} is not a directory", file=sys.stderr)
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
            host = session.get('host', session.get('ip', 'unknown'))
            port = session.get('port', 0)

            record = {
                'host': host,
                'ip': session.get('ip', ''),
                'port': port,
                'connected': session.get('connected', ''),
                'fingerprint': probe.get('fingerprint', fp_dir),
                'data_path': f"{fp_dir}/{fname}",
                'offered': fp_data.get('offered-options', []),
                'requested': fp_data.get('requested-options', []),
                'refused': fp_data.get('refused-options', []),
                'server_offered': option_states.get('server_offered', {}),
                'server_requested': option_states.get('server_requested', {}),
                'encoding': session_data.get('encoding', 'unknown'),
                'encoding_override': encoding_overrides.get(
                    (host, port), ''),
                'banner_before': session_data.get('banner_before_return', ''),
                'banner_after': session_data.get('banner_after_return', ''),
                'timing': session_data.get('timing', {}),
            }

            # Detect BBS software from banner
            banner = _combine_banners(record)
            record['bbs_software'] = detect_bbs_software(banner)

            # Extract URL from banner text
            record['website'] = ''
            for banner_key in ('banner_before', 'banner_after'):
                banner_text = record[banner_key]
                if banner_text:
                    match = _URL_RE.search(_strip_ansi(banner_text))
                    if match:
                        record['website'] = match.group(0)
                        break

            # Detect TLS support from telnet negotiation
            offered = set(record['offered'])
            requested = set(record['requested'])
            record['tls_support'] = 'TLS' in offered or 'TLS' in requested

            records.append(record)

    return records


def deduplicate_servers(records):
    """Deduplicate by host:port, keeping the most recent session.

    :param records: list of server record dicts
    :returns: deduplicated list sorted by host
    """
    by_host_port = {}
    for rec in records:
        key = (rec['host'], rec['port'])
        existing = by_host_port.get(key)
        if existing is None or rec['connected'] > existing['connected']:
            by_host_port[key] = rec
    return sorted(by_host_port.values(), key=lambda r: r['host'].lower())


def compute_statistics(servers):
    """Compute aggregate statistics from server list.

    :param servers: list of deduplicated server records
    :returns: dict of statistics
    """
    connected_times = sorted(s['connected'] for s in servers if s['connected'])
    stats = {
        'total_servers': len(servers),
        'unique_fingerprints': len(set(s['fingerprint'] for s in servers)),
        'scan_time_first': connected_times[0] if connected_times else '',
        'scan_time_last': connected_times[-1] if connected_times else '',
    }

    # BBS software counts
    software_counts = Counter()
    for s in servers:
        if s['bbs_software']:
            software_counts[s['bbs_software']] += 1
    stats['bbs_software_counts'] = dict(software_counts)
    stats['bbs_software_detected'] = sum(software_counts.values())

    # Encoding distribution
    encoding_counts = Counter()
    for s in servers:
        enc = s.get('encoding_override') or DEFAULT_ENCODING
        encoding_counts[enc] += 1
    stats['encoding_counts'] = dict(encoding_counts)

    # Telnet option statistics
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


# -- Plot generation -------------------------------------------------------

def _setup_plot_style():
    """Configure matplotlib for muted, transparent-background plots."""
    plt.rcParams.update({
        'figure.facecolor': PLOT_BG,
        'axes.facecolor': PLOT_BG,
        'axes.edgecolor': PLOT_FG,
        'axes.labelcolor': PLOT_FG,
        'text.color': PLOT_FG,
        'xtick.color': PLOT_FG,
        'ytick.color': PLOT_FG,
        'grid.color': PLOT_GRID,
        'grid.alpha': 0.5,
        'legend.facecolor': PLOT_BG,
        'legend.edgecolor': PLOT_FG,
        'savefig.facecolor': PLOT_BG,
        'savefig.edgecolor': PLOT_BG,
        'savefig.transparent': True,
    })


def _group_small_slices(labels, counts, threshold=0.01, min_count=None):
    """Group pie slices into 'Other'.

    :param labels: list of label strings
    :param counts: list of corresponding counts
    :param threshold: fraction of total at or below which slices are grouped
    :param min_count: absolute count at or below which slices are grouped
    :returns: (labels, counts) with small entries merged into 'Other'
    """
    total = sum(counts)
    if total == 0:
        return labels, counts
    keep_labels, keep_counts = [], []
    other = 0
    for label, count in zip(labels, counts):
        if min_count is not None and count <= min_count:
            other += count
        elif min_count is None and count / total <= threshold:
            other += count
        else:
            keep_labels.append(label)
            keep_counts.append(count)
    if other > 0:
        keep_labels.append('Other')
        keep_counts.append(other)
    return keep_labels, keep_counts


def _pie_colors(n, labels=None):
    """Return *n* distinct muted colors for pie slices.

    :param n: number of colors needed
    :param labels: optional list of labels; 'Other' gets forced to grey
    """
    palette = [
        PLOT_GREEN, PLOT_CYAN, PLOT_YELLOW, PLOT_BLUE,
        '#AA6666', '#AA66AA', '#66AAAA', '#AAAA66',
        '#66AA66', '#6666AA', '#8866AA', '#AA8866',
        '#66AA88', '#AA6688', '#88AA66', '#886688',
    ]
    colors = [palette[i % len(palette)] for i in range(n)]
    if labels is not None:
        for i, label in enumerate(labels):
            if label == 'Other':
                colors[i] = '#888888'
    return colors


def create_bbs_software_plot(stats, output_path):
    """Create pie chart of BBS software distribution."""
    software_counts = stats['bbs_software_counts']
    if not software_counts:
        return

    sorted_items = sorted(software_counts.items(), key=lambda x: x[1],
                          reverse=True)
    labels = [s for s, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(labels, counts, min_count=1)
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

    ax.legend(wedges, [f'{l} ({c})' for l, c in zip(labels, counts)],
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

    sorted_items = sorted(encoding_counts.items(), key=lambda x: x[1],
                          reverse=True)
    labels = [e for e, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(labels, counts, min_count=1)
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

    ax.legend(wedges, [f'{l} ({c})' for l, c in zip(labels, counts)],
              loc='center left', bbox_to_anchor=(1, 0.5),
              fontsize=9, facecolor='none', edgecolor=PLOT_FG,
              labelcolor=PLOT_FG)

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_telnet_options_plot(stats, output_path):
    """Create grouped bar chart of telnet option negotiation patterns."""
    offered = stats['option_offered']
    requested = stats['option_requested']

    all_opts = set()
    for opt in TELNET_OPTIONS_OF_INTEREST:
        if offered.get(opt, 0) > 0 or requested.get(opt, 0) > 0:
            all_opts.add(opt)
    for opt, count in offered.items():
        if count >= 3:
            all_opts.add(opt)
    for opt, count in requested.items():
        if count >= 3:
            all_opts.add(opt)

    if not all_opts:
        return

    options = sorted(all_opts,
                     key=lambda o: offered.get(o, 0) + requested.get(o, 0),
                     reverse=True)
    offered_counts = [offered.get(o, 0) for o in options]
    requested_counts = [requested.get(o, 0) for o in options]

    x = np.arange(len(options))
    width = 0.35

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, offered_counts, width, label='Server Offers',
           color=PLOT_GREEN, edgecolor='#222222', alpha=0.85)
    ax.bar(x + width / 2, requested_counts, width, label='Server Requests',
           color=PLOT_CYAN, edgecolor='#222222', alpha=0.85)

    ax.set_xlabel('Telnet Option', fontsize=12)
    ax.set_ylabel('Number of Servers', fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels(options, rotation=45, ha='right', fontsize=9)
    ax.legend(facecolor='none', edgecolor=PLOT_FG, labelcolor=PLOT_FG)
    ax.grid(True, axis='y')

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


# -- RST generation --------------------------------------------------------

def print_datatable(table_str, caption=None):
    """Print RST table with sphinx-datatable class."""
    if caption:
        print(f".. table:: {caption}")
    else:
        print(".. table::")
    print("   :class: sphinx-datatable")
    print()
    for line in table_str.split('\n'):
        if line.strip():
            print(f"   {line}")
        else:
            print()
    print()


def display_summary_stats(stats):
    """Print summary statistics section."""
    print("Statistics")
    print("==========")
    print()
    scan_date = datetime.now().strftime('%Y-%m-%d')
    print(f"*Data collected {scan_date}*")
    print()
    print(f"- **BBSes responding**: {stats['total_servers']}")
    print(f"- **Unique protocol fingerprints**: {stats['unique_fingerprints']}")
    if stats['bbs_software_detected']:
        print(f"- **BBS software detected**: {stats['bbs_software_detected']}"
              f" ({len(stats['bbs_software_counts'])} unique packages)")
    print()
    print("These statistics reflect the most recent scan of all servers in the")
    print("`bbslist.txt "
          "<https://github.com/jquast/bbs.modem.xyz/blob/master/"
          "data/bbslist.txt>`_ input list.")
    print("Each server is probed using `telnetlib3 "
          "<https://github.com/jquast/telnetlib3>`_,")
    print("which connects to each address, performs Telnet option negotiation,")
    print("and captures the login banner.")
    print()


def display_plots():
    """Print figure directives for all plots."""
    print("The charts below summarize data from all responding servers.")
    print()

    print("BBS Software")
    print("-------------")
    print()
    print(".. figure:: _static/plots/bbs_software.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the distribution of detected BBS"
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
    print("   :alt: Pie chart showing the distribution of character"
          " encodings across all servers.")
    print()
    print("   Character encoding distribution (default: CP437).")
    print()

    print("Telnet Option Negotiation")
    print("--------------------------")
    print()
    print(".. figure:: _static/plots/telnet_options.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Grouped bar chart comparing how many servers offer"
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
    print("All servers that responded to a Telnet connection during the most")
    print("recent scan. Click a column header to sort. Use the search box to")
    print("filter by host, software, or encoding.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Host**")
    print("     - Hostname and port. Links to a detail page with banner,"
          " fingerprint, and connection log.")
    print("   * - **Software**")
    print("     - BBS software detected from the login banner"
          " (e.g. Synchronet, Mystic BBS).")
    print("   * - **Encoding**")
    print("     - Character encoding. Defaults to CP437 unless overridden"
          " in bbslist.txt.")
    print("   * - **Fingerprint**")
    print("     - Truncated hash of the server's Telnet option negotiation"
          " behavior.")
    print("   * - **Banner**")
    print("     - First line of the server's login banner text.")
    print()

    rows = []
    for s in servers:
        bbs_file = s['_bbs_file']
        host_display = f"{s['host']}:{s['port']}"
        host_cell = f":doc:`{_rst_escape(host_display)} <bbs_detail/{bbs_file}>`"
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

        banner = _combine_banners(s)
        banner_excerpt = _truncate(banner, maxlen=60).split('\n')[0] if banner else ''

        rows.append({
            'Host': host_cell,
            'Software': _rst_escape(software),
            'Encoding': encoding,
            'Fingerprint': f':ref:`{fp} <fp_{s["fingerprint"]}>`',
            'Banner': _rst_escape(banner_excerpt[:50]),
        })

    table_str = tabulate_mod.tabulate(rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="BBS Servers")


def display_fingerprint_summary(servers):
    """Print summary table of protocol fingerprints."""
    print("Fingerprints")
    print("============")
    print()
    print("A fingerprint is a hash of a server's Telnet option negotiation")
    print("behavior -- which options it offers to the client, which it requests")
    print("from the client, and which it refuses. Servers running the same"
          " software")
    print("version typically produce identical fingerprints. A majority of"
          " servers")
    print("perform no negotiation at all and share the same empty fingerprint.")
    print()
    print("Click a fingerprint link to see the full negotiation details and all")
    print("servers in that group.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Fingerprint**")
    print("     - Truncated hash identifying the negotiation pattern."
          " Click to see the full detail page.")
    print("   * - **Servers**")
    print("     - Number of servers sharing this exact negotiation behavior.")
    print("   * - **Offers**")
    print("     - Telnet options the server offers"
          " (WILL) to the client during negotiation.")
    print("   * - **Requests**")
    print("     - Telnet options the server requests (DO) from the client.")
    print("   * - **Examples**")
    print("     - Sample server addresses sharing this fingerprint.")
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
        requested = ', '.join(fp_servers[0]['requested']) or 'none'
        server_addrs = ', '.join(
            f"{s['host']}:{s['port']}" for s in fp_servers[:3]
        )
        if len(fp_servers) > 3:
            server_addrs += f', ... (+{len(fp_servers) - 3})'

        rows.append({
            'Fingerprint': f':ref:`{fp[:16]}... <fp_{fp}>`',
            'Servers': str(len(fp_servers)),
            'Offers': _rst_escape(offered[:30]),
            'Requests': _rst_escape(requested[:30]),
            'Examples': _rst_escape(server_addrs[:50]),
        })

    table_str = tabulate_mod.tabulate(rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="Protocol Fingerprints")

    print()
    print(".. toctree::")
    print("   :maxdepth: 1")
    print("   :hidden:")
    print()
    for fp in sorted(by_fp.keys()):
        print(f"   server_detail/{fp}")
    print()


def generate_summary_rst(stats):
    """Generate the statistics.rst file with stats and plots."""
    rst_path = os.path.join(DOCS_PATH, "statistics.rst")
    with open(rst_path, 'w') as fout, contextlib.redirect_stdout(fout):
        display_summary_stats(stats)
        display_plots()
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_server_list_rst(servers):
    """Generate the server_list.rst file with the main server table."""
    rst_path = os.path.join(DOCS_PATH, "server_list.rst")
    with open(rst_path, 'w') as fout, contextlib.redirect_stdout(fout):
        display_server_table(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_fingerprints_rst(servers):
    """Generate the fingerprints.rst file with fingerprint summary."""
    rst_path = os.path.join(DOCS_PATH, "fingerprints.rst")
    with open(rst_path, 'w') as fout, contextlib.redirect_stdout(fout):
        display_fingerprint_summary(servers)
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_details_rst(servers):
    """Generate the servers.rst index page with toctree to per-BBS pages."""
    rst_path = os.path.join(DOCS_PATH, "servers.rst")
    with open(rst_path, 'w') as fout, contextlib.redirect_stdout(fout):
        print("Servers")
        print("=======")
        print()
        print("Individual detail pages for each BBS scanned in this")
        print("census. Each page shows the server's ANSI login banner,")
        print("detected encoding, BBS software (if identified),")
        print("fingerprint data, the raw JSON scan record, and the")
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
            print(f"   {_rst_escape(label)} <bbs_detail/{bbs_file}>")
        print()
    print(f"  wrote {rst_path}", file=sys.stderr)


def _write_bbs_port_section(server, sec_char, logs_dir=None,
                             data_dir=None, fp_counts=None):
    """Write the detail content sections for one BBS port.

    Used by :func:`generate_bbs_detail_group` to emit each port's
    content at a lower heading level than a standalone page.

    :param server: server record dict
    :param sec_char: RST underline character for section headings
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    host = server['host']
    port = server['port']
    title = f"{host}:{port}"

    # Banner
    banner = _combine_banners(server)
    if banner and not _is_garbled(banner):
        banner_html = _banner_to_html(banner, name=title)
        print(".. raw:: html")
        print()
        for line in banner_html.split('\n'):
            print(f"   {line}")
        print()
    elif banner:
        print("*Banner not shown (legacy encoding not supported).*")
        print()

    # Connection info with telnet link
    url = _telnet_url(host, port)
    print(f".. raw:: html")
    print()
    print(f'   <p class="mud-connect">')
    print(f'   <a href="{url}" class="telnet-link">{host}:{port}</a>')
    print(f'   <button class="copy-btn" data-host="{host}"'
          f' data-port="{port}"'
          f' title="Copy host and port"'
          f' aria-label="Copy {host} port {port} to clipboard">')
    print(f'   <span class="copy-icon" aria-hidden="true">'
          f'&#x2398;</span>')
    print(f'   </button>')
    if server['tls_support']:
        print(f'   <span class="tls-lock" title="Supports TLS">'
              f'&#x1f512;</span>')
    print(f'   </p>')
    print()

    # BBS software
    if server['bbs_software']:
        _rst_heading("BBS Software", sec_char)
        print(f"**Detected**: {_rst_escape(server['bbs_software'])}")
        print()

    # Encoding info
    effective_enc = server.get('encoding_override') or DEFAULT_ENCODING
    scanner_enc = server.get('encoding', 'unknown')
    _rst_heading("Encoding", sec_char)
    print(f"- **Effective encoding**: {effective_enc}")
    if server.get('encoding_override'):
        print(f"- **Override**: {server['encoding_override']}"
              " (from bbslist.txt)")
    print(f"- **Scanner detected**: {scanner_enc}")
    print()

    # Website link if found
    if server['website']:
        href = server['website']
        if not href.startswith(('http://', 'https://')):
            href = f'http://{href}'
        print(f"**Website**: `{_rst_escape(server['website'])}"
              f" <{href}>`_")
        print()

    # Fingerprint link
    fp = server['fingerprint']
    _rst_heading("Telnet Fingerprint", sec_char)
    print(f":ref:`{fp[:16]}... <fp_{fp}>`")
    print()
    if fp_counts:
        other_count = fp_counts.get(fp, 1) - 1
        if other_count > 0:
            print(f"*This fingerprint is shared by {other_count} other "
                  f"{'server' if other_count == 1 else 'servers'}.*")
        else:
            print("*This fingerprint is unique to this server.*")
        print()
    if server['offered']:
        print("**Options offered by server**: "
              + ', '.join(
                  f"``{o}``" for o in sorted(server['offered'])))
        print()
    if server['requested']:
        print("**Options requested from client**: "
              + ', '.join(
                  f"``{o}``" for o in sorted(server['requested'])))
        print()

    # Raw JSON data source
    data_path = server.get('data_path', '')
    if data_path and data_dir:
        json_file = os.path.join(data_dir, "server", data_path)
        github_url = f"{GITHUB_DATA_BASE}/{data_path}"
        print(f"**Data source**: `{data_path} <{github_url}>`_")
        print()
        print("The complete JSON record collected during the scan,")
        print("including Telnet negotiation results and banner data.")
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

    # Connection log
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
    :param logs_dir: path to directory containing per-host:port .log files
    :param force: if True, skip mtime checks
    :param data_dir: path to telnetlib3 data directory for mtime checks
    :param fp_counts: dict mapping fingerprint hash to server count
    """
    bbs_file = server['_bbs_file']
    detail_path = os.path.join(BBS_DETAIL_PATH, f"{bbs_file}.rst")

    if not force and data_dir:
        json_path = os.path.join(
            data_dir, "server", server.get('data_path', ''))
        log_path = (os.path.join(
            logs_dir, f"{server['host']}:{server['port']}.log")
                    if logs_dir else None)
        if not _needs_rebuild(detail_path, json_path, log_path):
            return False

    host = server['host']
    port = server['port']
    title = f"{host}:{port}"

    with open(detail_path, 'w') as fout, contextlib.redirect_stdout(fout):
        escaped_title = _rst_escape(title)
        print(escaped_title)
        print("=" * max(len(escaped_title), 4))
        print()

        _write_bbs_port_section(
            server, '-', logs_dir=logs_dir, data_dir=data_dir,
            fp_counts=fp_counts)


def generate_bbs_detail_group(ip, group_servers, logs_dir=None,
                               data_dir=None, fp_counts=None):
    """Generate a combined detail page for BBSes sharing an IP.

    Each server gets its own sub-heading by ``hostname:port``, with all
    detail sections nested underneath.

    :param ip: shared IP address
    :param group_servers: list of server records sharing this IP
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    bbs_file = group_servers[0]['_bbs_file']
    detail_path = os.path.join(BBS_DETAIL_PATH, f"{bbs_file}.rst")
    hostname_hint = _most_common_hostname(group_servers)
    if hostname_hint == ip:
        display_name = ip
    else:
        display_name = f"{ip} ({hostname_hint})"

    with open(detail_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(display_name)
        print(escaped_name)
        print("=" * max(len(escaped_name), 4))
        print()

        for server in group_servers:
            host = server['host']
            port = server['port']
            sub_title = f"{host}:{port}"
            escaped_sub = _rst_escape(sub_title)
            print(escaped_sub)
            print("-" * max(len(escaped_sub), 4))
            print()

            _write_bbs_port_section(
                server, '~', logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts)


def generate_bbs_details(servers, logs_dir=None, force=False,
                          data_dir=None, ip_groups=None):
    """Generate all per-BBS detail pages.

    :param servers: list of server records
    :param logs_dir: path to directory containing per-host:port .log files
    :param force: if True, regenerate all files regardless of mtime
    :param data_dir: path to telnetlib3 data directory for mtime checks
    :param ip_groups: dict from :func:`_group_shared_ip`, or None
    """
    if force:
        _clean_dir(BBS_DETAIL_PATH)
    os.makedirs(BBS_DETAIL_PATH, exist_ok=True)

    fp_counts = Counter(s['fingerprint'] for s in servers)

    # Collect grouped server keys to skip in individual generation
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

    # Generate combined pages for grouped servers
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
              f" to {BBS_DETAIL_PATH} ({total - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} BBS detail pages to {BBS_DETAIL_PATH}",
              file=sys.stderr)


def generate_fingerprint_detail(fp_hash, fp_servers, force=False,
                                 data_dir=None):
    """Generate a detail page for one fingerprint group.

    :param fp_hash: fingerprint hash string
    :param fp_servers: list of server records sharing this fingerprint
    :param force: if True, skip mtime checks
    :param data_dir: path to telnetlib3 data directory for mtime checks
    """
    detail_path = os.path.join(DETAIL_PATH, f"{fp_hash}.rst")

    if not force and data_dir:
        source_paths = [
            os.path.join(data_dir, "server", s.get('data_path', ''))
            for s in fp_servers
        ]
        if not _needs_rebuild(detail_path, *source_paths):
            return False

    sample = fp_servers[0]

    with open(detail_path, 'w') as fout, contextlib.redirect_stdout(fout):
        print(f".. _fp_{fp_hash}:")
        print()
        title = f"{fp_hash[:16]}"
        print(title)
        print("=" * max(len(title), 4))
        print()

        print(f"**Full hash**: ``{fp_hash}``")
        print()
        print(f"**Servers sharing this fingerprint**: {len(fp_servers)}")
        print()

        # Telnet options detail
        print("Telnet Options")
        print("--------------")
        print()

        if sample['offered']:
            print("**Offered by server**: "
                  + ', '.join(
                      f"``{o}``" for o in sorted(sample['offered'])))
        else:
            print("**Offered by server**: none")
        print()

        if sample['requested']:
            print("**Requested from client**: "
                  + ', '.join(
                      f"``{o}``" for o in sorted(sample['requested'])))
        else:
            print("**Requested from client**: none")
        print()

        refused_display = [
            o for o in sorted(sample['refused'])
            if o in TELNET_OPTIONS_OF_INTEREST
        ]
        other_refused = len(sample['refused']) - len(refused_display)
        if refused_display:
            print("**Refused (notable)**: "
                  + ', '.join(f"``{o}``" for o in refused_display))
            if other_refused > 0:
                print(f"  *(and {other_refused} other standard options)*")
        print()

        # Option states
        negotiated_offered = {
            k: v for k, v in sample['server_offered'].items() if v
        }
        negotiated_requested = {
            k: v for k, v in sample['server_requested'].items() if v
        }
        if negotiated_offered or negotiated_requested:
            print("Negotiation Results")
            print("~~~~~~~~~~~~~~~~~~~")
            print()
            if negotiated_offered:
                print("**Server offered (accepted)**: "
                      + ', '.join(
                          f"``{o}``" for o in sorted(negotiated_offered)))
                print()
            if negotiated_requested:
                print("**Server requested (accepted)**: "
                      + ', '.join(
                          f"``{o}``" for o in sorted(negotiated_requested)))
                print()

        # Server list
        print("Servers")
        print("-------")
        print()

        for s in fp_servers:
            bbs_file = s['_bbs_file']
            label = f"{s['host']}:{s['port']}"
            tls = ' :tls-lock:`\U0001f512`' if s['tls_support'] else ''
            print(f":doc:`{_rst_escape(label)}"
                  f" <../bbs_detail/{bbs_file}>`{tls}")
            print()

            if s['bbs_software']:
                print(f"  - Software: {_rst_escape(s['bbs_software'])}")
            enc = s.get('encoding_override') or DEFAULT_ENCODING
            print(f"  - Encoding: {enc}")
            if s['website']:
                href = s['website']
                if not href.startswith(('http://', 'https://')):
                    href = f'http://{href}'
                print(f"  - Website: `{_rst_escape(s['website'])}"
                      f" <{href}>`_")
            print()

            # Banner excerpt
            banner = _combine_banners(s)
            if banner and not _is_garbled(banner):
                banner_html = _banner_to_html(
                    banner, maxlen=300, maxlines=10,
                    name=label)
                print("  .. raw:: html")
                print()
                for line in banner_html.split('\n'):
                    print(f"     {line}")
                print()


def _clean_dir(dirpath):
    """Remove all .rst files from a directory."""
    if os.path.isdir(dirpath):
        for fname in os.listdir(dirpath):
            if fname.endswith('.rst'):
                os.remove(os.path.join(dirpath, fname))


def generate_fingerprint_details(servers, force=False, data_dir=None):
    """Generate all fingerprint detail pages.

    :param servers: list of server records
    :param force: if True, regenerate all files regardless of mtime
    :param data_dir: path to telnetlib3 data directory for mtime checks
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
            fp_hash, fp_servers, force=force, data_dir=data_dir)
        if result is not False:
            rebuilt += 1

    if rebuilt < len(by_fp):
        print(f"  wrote {rebuilt}/{len(by_fp)} fingerprint detail pages"
              f" to {DETAIL_PATH} ({len(by_fp) - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} fingerprint detail pages to {DETAIL_PATH}",
              file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Generate BBS server statistics site from telnetlib3'
                    ' data.')
    parser.add_argument(
        '--data-dir',
        default=os.path.join(os.path.dirname(__file__), 'data-bbs'),
        help='Path to data directory (default: ./data-bbs)')
    parser.add_argument(
        '--logs-dir',
        default=os.path.join(os.path.dirname(__file__), 'logs'),
        help='Path to scan log directory (default: ./logs)')
    parser.add_argument(
        '--bbslist',
        default=os.path.join(os.path.dirname(__file__), 'data-bbs', 'bbslist.txt'),
        help='Path to bbslist.txt for encoding overrides')
    parser.add_argument(
        '--force', action='store_true',
        help='Regenerate all RST files, ignoring mtime checks')
    args = parser.parse_args()

    data_dir = os.path.abspath(args.data_dir)
    logs_dir = os.path.abspath(args.logs_dir)
    if os.path.isdir(logs_dir):
        print(f"Using logs from {logs_dir}", file=sys.stderr)
    else:
        logs_dir = None

    # Load encoding overrides from bbslist.txt
    encoding_overrides = load_bbslist_encodings(args.bbslist)
    if encoding_overrides:
        print(f"Loaded {len(encoding_overrides)} encoding overrides"
              f" from {args.bbslist}", file=sys.stderr)

    print(f"Loading data from {data_dir} ...", file=sys.stderr)
    records = load_server_data(data_dir, encoding_overrides)
    print(f"  loaded {len(records)} session records", file=sys.stderr)

    servers = deduplicate_servers(records)
    print(f"  {len(servers)} unique servers after deduplication",
          file=sys.stderr)

    listed = _parse_server_list(args.bbslist)
    servers = [s for s in servers if (s['host'], s['port']) in listed]
    print(f"  {len(servers)} servers after filtering by {args.bbslist}",
          file=sys.stderr)

    ip_groups = _group_shared_ip(servers)
    _assign_bbs_filenames(servers, ip_groups)
    if ip_groups:
        n_groups = len(ip_groups)
        n_combined = sum(len(m) for m in ip_groups.values())
        print(f"  {n_groups} IP groups ({n_combined} servers combined)",
              file=sys.stderr)

    stats = compute_statistics(servers)

    # Generate plots
    print("Generating plots ...", file=sys.stderr)
    create_all_plots(stats)
    print(f"  wrote plots to {PLOTS_PATH}", file=sys.stderr)

    # Generate RST pages
    print("Generating RST ...", file=sys.stderr)
    generate_summary_rst(stats)
    generate_server_list_rst(servers)
    generate_fingerprints_rst(servers)
    generate_details_rst(servers)
    generate_bbs_details(servers, logs_dir=logs_dir,
                          force=args.force, data_dir=data_dir,
                          ip_groups=ip_groups)
    generate_fingerprint_details(servers, force=args.force,
                                  data_dir=data_dir)

    _remove_stale_rst(BBS_DETAIL_PATH,
                      {s['_bbs_file'] for s in servers})
    _remove_stale_rst(DETAIL_PATH,
                      {s['fingerprint'] for s in servers})

    print("Done. Run sphinx-build to generate HTML.", file=sys.stderr)


if __name__ == '__main__':
    main()
