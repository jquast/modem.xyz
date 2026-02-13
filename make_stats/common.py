"""Shared utilities for MUD and BBS statistics generation."""

import contextlib
import hashlib
import html
import os
import re
import sys
import textwrap
from collections import Counter
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import tabulate as tabulate_mod  # noqa: E402
import wcwidth  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINK_REGEX = re.compile(r'[^a-zA-Z0-9]')
_URL_RE = re.compile(r'https?://[^\s<>"\']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"\']*)?')
_RST_SECTION_RE = re.compile(r'([=\-~#+^"._]{4,})')
_SURROGATES_RE = re.compile(r'[\udc80-\udcff]')

TELNET_OPTIONS_OF_INTEREST = [
    'BINARY', 'ECHO', 'SGA', 'STATUS', 'TTYPE', 'TSPEED',
    'NAWS', 'NEW_ENVIRON', 'CHARSET', 'EOR', 'LINEMODE',
    'SNDLOC', 'COM_PORT', 'TLS', 'ENCRYPT', 'AUTHENTICATION',
]

# Plot styling (muted palette, transparent background)
PLOT_BG = 'none'
PLOT_FG = '#999999'
PLOT_GREEN = '#66AA66'
PLOT_CYAN = '#6699AA'
PLOT_YELLOW = '#AA9955'
PLOT_BLUE = '#6666AA'
PLOT_GRID = '#444444'


# Terminal rendering pool, initialized by init_renderer().
_renderer_pool = None


# ---------------------------------------------------------------------------
# Pure utilities
# ---------------------------------------------------------------------------

def make_link(text):
    """Convert text to a valid RST link target."""
    return LINK_REGEX.sub('_', text.lower())


def _listify(value):
    """Ensure value is a list (MSSP fields can be string or list)."""
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


def _load_encoding_overrides(path):
    """Load encoding overrides from a server list file.

    :param path: path to server list file (host port [encoding [columns]])
    :returns: dict mapping (host, port) to encoding string
    """
    overrides = {}
    if not os.path.isfile(path):
        return overrides
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides[(host, port)] = parts[2]
    return overrides


def _load_column_overrides(path):
    """Load column width overrides from a server list file.

    :param path: path to server list file (host port [encoding [columns]])
    :returns: dict mapping (host, port) to column width int
    """
    overrides = {}
    if not os.path.isfile(path):
        return overrides
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                host = parts[0]
                try:
                    port = int(parts[1])
                    columns = int(parts[3])
                except ValueError:
                    continue
                overrides[(host, port)] = columns
    return overrides


# ---------------------------------------------------------------------------
# Text processing
# ---------------------------------------------------------------------------

def _rst_escape(text):
    """Escape text for safe RST inline use."""
    if not text:
        return ''
    result = (text.replace('\\', '\\\\').replace('`', '\\`')
              .replace('*', '\\*').replace('|', '\\|'))
    result = _RST_SECTION_RE.sub(
        lambda m: m.group(0)[0] + '\u200B' + m.group(0)[1:], result)
    if result.endswith('_'):
        result = result[:-1] + '\\_'
    return result


def _strip_ansi(text):
    """Remove all terminal escape sequences from text."""
    return wcwidth.strip_sequences(text)


#def _rstrip_ansi_line(line, columns=80):
#    """Strip trailing visible whitespace from lines that would cause wrapping.
#
#    When libansilove renders a line whose visible width equals the column
#    count, the cursor auto-wraps and the following newline produces a
#    double-spaced blank line.  Detect this with :func:`wcwidth.wcswidth`
#    on the ANSI-stripped text and remove trailing whitespace + ANSI resets
#    when the visible width meets or exceeds *columns*.
#
#    :param line: single line of text, possibly containing ANSI escapes
#    :param columns: rendering column width (default 80)
#    :returns: line with trailing visible whitespace removed when needed
#    """
#    visible = _strip_ansi(line)
#    if wcwidth.wcswidth(visible) < columns:
#        return line
#    # Strip trailing whitespace and any surrounding ANSI SGR sequences
#    return re.sub(r'(?:\s|\x1b\[[0-9;]*m)*$', '', line)


def _banner_alt_text(text):
    """Extract visible banner text as a single-line string for alt attributes.

    Strips ANSI escapes, splits on newlines and whitespace, and joins
    all tokens with single spaces.

    :param text: raw banner text with possible ANSI escape sequences
    :returns: single-line visible text string
    """
    visible = _strip_ansi(text)
    return ' '.join(visible.split())


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

    MXP (MUD eXtension Protocol) uses SGML-style declarations like
    ``<!ELEMENT ...>`` and mode-switch escapes like ``\\x1b[6z``.
    Servers may use abbreviated forms (``<!EL``, ``<!EN``) as well.
    Any remaining HTML entities (e.g. ``&quot;``) are unescaped.

    :param text: banner text possibly containing MXP/SGML
    :returns: cleaned text
    """
    text = re.sub(r'\x1b\[\d+z', '', text)
    text = re.sub(r'<!--.*?-->', '', text)
    text = re.sub(r'<!(EL(EMENT)?|ATTLIST|EN(TITY)?)\b.*', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = html.unescape(text)
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


def _telnet_url(host, port):
    """Build a telnet:// URL string.

    :param host: hostname
    :param port: port number
    :returns: telnet URL, omitting port if default (23)
    """
    if port == 23:
        return f"telnet://{host}"
    return f"telnet://{host}:{port}"


# ---------------------------------------------------------------------------
# Banner processing
# ---------------------------------------------------------------------------

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


def _has_encoding_issues(text):
    """Check if text has unresolved encoding problems.

    These indicate encoding mismatches that should be addressed via
    mudlist.txt or bbslist.txt encoding overrides.

    :param text: banner text to check
    :returns: True if text has encoding issues
    """
    if not text:
        return False
    try:
        text.encode('utf-8')
        return '\ufffd' in text
    except UnicodeEncodeError:
        return True


def _combine_banners(server, default_encoding=None):
    """Combine banner_before and banner_after when they contain unique content.

    If *default_encoding* is set and the server has an encoding override
    that differs from the scanner's detected encoding, attempt to
    re-decode the banner with the correct encoding.

    :param server: server record dict
    :param default_encoding: default encoding for the mode (e.g. 'cp437'
        for BBS), or None to skip re-decoding (MUD mode)
    :returns: combined banner text
    """
    banner_before = server['banner_before'] or ''
    banner_after = server['banner_after'] or ''

    if default_encoding is not None:
        effective_enc = (server.get('encoding_override')
                         or default_encoding)
        scanner_enc = server.get('encoding', 'ascii')
        if (effective_enc != scanner_enc
                and scanner_enc in ('ascii', 'utf-8', 'unknown')):
            banner_before = _redecode_banner(
                banner_before, scanner_enc, effective_enc)
            banner_after = _redecode_banner(
                banner_after, scanner_enc, effective_enc)

    # Strip replacement characters and surrogate escapes after re-decoding
    # so that surrogateescape round-trips can recover the original bytes
    # first.  Any remaining surrogates (\udc80-\udcff) would crash print().
    banner_before = _SURROGATES_RE.sub('', banner_before.replace('\ufffd', ''))
    banner_after = _SURROGATES_RE.sub('', banner_after.replace('\ufffd', ''))

    before_clean = _strip_mxp_sgml(_strip_ansi(banner_before)).strip()
    after_clean = _strip_mxp_sgml(_strip_ansi(banner_after)).strip()
    if before_clean and after_clean and after_clean not in before_clean:
        return banner_before.rstrip() + '\r\n' + banner_after.lstrip()
    return banner_before or banner_after


def _banner_to_png(text, banners_dir, encoding='cp437', columns=None):
    """Render ANSI banner text to a deduplicated PNG file.

    Preprocesses the banner text, hashes it with the encoding and
    column width to produce a canonical filename, and renders only
    if that file does not already exist.  Multiple servers with
    identical banners share the same PNG.

    :param text: raw banner text with ANSI escape sequences
    :param banners_dir: directory for output PNG files
    :param encoding: server encoding for font group selection
    :param columns: optional terminal column width override
    :returns: PNG filename (basename) or None on failure
    """
    if _renderer_pool is None:
        return None
    hash_input = text + '\x00' + encoding
    if columns is not None:
        hash_input += '\x00' + str(columns)
    key = hashlib.sha1(
        hash_input.encode('utf-8', errors='surrogateescape')).hexdigest()[:12]

    fname = f"banner_{key}.png"

    output_path = os.path.join(banners_dir, fname)
    if os.path.isfile(output_path):
        if os.path.getsize(output_path) == 0:
            return None  # cached failure
        return fname

    text = text.replace('\x00', '')
    text = text.replace('\r\n', '\n').replace('\n\r', '\n')
    text = _strip_mxp_sgml(text)
    # Strip terminal report/query sequences (DSR, DA, window ops)
    text = re.sub(r'\x1b\[[0-9;]*[nc]', '', text).rstrip()

    if _renderer_pool.capture(text, output_path, encoding, columns=columns):
        return fname
    # Cache failure as 0-byte file to avoid retrying on next run.
    open(output_path, 'a').close()
    return None


def init_renderer(**kwargs):
    """Initialize the terminal rendering pool.

    Call at the beginning of a rendering session.  If no terminal
    backend is available, the pool remains ``None`` and
    :func:`_banner_to_png` will return None for all calls.

    :param kwargs: forwarded to :class:`~make_stats.renderer.RendererPool`
    """
    global _renderer_pool
    from make_stats.renderer import RendererPool
    if not RendererPool.available():
        print("renderer not available (need DISPLAY + kitty or wezterm"
              " + xdotool/import), banners will be skipped",
              file=sys.stderr)
        return
    _renderer_pool = RendererPool(**kwargs)
    _renderer_pool.__enter__()


def close_renderer():
    """Shut down the terminal rendering pool.

    Safe to call even if :func:`init_renderer` was never called
    or failed.
    """
    global _renderer_pool
    if _renderer_pool is not None:
        _renderer_pool.__exit__(None, None, None)
        _renderer_pool = None


# ---------------------------------------------------------------------------
# RST helpers
# ---------------------------------------------------------------------------

def _rst_heading(title, char):
    """Print an RST section heading with the given underline character."""
    print(title)
    width = wcwidth.wcswidth(title)
    if width < 0:
        width = len(title)
    print(char * max(width, 4))
    print()


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


# ---------------------------------------------------------------------------
# IP grouping
# ---------------------------------------------------------------------------

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


def _group_by_banner(servers, default_encoding=None):
    """Group servers by normalized visible banner text.

    Servers with no banner or garbled banners are excluded.
    Within each group, servers are sorted by hostname.

    :param servers: list of server records
    :param default_encoding: passed to :func:`_combine_banners`
    :returns: dict mapping banner hash to dict with keys
        ``banner`` (raw combined text) and ``servers`` (list)
    """
    groups = {}
    for s in servers:
        banner = _combine_banners(s, default_encoding=default_encoding)
        if not banner or _is_garbled(banner):
            continue
        visible = _strip_mxp_sgml(_strip_ansi(banner))
        normalized = ' '.join(visible.split())
        if not normalized:
            continue
        key = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
        if key not in groups:
            groups[key] = {'banner': banner, 'servers': []}
        groups[key]['servers'].append(s)
    for group in groups.values():
        group['servers'].sort(key=lambda s: s['host'].lower())
    return groups


def _most_common_hostname(group_servers):
    """Return the most common hostname among grouped servers.

    :param group_servers: list of server records sharing an IP
    :returns: most frequent hostname string
    """
    counts = Counter(s['host'] for s in group_servers)
    return counts.most_common(1)[0][0]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_servers(records, sort_key=None):
    """Deduplicate by host:port, keeping the most recent session.

    :param records: list of server record dicts
    :param sort_key: callable for sorting the result list
    :returns: deduplicated list
    """
    by_host_port = {}
    for rec in records:
        key = (rec['host'], rec['port'])
        existing = by_host_port.get(key)
        if existing is None or rec['connected'] > existing['connected']:
            by_host_port[key] = rec
    if sort_key is None:
        sort_key = lambda r: r['host'].lower()  # noqa: E731
    return sorted(by_host_port.values(), key=sort_key)


# ---------------------------------------------------------------------------
# File management
# ---------------------------------------------------------------------------

def _clean_dir(dirpath):
    """Remove all .rst files from a directory."""
    if os.path.isdir(dirpath):
        for fname in os.listdir(dirpath):
            if fname.endswith('.rst'):
                os.remove(os.path.join(dirpath, fname))


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


def _needs_rebuild(output_path, *source_paths):
    """Check if output file needs rebuilding based on source file mtimes.

    :param output_path: path to the output file
    :param source_paths: paths to source files (including the caller's
        ``__file__`` if desired)
    :returns: True if output is missing or older than any source
    """
    if not os.path.isfile(output_path):
        return True
    out_mtime = os.path.getmtime(output_path)
    for src in source_paths:
        if src and os.path.isfile(src) and os.path.getmtime(src) > out_mtime:
            return True
    return False


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------

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


def _group_small_slices(labels, counts, threshold=0.01,
                        min_count=None):
    """Group pie slices into 'Other'.

    Slices are grouped if they fall at or below *threshold* fraction of
    the total, or if *min_count* is given and their count is at or below
    that value.

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


def _create_pie_chart(sorted_items, output_path, min_count=None, top_n=None):
    """Create a standard pie chart from sorted (label, count) pairs.

    :param sorted_items: list of (label, count) tuples, sorted descending
    :param output_path: path to write the output PNG
    :param min_count: group slices at or below this count into 'Other'
    :param top_n: if set, keep only the top N items before grouping
    """
    if not sorted_items:
        return
    if top_n is not None:
        sorted_items = sorted_items[:top_n]
    labels = [s for s, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    labels, counts = _group_small_slices(
        labels, counts,
        min_count=min_count if min_count is not None else 1)
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


def _assign_filenames(servers, ip_groups, file_key, toc_key,
                      filename_fn, standalone_label_fn):
    """Assign detail-page filename and toc label to each server.

    Servers sharing an IP get a combined ``ip_<addr>`` filename.
    Standalone servers use *filename_fn* and *standalone_label_fn*.

    :param servers: list of server records (modified in place)
    :param ip_groups: dict from :func:`_group_shared_ip`
    :param file_key: record key for the filename (e.g. ``'_bbs_file'``)
    :param toc_key: record key for the toc label (e.g. ``'_bbs_toc_label'``)
    :param filename_fn: callable(server) -> filesystem-safe filename
    :param standalone_label_fn: callable(server) -> toc label string
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
            s[file_key], s[toc_key] = grouped_keys[key]
        else:
            s[file_key] = filename_fn(s)
            s[toc_key] = standalone_label_fn(s)


def display_fingerprint_summary(servers, server_label_fn):
    """Print summary table of protocol fingerprints.

    :param servers: list of server records
    :param server_label_fn: callable(server) -> display label string
    """
    print("Fingerprints")
    print("============")
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
        server_labels = ', '.join(
            server_label_fn(s) for s in fp_servers[:3])
        if len(fp_servers) > 3:
            server_labels += f', ... (+{len(fp_servers) - 3})'

        rows.append({
            'Fingerprint': f':ref:`{fp[:16]}... <fp_{fp}>`',
            'Servers': str(len(fp_servers)),
            'Offers': _rst_escape(offered[:30]),
            'Requests': _rst_escape(requested[:30]),
            'Examples': _rst_escape(server_labels[:50]),
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


def _write_fingerprint_options_section(fp_hash, fp_servers):
    """Write the Telnet Options and Negotiation Results sections.

    Shared RST output for fingerprint detail pages in both BBS
    and MUD modes.

    :param fp_hash: fingerprint hash string
    :param fp_servers: list of server records sharing this fingerprint
    """
    sample = fp_servers[0]

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


def display_encoding_groups(servers, detail_subdir, file_key,
                            server_label_fn, server_sort_key, tls_fn):
    """Print servers-by-encoding page.

    :param servers: list of server records
    :param detail_subdir: subdirectory for detail links (e.g. ``'bbs_detail'``)
    :param file_key: record key for the detail filename (e.g. ``'_bbs_file'``)
    :param server_label_fn: callable(server) -> display label string
    :param server_sort_key: callable(server) -> sort key
    :param tls_fn: callable(server) -> truthy if TLS supported
    """
    _rst_heading("Encodings", '=')
    print("Servers grouped by their detected or configured"
          " character encoding.")

    by_encoding = {}
    for s in servers:
        key = s['display_encoding']
        by_encoding.setdefault(key, []).append(s)

    for name, members in sorted(
            by_encoding.items(), key=lambda x: (-len(x[1]), x[0])):
        print()
        print(f"- `{_rst_escape(name)}`_: {len(members)}")
    print()

    for name, members in sorted(
            by_encoding.items(), key=lambda x: (-len(x[1]), x[0])):
        print()
        print(f'.. _{name}:')
        print()
        _rst_heading(name, '-')
        for s in sorted(members, key=server_sort_key):
            detail_file = s[file_key]
            label = server_label_fn(s)
            tls = (' :tls-lock:`\U0001f512`'
                   if tls_fn(s) else '')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <{detail_subdir}/{detail_file}>`{tls}")
        print()


def display_location_groups(servers, detail_subdir, file_key,
                            server_label_fn, server_sort_key, tls_fn):
    """Print servers-by-location page.

    :param servers: list of server records (must have ``_country_code``
        and ``_country_name`` keys)
    :param detail_subdir: subdirectory for detail links (e.g. ``'bbs_detail'``)
    :param file_key: record key for the detail filename (e.g. ``'_bbs_file'``)
    :param server_label_fn: callable(server) -> display label string
    :param server_sort_key: callable(server) -> sort key
    :param tls_fn: callable(server) -> truthy if TLS supported
    """
    from .geoip import _country_flag

    _rst_heading("Server Locations", '=')
    print("Servers grouped by the geographic location of"
          " their IP address.")

    by_country = {}
    for s in servers:
        code = s.get('_country_code', '')
        name = s.get('_country_name', 'Unknown')
        key = code or 'XX'
        by_country.setdefault(key, (name, []))[1].append(s)

    for key, (name, members) in sorted(
            by_country.items(), key=lambda x: (-len(x[1][1]), x[1][0])):
        flag = _country_flag(key) + ' ' if key != 'XX' else ''
        print()
        print(f"- `{flag}{_rst_escape(name)}`_: {len(members)}")
    print()

    for key, (name, members) in sorted(
            by_country.items(), key=lambda x: (-len(x[1][1]), x[1][0])):
        flag = _country_flag(key) + ' ' if key != 'XX' else ''
        heading = f'{flag}{name}'
        print()
        print(f'.. _{name}:')
        print()
        _rst_heading(heading, '-')
        for s in sorted(members, key=server_sort_key):
            detail_file = s[file_key]
            label = server_label_fn(s)
            tls = (' :tls-lock:`\U0001f512`'
                   if tls_fn(s) else '')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <{detail_subdir}/{detail_file}>`{tls}")
        print()


def _page_initial_range(page_groups, server_name_fn):
    """Compute the letter range label for a page of banner groups.

    Returns ``'[A]'`` when all entries share the same initial, or
    ``'[A-F]'`` when they span a range.

    :param page_groups: list of banner group dicts
    :param server_name_fn: callable(server) -> display name
    :returns: bracket-enclosed range string, or ``''``
    """
    initials = set()
    for group in page_groups:
        name = server_name_fn(group['servers'][0])
        if name:
            initials.add(name[0].upper())
    if not initials:
        return ''
    ordered = sorted(initials)
    if ordered[0] == ordered[-1]:
        return f'[{ordered[0]}]'
    return f'[{ordered[0]}-{ordered[-1]}]'


def _display_banner_page(page_groups, page_num, total_pages,
                         page_label,
                         file_key, banners_path,
                         detail_subdir, server_name_fn, tls_fn):
    """Write one page of the banner gallery to stdout.

    :param page_groups: list of banner group dicts for this page
    :param page_num: current page number (1-based)
    :param total_pages: total number of pages
    :param page_label: letter-range label (e.g. ``'[A-F]'``)
    :param file_key: record key for the detail filename
    :param banners_path: path to banner PNG directory
    :param detail_subdir: subdirectory for detail links
    :param server_name_fn: callable(server) -> display name
    :param tls_fn: callable(server) -> truthy if TLS supported
    """
    title = f"Page {page_num} of {total_pages} {_rst_escape(page_label)}"
    _rst_heading(title, '=')

    for group in page_groups:
        members = group['servers']
        count = len(members)
        rep = members[0]
        banner = group['banner']

        name = server_name_fn(rep)
        if count > 1:
            heading = f"{_rst_escape(name)} (+{count - 1} more)"
        else:
            heading = _rst_escape(name)
        _rst_heading(heading, '-')

        banner_fname = rep.get('_banner_png')
        if banner_fname:
            print(f".. image:: /_static/banners/{banner_fname}")
            print(f"   :alt:"
                  f" {_rst_escape(_banner_alt_text(banner))}")
            print(f"   :class: ansi-banner")
            print(f"   :loading: lazy")
            print()

        for s in members:
            label = server_name_fn(s)
            host = s['host']
            port = s['port']
            tls = (' :tls-lock:`\U0001f512`'
                   if tls_fn(s) else '')
            encoding = s.get('display_encoding', 'utf-8')
            print(f"- :doc:`{_rst_escape(label)}"
                  f" <{detail_subdir}/{s[file_key]}>`"
                  f"{tls}"
                  f" :copy-btn:`{_rst_escape(host)} {port}`")
            print(f"  | Encoding: {_rst_escape(encoding)}")
        print()



def generate_banner_gallery(servers, docs_path, page_size=100,
                            entity_name='servers', file_key='_file',
                            banners_path=None,
                            detail_subdir='detail',
                            default_encoding=None,
                            server_name_fn=None,
                            server_sort_key=None,
                            tls_fn=None):
    """Generate paginated banner gallery RST files.

    Writes a landing page ``banner_gallery.rst`` with intro text
    and a toctree, then ``banner_gallery_1.rst`` through
    ``banner_gallery_N.rst`` with the actual banner groups.
    Stale pages from previous runs are removed.

    :param servers: list of server records
    :param docs_path: Sphinx docs directory to write RST into
    :param page_size: number of banner groups per page
    :param entity_name: plural entity label (e.g. ``'BBSes'``)
    :param file_key: record key for the detail filename
    :param banners_path: path to banner PNG directory
    :param detail_subdir: subdirectory for detail links
    :param default_encoding: passed to :func:`_combine_banners`
    :param server_name_fn: callable(server) -> display name
    :param server_sort_key: callable for sorting groups
    :param tls_fn: callable(server) -> truthy if TLS supported
    """
    if server_name_fn is None:
        server_name_fn = lambda s: f"{s['host']}:{s['port']}"  # noqa: E731
    if tls_fn is None:
        tls_fn = lambda s: False  # noqa: E731

    groups = _group_by_banner(
        servers, default_encoding=default_encoding)

    if server_sort_key is None:
        server_sort_key = lambda g: g['servers'][0]['host'].lower()  # noqa: E731

    sorted_groups = sorted(
        groups.values(),
        key=lambda g: (-len(g['servers']), server_sort_key(g)))

    total_groups = len(sorted_groups)
    total_servers = sum(len(g['servers']) for g in sorted_groups)

    pages = []
    for i in range(0, max(len(sorted_groups), 1), page_size):
        pages.append(sorted_groups[i:i + page_size])
    total_pages = len(pages)

    # Write landing page: banner_gallery.rst
    landing_path = os.path.join(docs_path, "banner_gallery.rst")
    with open(landing_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        _rst_heading("Banner Gallery", '=')
        print("A gallery of ANSI connection banners collected"
              " from responding")
        print(f"{entity_name}. Servers that display identical"
              " visible banner text are")
        print("grouped together. Each group shows the shared"
              " banner image")
        print("and a list of all servers in that group.")
        print()
        print(f"{total_groups} unique banners across"
              f" {total_servers} servers.")
        print()
        # Compute labels for all pages before writing toctree
        page_labels = []
        for p_groups in pages:
            page_labels.append(
                _page_initial_range(p_groups, server_name_fn))

        print(".. toctree::")
        print("   :maxdepth: 1")
        print()
        for p in range(1, total_pages + 1):
            label = page_labels[p - 1]
            print(f"   Page {p} {label}"
                  f" <banner_gallery_{p}>")
        print()
    print(f"  wrote {landing_path}", file=sys.stderr)

    # Write content pages: banner_gallery_1.rst .. _N.rst
    for page_num, page_groups in enumerate(pages, 1):
        page_label = _page_initial_range(
            page_groups, server_name_fn)
        rst_path = os.path.join(
            docs_path, f"banner_gallery_{page_num}.rst")
        with open(rst_path, 'w') as fout, \
                contextlib.redirect_stdout(fout):
            _display_banner_page(
                page_groups, page_num, total_pages,
                page_label=page_label,
                file_key=file_key,
                banners_path=banners_path,
                detail_subdir=detail_subdir,
                server_name_fn=server_name_fn,
                tls_fn=tls_fn)
        print(f"  wrote {rst_path}", file=sys.stderr)

    # Remove stale banner_gallery_*.rst from previous runs
    expected = {'banner_gallery'}
    expected.update(
        f'banner_gallery_{p}' for p in range(1, total_pages + 1))
    for fname in os.listdir(docs_path):
        if (fname.startswith('banner_gallery')
                and fname.endswith('.rst')):
            stem = fname[:-4]
            if stem not in expected:
                os.remove(os.path.join(docs_path, fname))
                print(f"  removed stale {fname}",
                      file=sys.stderr)


def generate_fingerprint_details(servers, detail_path, generate_detail_fn,
                                 force=False):
    """Generate all fingerprint detail pages.

    :param servers: list of server records
    :param detail_path: directory for fingerprint detail RST files
    :param generate_detail_fn: callable(fp_hash, fp_servers) to generate
        one detail page; should return False if skipped
    :param force: if True, clean directory before regenerating
    """
    if force:
        _clean_dir(detail_path)
    os.makedirs(detail_path, exist_ok=True)

    by_fp = {}
    for s in servers:
        by_fp.setdefault(s['fingerprint'], []).append(s)

    rebuilt = 0
    for fp_hash, fp_servers in sorted(by_fp.items()):
        result = generate_detail_fn(fp_hash, fp_servers)
        if result is not False:
            rebuilt += 1

    if rebuilt < len(by_fp):
        print(f"  wrote {rebuilt}/{len(by_fp)} fingerprint detail"
              f" pages to {detail_path}"
              f" ({len(by_fp) - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} fingerprint detail pages"
              f" to {detail_path}", file=sys.stderr)


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
    ax.bar(x - width / 2, offered_counts, width,
           label='Server Offers',
           color=PLOT_GREEN, edgecolor='#222222', alpha=0.85)
    ax.bar(x + width / 2, requested_counts, width,
           label='Server Requests',
           color=PLOT_CYAN, edgecolor='#222222', alpha=0.85)

    ax.set_xlabel('Telnet Option', fontsize=12)
    ax.set_ylabel('Number of Servers', fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels(options, rotation=45, ha='right', fontsize=9)
    ax.legend(facecolor='none', edgecolor=PLOT_FG,
              labelcolor=PLOT_FG)
    ax.grid(True, axis='y')

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()
