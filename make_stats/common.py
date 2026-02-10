"""Shared utilities for MUD and BBS statistics generation."""

import os
import re
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import tabulate as tabulate_mod  # noqa: E402
import wcwidth  # noqa: E402
from ansi2html import Ansi2HTMLConverter  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ANSI_CONV = Ansi2HTMLConverter(inline=True, dark_bg=True, scheme='xterm')

LINK_REGEX = re.compile(r'[^a-zA-Z0-9]')
_URL_RE = re.compile(r'https?://[^\s<>"\']+')
_RST_SECTION_RE = re.compile(r'([=\-~#+^"._]{4,})')

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

ANSI2PNG = os.path.join(_PROJECT_ROOT, "ansi2png")
_LD_LIBRARY_PATH = os.path.join(_PROJECT_ROOT, "libansilove", "build")

# Mapping of encoding names to libansilove font names (BBS superset)
_ENCODING_TO_FONT = {
    'ascii': 'CP437',
    'cp437': 'CP437',
    'cp437_art': 'CP437',
    'cp437-art': 'CP437',
    'cp737': 'CP737',
    'cp775': 'CP775',
    'cp850': 'CP850',
    'cp852': 'CP852',
    'cp855': 'CP855',
    'cp857': 'CP857',
    'cp860': 'CP860',
    'cp861': 'CP861',
    'cp862': 'CP862',
    'cp863': 'CP863',
    'cp865': 'CP865',
    'cp866': 'CP866',
    'cp869': 'CP869',
    'amiga': 'TOPAZ',
    'petscii': 'CP437',
    'atarist': 'CP437',
    'utf-8': 'CP437',
    'unknown': 'CP437',
    'big5': 'CP437',
    'gbk': 'CP437',
    'shift-jis': 'CP437',
    'shift_jis': 'CP437',
    'euc-kr': 'CP437',
    'euc_kr': 'CP437',
}


def _encoding_to_font(encoding):
    """Map a server encoding name to a libansilove font name.

    :param encoding: encoding string from scanner or bbslist
    :returns: libansilove font name string
    """
    return _ENCODING_TO_FONT.get(
        encoding.lower().replace('-', '_'), 'CP437')


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


def _rstrip_ansi_line(line, columns=80):
    """Strip trailing visible whitespace from lines that would cause wrapping.

    When libansilove renders a line whose visible width equals the column
    count, the cursor auto-wraps and the following newline produces a
    double-spaced blank line.  Detect this with :func:`wcwidth.wcswidth`
    on the ANSI-stripped text and remove trailing whitespace + ANSI resets
    when the visible width meets or exceeds *columns*.

    :param line: single line of text, possibly containing ANSI escapes
    :param columns: rendering column width (default 80)
    :returns: line with trailing visible whitespace removed when needed
    """
    visible = _strip_ansi(line)
    if wcwidth.wcswidth(visible) < columns:
        return line
    # Strip trailing whitespace and any surrounding ANSI SGR sequences
    return re.sub(r'(?:\s|\x1b\[[0-9;]*m)*$', '', line)


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
    import html as html_mod
    text = re.sub(r'\x1b\[\d+z', '', text)
    text = re.sub(r'<!--.*?-->', '', text)
    text = re.sub(r'<!(EL(EMENT)?|ATTLIST|EN(TITY)?)\b.*', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = html_mod.unescape(text)
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
    banner_before = (server['banner_before'] or '').replace('\ufffd', '')
    banner_after = (server['banner_after'] or '').replace('\ufffd', '')

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

    before_clean = _strip_mxp_sgml(_strip_ansi(banner_before)).strip()
    after_clean = _strip_mxp_sgml(_strip_ansi(banner_after)).strip()
    if before_clean and after_clean and after_clean not in before_clean:
        return banner_before.rstrip() + '\r\n' + banner_after.lstrip()
    return banner_before or banner_after


def _banner_to_html(text, maxlen=5000, maxlines=250, name='',
                    wrap_width=80, brighten_blue=False,
                    default_aria='BBS'):
    """Convert ANSI banner text to inline-styled HTML.

    :param text: raw banner text with possible ANSI escape sequences
    :param maxlen: maximum visible character length for truncation
    :param maxlines: maximum number of lines to include
    :param name: server name for the aria-label attribute
    :param wrap_width: column width for wrapping long lines
    :param brighten_blue: if True, brighten dark blues for dark backgrounds
    :param default_aria: fallback aria-label name if *name* is empty
    :returns: HTML string suitable for ``.. raw:: html`` embedding
    """
    import html as html_mod

    text = text.replace('\r\n', '\n').replace('\n\r', '\n').replace('\r', '\n')
    text = _strip_mxp_sgml(text)
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
        elif (text[i] == '\n'
              or (text[i].isprintable() and ord(text[i]) < 0xFFFD)):
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
            line, width=wrap_width, drop_whitespace=False,
            break_long_words=True, break_on_hyphens=False,
        )
        wrapped_lines.extend(wrapped if wrapped else [''])
    text = '\n'.join(wrapped_lines)

    html_content = _ANSI_CONV.convert(text, full=False)
    if brighten_blue:
        html_content = html_content.replace('#0000ee', '#5555ff')
        html_content = html_content.replace('#5c5cff', '#7777ff')
    aria_name = html_mod.escape(name or default_aria)
    return (f'<pre class="ansi-banner" role="img"'
            f' aria-label="ANSI art banner for {aria_name}">'
            f'{html_content}</pre>')


def _banner_to_png(text, output_path, encoding='cp437'):
    """Render ANSI banner text to a PNG file via ansi2png.

    Writes the raw banner text to a temporary file, invokes the
    ansi2png C program, and verifies the output.

    :param text: raw banner text with ANSI escape sequences
    :param output_path: path to write the output PNG
    :param encoding: server encoding for font selection
    :returns: True if PNG was successfully created
    """
    text = text.replace('\r\n', '\n').replace('\n\r', '\n')
    text = _strip_mxp_sgml(text)
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)

    lines = text.split('\n')
    text = '\n'.join(_rstrip_ansi_line(line) for line in lines)

    codec = encoding if encoding != 'ascii' else 'cp437'
    try:
        raw_bytes = text.encode(codec, errors='replace')
    except LookupError:
        raw_bytes = text.encode('latin-1', errors='surrogateescape')

    font = _encoding_to_font(encoding)
    env = os.environ.copy()
    env['ANSILOVE_FONT'] = font
    env['ANSILOVE_COLUMNS'] = '80'
    ld = _LD_LIBRARY_PATH
    if env.get('LD_LIBRARY_PATH'):
        ld += ':' + env['LD_LIBRARY_PATH']
    env['LD_LIBRARY_PATH'] = ld

    with tempfile.NamedTemporaryFile(
        suffix='.ans', delete=False
    ) as tmp:
        tmp.write(raw_bytes)
        tmp_path = tmp.name

    result = subprocess.run(
        [ANSI2PNG, tmp_path, output_path],
        env=env, capture_output=True,
    )
    os.unlink(tmp_path)

    if result.returncode != 0:
        stderr_msg = result.stderr.decode(errors='replace')
        print(f"  ansi2png failed for {output_path}: "
              f"{stderr_msg.strip()}", file=sys.stderr)
        return False

    if (not os.path.isfile(output_path)
            or os.path.getsize(output_path) == 0):
        print(f"  ansi2png produced empty output: "
              f"{output_path}", file=sys.stderr)
        return False

    return True


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
