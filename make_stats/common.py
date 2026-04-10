"""Shared utilities for MUD and BBS statistics generation."""

import contextlib
import hashlib
import html
import json
import os
import re
import sys
import textwrap
from collections import Counter
from datetime import datetime
from functools import lru_cache

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import tabulate as tabulate_mod  # noqa: E402
import wcwidth  # noqa: E402
from telix.color_filter import ColorConfig, ColorFilter  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINK_REGEX = re.compile(r'[^a-zA-Z0-9]')
_URL_RE = re.compile(r'https?://[^\s<>"\']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"\']*)?')
# Domains that must never be reported as a server's website — they appear in
# banners because the scanner's reverse-DNS hostname resolves to this domain.
_URL_SCANNER_DOMAINS = frozenset({'modem.xyz', 'syncterm.bbsdev.net'})
_RST_SECTION_RE = re.compile(r'([=\-~#+^"._]{4,})')
_SURROGATES_RE = re.compile(r'[\udc80-\udcff]')

# Keywords in server list files that are not encoding names.
_LIST_KEYWORDS = {'ssl', 'no_ambig'}

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
                enc = parts[2]
                if enc in _LIST_KEYWORDS:
                    continue
                overrides[(host, port)] = enc
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


def _load_row_overrides(path):
    """Load row height overrides from a server list file.

    Looks for the keyword ``tall`` anywhere after the port field.

    :param path: path to server list file
    :returns: dict mapping (host, port) to row count
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
            if len(parts) >= 3 and 'tall' in parts[2:]:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides[(host, port)] = 100
    return overrides


def _load_ssl_overrides(path):
    """Load SSL overrides from a server list file.

    Looks for the keyword ``ssl`` anywhere after the port field.

    :param path: path to server list file
    :returns: set of (host, port) tuples that use SSL
    """
    overrides = set()
    if not os.path.isfile(path):
        return overrides
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and 'ssl' in parts[2:]:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides.add((host, port))
    return overrides


def _load_no_ambig_overrides(path):
    """Load no_ambig overrides from a server list file.

    Looks for the keyword ``no_ambig`` anywhere after the port field.
    Servers with this flag render CJK banners without treating
    ambiguous-width characters as wide.

    :param path: path to server list file
    :returns: dict mapping (host, port) to True
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
            if len(parts) >= 3 and 'no_ambig' in parts[2:]:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                overrides[(host, port)] = True
    return overrides


def _load_ssh_overrides(path):
    """Load SSH port overrides from a server list file.

    Looks for lines with format ``host port ssh``.

    :param path: path to server list file
    :returns: dict mapping host_lower to ssh_port int
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
            if len(parts) >= 2 and parts[1] == 'ssh':
                host = parts[0].lower()
                if len(parts) >= 3:
                    try:
                        ssh_port = int(parts[2])
                    except ValueError:
                        continue
                else:
                    ssh_port = 22
                overrides[host] = ssh_port
    return overrides


def _load_base_records(data_dir, encoding_overrides=None,
                       column_overrides=None, row_overrides=None,
                       no_ambig_overrides=None):
    """Load base server records from fingerprint JSON files.

    Parses session data, fingerprint data, encoding overrides, and
    surrogate escape handling common to both MUD and BBS pipelines.
    Returns records with shared fields; callers enrich with
    mode-specific data.

    :param data_dir: path to telnetlib3 data directory
    :param encoding_overrides: dict mapping (host, port) to encoding
    :param column_overrides: dict mapping (host, port) to column width
    :param row_overrides: dict mapping (host, port) to row height
    :param no_ambig_overrides: dict mapping (host, port) to True
    :returns: list of dicts, each containing base record fields plus
        ``_session_data`` and ``_session`` for caller enrichment
    """
    if encoding_overrides is None:
        encoding_overrides = {}
    if column_overrides is None:
        column_overrides = {}
    if row_overrides is None:
        row_overrides = {}
    if no_ambig_overrides is None:
        no_ambig_overrides = {}

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
                with open(fpath, encoding='utf-8',
                          errors='surrogateescape') as f:
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

            detected_encoding = session_data.get(
                'encoding', 'unknown')
            banner_before = session_data.get(
                'banner_before_return', '')
            banner_after = session_data.get(
                'banner_after_return', '')

            if not banner_before and not banner_after:
                continue

            host = session.get('host',
                               session.get('ip', 'unknown'))
            port = session.get('port', 0)

            # Re-decode surrogate escapes as UTF-8 for servers that
            # don't have an explicit encoding override.  Servers with
            # an override (e.g. cp437) are handled later by
            # _combine_banners which re-decodes with the correct
            # target encoding — doing a premature UTF-8 re-decode here
            # would destroy the surrogate escapes it needs.
            if detected_encoding in ('ascii', 'utf-8', 'unknown'):
                if (host, port) not in encoding_overrides:
                    if banner_before:
                        banner_before = _redecode_banner(
                            banner_before, detected_encoding, 'utf-8')
                    if banner_after:
                        banner_after = _redecode_banner(
                            banner_after, detected_encoding, 'utf-8')

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
                'encoding': detected_encoding,
                'encoding_override': encoding_overrides.get(
                    (host, port), ''),
                'column_override': column_overrides.get(
                    (host, port)),
                'row_override': row_overrides.get(
                    (host, port)),
                'no_ambig_override': no_ambig_overrides.get(
                    (host, port), False),
                'banner_before': banner_before,
                'banner_after': banner_after,
                'timing': session_data.get('timing', {}),
                'dsr_requests': session_data.get(
                    'dsr_requests', 0),
                'dsr_replies': session_data.get(
                    'dsr_replies', 0),
                '_session_data': session_data,
            }

            records.append(record)

    return records


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


# C0 control codes and DEL that produce no visible terminal output.
_C0_CONTROLS = frozenset(
    chr(c) for c in range(0x20) if chr(c) not in '\t\n\r'
) | {'\x7f'}


def _printable_text(text):
    """Return only printable characters from text, stripping escapes and controls.

    :param text: raw text possibly containing ANSI escapes and control codes
    :returns: string with only printable characters
    """
    stripped = _strip_ansi(text).strip()
    return ''.join(c for c in stripped if c not in _C0_CONTROLS)


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


def _collapse_double_spaced_rows(text):
    """Remap cursor-positioned rows when every row is evenly spaced.

    Some BBS software (e.g. Mystic BBS) sends art with cursor
    positioning that skips every other row (rows 2,4,6,... or
    4,6,8,10,...), producing unwanted double-spacing.  Detection
    uses the unique row numbers from *all* CUP sequences (any
    column), then remaps every CUP in the affected row range.

    :param text: banner text after newline stripping
    :returns: text with collapsed row positioning
    """
    _CUP_RE = re.compile(r'\x1b\[(\d+);(\d*)H')

    cups = [(m.start(), m.end(), int(m.group(1)), int(m.group(2) or '1'))
            for m in _CUP_RE.finditer(text)]
    if not cups:
        return text

    # Build sorted list of unique row numbers across all CUP sequences.
    unique_rows = sorted(set(r for _, _, r, _ in cups))
    if len(unique_rows) < 3:
        return text

    # Find runs of unique rows with a constant stride > 1.
    runs = []
    i = 0
    while i < len(unique_rows) - 1:
        stride = unique_rows[i + 1] - unique_rows[i]
        if stride < 2:
            i += 1
            continue
        j = i + 1
        while (j < len(unique_rows) - 1
               and unique_rows[j + 1] - unique_rows[j] == stride):
            j += 1
        if j - i >= 2:  # at least 3 rows in the run
            runs.append((i, j, stride))
        i = j + 1

    if not runs:
        return text

    # Build row mapping from detected runs.
    row_map = {}
    for run_start, run_end, stride in runs:
        base_row = unique_rows[run_start]
        for k in range(run_start, run_end + 1):
            orig_row = unique_rows[k]
            new_row = base_row + (k - run_start)
            if new_row != orig_row:
                row_map[orig_row] = new_row

    if not row_map:
        return text

    # Replace all CUP sequences whose row is in the map (right-to-left).
    replacements = []
    for start, end, row, col in cups:
        if row in row_map:
            col_part = f';{col}' if col != 1 else ';1'
            replacements.append((start, end, f'\x1b[{row_map[row]}{col_part}H'))

    for start, end, new_seq in reversed(replacements):
        text = text[:start] + new_seq + text[end:]
    return text


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


def _copy_btn_markup(server, tls_fn):
    """Build RST copy-button markup for a server entry.

    Returns a :tls-lock: copy button when TLS is supported, otherwise
    a plain :copy-btn: clipboard button.

    :param server: server record dict with ``host`` and ``port`` keys
    :param tls_fn: callable(server) -> truthy if TLS supported (for MUDs,
        returns the TLS port string; for BBS returns True/False)
    :returns: RST role string (leading space included)
    """
    host = server['host']
    port = server['port']
    tls = tls_fn(server)
    if tls:
        if isinstance(tls, str) and tls not in ('1', str(port)):
            copy_port = tls
        else:
            copy_port = port
        return f' :tls-lock:`{host} {copy_port}`'
    return f' :copy-btn:`{host} {port}`'


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



def _png_display_width(path):
    """Read a PNG file's pixel width for use as the CSS display width.

    Banner PNGs are captured at native terminal resolution (1:1 pixels)
    so the display width equals the actual pixel width.  Falls back to
    None if the file cannot be read.

    :param path: path to a PNG file
    :returns: display width in pixels, or None
    """
    import struct
    try:
        with open(path, 'rb') as fh:
            header = fh.read(24)
        if len(header) >= 24 and header[:8] == b'\x89PNG\r\n\x1a\n':
            return struct.unpack('>I', header[16:20])[0]
    except OSError:
        pass
    return None


def _banner_to_png(text, banners_dir, encoding='cp437', columns=None,
                   rows=None, no_ambig=False, ice_colors=False,
                   server_label=None):
    """Render ANSI banner text to a deduplicated PNG file.

    Preprocesses the banner text, hashes it with the encoding and
    column width to produce a canonical filename, and renders only
    if that file does not already exist.  Multiple servers with
    identical banners share the same PNG.

    :param text: raw banner text with ANSI escape sequences
    :param banners_dir: directory for output PNG files
    :param encoding: server encoding for font group selection
    :param columns: optional terminal column width override
    :param rows: optional terminal row height override
    :param no_ambig: if True, disable ambiguous-width-as-wide for CJK
    :param ice_colors: if True, treat SGR 5 (blink) as bright background
    :param server_label: optional string identifying the server for error
        messages (e.g. ``'host:port (data_path)'``)
    :returns: ``(filename, display_width)`` tuple, or ``(None, None)``
        on failure.  *display_width* is the PNG pixel width, used as
        the CSS display width so banners render at natural size.
    """
    if _renderer_pool is None:
        return None, None

    text = text.replace('\x00', '')
    text = text.replace('\r\n', '\n').replace('\n\r', '\n')
    # PETSCII uses standalone \r as newline (0x0D = carriage return only
    # in ASCII, but acts as newline on C64).  After \r\n pairs are already
    # collapsed above, remaining \r are standalone PETSCII newlines.
    if encoding == 'petscii':
        text = text.replace('\r', '\n')
    text = _strip_mxp_sgml(text)
    # Strip terminal report/query sequences (DSR, DA, window ops)
    text = re.sub(r'\x1b\[[0-9;]*[nc]', '', text)
    # Normalize clear-screen sequences.  CTerm (Synchronet's terminal)
    # homes the cursor on ED 2 and treats form feed (0x0C) as clear +
    # home; standard terminals like wezterm don't.  Normalize each
    # clear to HOME + CLEAR + SGR-RESET so carried-over colors (e.g.
    # black-on-black detection strings) don't make post-clear content
    # invisible.  Also treat form feed as clear screen.
    text = text.replace('\x0c', '\x1b[2J')
    text = text.replace('\x1b[2J\x1b[H', '\x1b[2J')
    text = text.replace('\x1b[2J', '\x1b[H\x1b[2J\x1b[0m')
    # If a clear screen wipes visible content but leaves nothing
    # visible after it, drop the clear and everything after so the
    # pre-clear content is displayed instead.
    _clear_token = '\x1b[H\x1b[2J\x1b[0m'
    last_clear = text.rfind(_clear_token)
    if last_clear > 0:
        before_clear = text[:last_clear]
        after_clear = text[last_clear + len(_clear_token):]
        if (_printable_text(before_clear)
                and not _printable_text(after_clear)):
            # Clear wipes visible content but nothing follows — keep
            # the pre-clear art (e.g. server clears on disconnect).
            text = before_clear
        elif _printable_text(after_clear):
            # Clear screen replaces the display — keep only what a
            # terminal would actually show (the post-clear content).
            # This also strips pre-clear CUP positioning junk that
            # would confuse row-stride detection below.
            text = after_clear
    # Strip newlines before absolute cursor positioning — they are
    # redundant and produce unwanted blank lines (e.g. Mystic BBS).
    text = re.sub(r'\n(\x1b\[\d+;\d*H)', r'\1', text)
    # Collapse double-spaced cursor positioning (rows 2,4,6,... or
    # 1,3,5,...) to consecutive rows so art isn't stretched vertically.
    text = _collapse_double_spaced_rows(text)
    text = text.rstrip()

    # Skip banners with no visible content — they all render to the same
    # blank image and waste renderer cycles.
    if not _printable_text(text):
        return None, None

    # Apply VGA color matching: translate 16-color SGR codes to 24-bit
    # RGB from the VGA palette.  For BBS banners, also enable iCE colors
    # (SGR 5 blink repurposed as bright background).  Skip encodings
    # that use their own control codes rather than ANSI SGR.
    if encoding not in ('petscii', 'atascii', 'atarist'):
        color_cfg = ColorConfig(palette_name='vga', ice_colors=ice_colors)
        color_filter = ColorFilter(color_cfg)
        text = color_filter.filter(text) + color_filter.flush()

    # Cap at 512 KiB to avoid overwhelming the terminal renderer with
    # giant pixel-art banners (e.g. 21 MB truecolor block-character art).
    max_bytes = 512 * 1024
    encoded = text.encode('utf-8', errors='surrogateescape')
    if len(encoded) > max_bytes:
        text = encoded[:max_bytes].decode('utf-8', errors='ignore').rstrip()

    hash_input = text + '\x00' + encoding
    if columns is not None:
        hash_input += '\x00' + str(columns)
    if rows is not None:
        hash_input += '\x00r' + str(rows)
    if no_ambig:
        hash_input += '\x00no_ambig'
    key = hashlib.sha1(
        hash_input.encode('utf-8', errors='surrogateescape')).hexdigest()[:12]

    fname = f"banner_{key}.png"

    output_path = os.path.join(banners_dir, fname)
    if os.path.isfile(output_path):
        if os.path.getsize(output_path) == 0:
            return None, None  # cached failure
        return fname, _png_display_width(output_path)

    instance_name = _renderer_pool.capture(
        text, output_path, encoding, columns=columns, rows=rows,
        no_ambig=no_ambig)
    if instance_name:
        return fname, _png_display_width(output_path)
    # Cache failure as 0-byte file to avoid retrying on next run.
    plain_len = len(_printable_text(text))
    label = f" [{server_label}]" if server_label else ""
    print(f"  banner render failed: {fname} "
          f"({plain_len} visible chars, enc={encoding}){label}",
          file=sys.stderr)
    open(output_path, 'w').close()
    return None, None


def purge_failed_banners(banners_dir):
    """Remove 0-byte banner PNGs so failed renders are retried.

    Failed renders are cached as empty files to avoid repeated attempts
    within a single run.  Between runs, these should be cleared so that
    transient failures (e.g. renderer timeouts) get another chance.

    :param banners_dir: path to the banners directory
    """
    count = 0
    for name in os.listdir(banners_dir):
        if name.startswith('banner_') and name.endswith('.png'):
            path = os.path.join(banners_dir, name)
            if os.path.getsize(path) == 0:
                os.remove(path)
                count += 1
    if count:
        print(f"  purged {count} failed banner cache file(s)", file=sys.stderr)


def init_renderer(check_dupes=False, **kwargs):
    """Initialize the terminal rendering pool.

    Call at the beginning of a rendering session.  If no terminal
    backend is available, the pool remains ``None`` and
    :func:`_banner_to_png` will return None for all calls.

    :param check_dupes: enable duplicate-image detection between
        consecutive renders on the same terminal instance
    :param kwargs: forwarded to :class:`~make_stats.renderer.RendererPool`
    """
    global _renderer_pool
    from make_stats.renderer import RendererPool
    if not RendererPool.available():
        print("renderer not available (need DISPLAY + wezterm"
              " + xdotool/import), banners will be skipped",
              file=sys.stderr)
        return
    _renderer_pool = RendererPool(check_dupes=check_dupes, **kwargs)
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
# Jinja2 template environment
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _jinja_env():
    """Return the shared Jinja2 environment for RST templates.

    :returns: configured ``jinja2.Environment``
    """
    import jinja2
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(
            os.path.join(os.path.dirname(__file__), 'templates')),
        lstrip_blocks=True,
        trim_blocks=True,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
    )
    env.filters['rst_escape'] = _rst_escape
    env.filters['banner_alt_text'] = _banner_alt_text
    env.filters['telnet_url'] = lambda h, p: _telnet_url(h, p)
    env.filters['clean_log_line'] = _clean_log_line
    env.filters['rst_width'] = lambda t: wcwidth.width(t, control_codes='ignore')
    from .geoip import _country_flag
    env.filters['country_flag'] = _country_flag
    return env


def _render_template(template_name, **context):
    """Render a Jinja2 template and return the resulting string.

    :param template_name: template filename relative to templates/
    :param context: template variables
    :returns: rendered string
    """
    env = _jinja_env()
    template = env.get_template(template_name)
    return template.render(**context)


# ---------------------------------------------------------------------------
# Escape sequence analysis
# ---------------------------------------------------------------------------

# Friendly names for common escape sequences.
_SEQ_NAMES = {
    '\x1b[0m': 'SGR Reset',
    '\x1b[m': 'SGR Reset (short)',
    '\x1b[2J': 'Erase Display',
    '\x1b[H': 'Cursor Home',
    '\x1b[0;0H': 'Cursor Home (0,0)',
    '\x1b[1;1H': 'Cursor Home (1,1)',
    '\x1b[s': 'Save Cursor',
    '\x1b[u': 'Restore Cursor',
    '\x1b[K': 'Erase to EOL',
    '\x1b[0K': 'Erase to EOL',
    '\x1b[1K': 'Erase to BOL',
    '\x1b[2K': 'Erase Line',
    '\x1b(B': 'ASCII Charset',
    '\x1b(0': 'Line Drawing',
    '\x1b)0': 'Line Drawing G1',
    '\x1b[6n': 'DSR (cursor pos)',
    '\x1b[0c': 'DA (device attributes)',
    '\x1b[c': 'DA (device attributes)',
    '\x1b[!_': 'Synchronet terminal query',
    '\x1b[J': 'Erase Below',
    '\x1b[0J': 'Erase Below',
    '\x1b[1J': 'Erase Above',
    '\x1b[3J': 'Erase Scrollback',
    '\x1b[L': 'Insert Line',
    '\x1b[M': 'Delete Line',
    '\x1b[P': 'Delete Char',
    '\x1b[@': 'Insert Char',
    '\x1b[G': 'Cursor Column 1',
    '\x1b7': 'Save Cursor (DEC)',
    '\x1b8': 'Restore Cursor (DEC)',
    '\x1bc': 'Full Reset (RIS)',
    '\x1b': 'ESC (bare)',
    '\x1b[0z': 'MXP Open Line',
    '\x1b[1z': 'MXP Secure Line',
    '\x1b[2z': 'MXP Locked Line',
    '\x1b[3z': 'MXP Reset',
    '\x1b[4z': 'MXP Temp Secure',
    '\x1b[5z': 'MXP Lock Open',
    '\x1b[6z': 'MXP Lock Secure',
    '\x1b[7z': 'MXP Lock Locked',
}

_SGR_RE = re.compile(r'\x1b\[([\d;]*)m$')
_CUP_RE = re.compile(r'\x1b\[(\d+);(\d+)H$')
_CUR_MOVE_RE = re.compile(r'\x1b\[(\d*)([ABCDEFG])$')
_SCROLL_RE = re.compile(r'\x1b\[(\d+);(\d+)r$')
_DEC_RE = re.compile(r'\x1b\[\?(\d+)([hl])$')
# Synchronet CTerm proprietary sequences (src/conio/cterm.txt)
_CTERM_RE = re.compile(r'\x1b\[=([0-9;]*)([Mhln{])$')
_FNT_RE = re.compile(r'\x1b\[([0-9;]*) D$')
from blessed.dec_modes import DecPrivateMode as _DecPM
_DEC_PRIVATE_MODES = {
    val: _DecPM._LONG_DESCRIPTIONS.get(val, '')
    for attr in dir(_DecPM)
    if not attr.startswith('_')
    and isinstance((val := getattr(_DecPM, attr)), int)
    and val >= 0
}
_CSI_FINAL_RE = re.compile(r'\x1b\[([0-9;!?]*)([A-Za-z@`~_])$')
_CUR_DIRS = {
    'A': 'Up', 'B': 'Down', 'C': 'Right', 'D': 'Left',
    'E': 'Next Line', 'F': 'Prev Line', 'G': 'Column',
}
_IAC_CMDS = {0xfb: 'WILL', 0xfc: 'WONT', 0xfd: 'DO', 0xfe: 'DONT', 0xfa: 'SB'}
_SGR_PARAMS = {
    0: 'Reset', 1: 'Bold', 2: 'Dim', 3: 'Italic', 4: 'Underline',
    5: 'Blink', 7: 'Reverse', 8: 'Hidden', 9: 'Strikethrough',
    22: 'Normal Intensity', 23: 'No Italic', 24: 'No Underline',
    25: 'No Blink', 27: 'No Reverse', 28: 'No Hidden',
    30: 'Black FG', 31: 'Red FG', 32: 'Green FG', 33: 'Yellow FG',
    34: 'Blue FG', 35: 'Magenta FG', 36: 'Cyan FG', 37: 'White FG',
    38: 'Extended FG', 39: 'Default FG',
    40: 'Black BG', 41: 'Red BG', 42: 'Green BG', 43: 'Yellow BG',
    44: 'Blue BG', 45: 'Magenta BG', 46: 'Cyan BG', 47: 'White BG',
    48: 'Extended BG', 49: 'Default BG',
    90: 'Bright Black FG', 91: 'Bright Red FG', 92: 'Bright Green FG',
    93: 'Bright Yellow FG', 94: 'Bright Blue FG',
    95: 'Bright Magenta FG', 96: 'Bright Cyan FG',
    97: 'Bright White FG',
    100: 'Bright Black BG', 101: 'Bright Red BG',
    102: 'Bright Green BG', 103: 'Bright Yellow BG',
    104: 'Bright Blue BG', 105: 'Bright Magenta BG',
    106: 'Bright Cyan BG', 107: 'Bright White BG',
}
_CSI_FINALS = {
    'J': 'Erase Display', 'K': 'Erase Line', 'L': 'Insert Lines',
    'M': 'Delete Lines', 'P': 'Delete Chars', '@': 'Insert Chars',
    'X': 'Erase Chars', 'S': 'Scroll Up', 'T': 'Scroll Down',
    'n': 'Device Status', 'c': 'Device Attributes',
    's': 'Save Cursor', 'u': 'Restore Cursor',
    'r': 'Scroll Region', 't': 'Window Op',
    'd': 'Cursor Row', 'f': 'Cursor Position',
}


def _name_sgr(params_str):
    """Return a human-readable name for SGR parameters.

    :param params_str: semicolon-separated SGR parameter string
    :returns: descriptive name
    """
    if not params_str:
        return 'SGR Reset'
    parts = params_str.split(';')
    names = []
    i = 0
    while i < len(parts):
        try:
            p = int(parts[i]) if parts[i] else 0
        except ValueError:
            i += 1
            continue
        if p in (38, 48) and i + 1 < len(parts):
            try:
                mode = int(parts[i + 1])
            except ValueError:
                mode = 0
            if mode == 2 and i + 4 < len(parts):
                prefix = 'FG' if p == 38 else 'BG'
                names.append(f'24-bit {prefix}')
                i += 5
                continue
            if mode == 5 and i + 2 < len(parts):
                prefix = 'FG' if p == 38 else 'BG'
                names.append(f'256-color {prefix}')
                i += 3
                continue
        name = _SGR_PARAMS.get(p)
        if name:
            names.append(name)
        else:
            names.append(str(p))
        i += 1
    return 'SGR ' + ', '.join(names)


def _classify_seq(seq):
    """Classify an escape sequence into a human-readable category.

    :param seq: raw sequence string
    :returns: friendly name string
    """
    if seq in _SEQ_NAMES:
        return _SEQ_NAMES[seq]

    m = _SGR_RE.match(seq)
    if m:
        return _name_sgr(m.group(1))

    m = _CUP_RE.match(seq)
    if m:
        return f'Cursor Position ({m.group(1)},{m.group(2)})'

    m = _CUR_MOVE_RE.match(seq)
    if m:
        n = m.group(1) or '1'
        return f'Cursor {_CUR_DIRS[m.group(2)]} {n}'

    m = _SCROLL_RE.match(seq)
    if m:
        return f'Scroll Region ({m.group(1)},{m.group(2)})'

    m = _DEC_RE.match(seq)
    if m:
        num = int(m.group(1))
        action = 'Set' if m.group(2) == 'h' else 'Reset'
        desc = _DEC_PRIVATE_MODES.get(num)
        if desc:
            return f'{action}: {desc}'
        return f'DEC Private Mode {action} ?{num}'

    # Synchronet CTerm proprietary CSI = sequences (cterm.txt)
    m = _CTERM_RE.match(seq)
    if m:
        params, final = m.group(1), m.group(2)
        cterm_names = {
            'M': 'CTerm Set ANSI Music',
            'h': 'CTerm Mode Set',
            'l': 'CTerm Mode Reset',
            'n': 'CTerm State Request',
            '{': 'CTerm Set Font (deprecated)',
        }
        name = cterm_names.get(final, f'CTerm {final}')
        return f'{name} ({params})' if params else name

    # CSI Ps1 ; Ps2 SP D — FNT font select (cterm.txt)
    m = _FNT_RE.match(seq)
    if m:
        return f'FNT Font Select ({m.group(1)})'

    m = _CSI_FINAL_RE.match(seq)
    if m:
        name = _CSI_FINALS.get(m.group(2))
        if name:
            params = m.group(1)
            return f'{name} ({params})' if params else name

    if seq.startswith('\x1b]'):
        return 'OSC'

    if seq == '\x1b[':
        return 'CSI (truncated)'

    if seq.startswith('\xff'):
        if len(seq) >= 2:
            cmd = ord(seq[1])
            name = _IAC_CMDS.get(cmd, f'0x{cmd:02x}')
            if len(seq) >= 3:
                opt = ord(seq[2])
                return f'IAC {name} {opt}'
            return f'IAC {name}'
        return 'IAC'

    return repr(seq)


def analyze_escape_sequences(servers):
    """Count unique servers using each escape sequence category.

    Iterates over all server banners (before + after), classifies each
    escape sequence found via :func:`_classify_seq`, and counts how
    many distinct servers use each category.

    :param servers: list of server record dicts
    :returns: Counter mapping category name to number of servers
    """
    category_servers = Counter()
    total_with_banner = 0

    for s in servers:
        banner = (s.get('banner_before') or '') + (s.get('banner_after') or '')
        if not banner:
            continue
        total_with_banner += 1

        seen_categories = set()
        for segment, is_seq in wcwidth.iter_sequences(banner):
            if is_seq:
                category = _classify_seq(segment)
                seen_categories.add(category)

        for cat in seen_categories:
            category_servers[cat] += 1

    return category_servers, total_with_banner


def display_top_sequences(servers, limit=100):
    """Print RST table of the most common escape sequences across banners.

    Counts distinct banners containing each raw escape sequence and
    displays the top *limit* entries ranked by frequency.

    :param servers: list of server record dicts
    :param limit: number of sequences to show
    """
    seq_banners = Counter()
    total_with_banner = 0

    for s in servers:
        banner = (s.get('banner_before') or '') + (s.get('banner_after') or '')
        if not banner:
            continue
        total_with_banner += 1

        seen = set()
        for segment, is_seq in wcwidth.iter_sequences(banner):
            if is_seq:
                seen.add(segment)
        for seq in seen:
            seq_banners[seq] += 1

    if not seq_banners:
        return

    _rst_heading("Common Escape Sequences", '-')
    print(f"Top {limit} escape sequences by number of unique banners"
          f" (of {total_with_banner:,} total).")
    print()

    rows = []
    for seq, count in seq_banners.most_common(limit):
        pct = f'{count / total_with_banner * 100:.1f}%'
        rows.append({
            'Sequence': f'``{repr(seq)}``',
            'Name': _classify_seq(seq),
            'Banners': str(count),
            '%': pct,
        })

    table_str = tabulate_mod.tabulate(rows, headers='keys', tablefmt='rst')
    print_datatable(table_str, caption="Common Escape Sequences")


# ---------------------------------------------------------------------------
# RST helpers
# ---------------------------------------------------------------------------

def _rst_heading(title, char):
    """Print an RST section heading with the given underline character."""
    print(title)
    print(char * max(wcwidth.width(title, control_codes='ignore'), 4))
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


def _find_similar_banners(servers, default_encoding=None, threshold=95.0):
    """Find servers whose banners are similar but not identical.

    Compares normalized visible banner text across servers using fuzzy
    string matching.  Exact duplicates (already handled by
    :func:`_group_by_banner`) are excluded from the results.

    To keep the comparison tractable, banners are first bucketed by
    approximate length and only cross-compared within a window where
    similarity above *threshold* is geometrically possible.

    :param servers: list of server records
    :param default_encoding: passed to :func:`_combine_banners`
    :param threshold: minimum similarity ratio (0--100) to report
    :returns: dict mapping ``(host, port)`` to list of dicts with
        keys ``server`` and ``score``
    """
    from rapidfuzz import fuzz

    # Build normalized text per server, keyed by (host, port).
    entries = []
    for s in servers:
        banner = _combine_banners(s, default_encoding=default_encoding)
        if not banner or _is_garbled(banner):
            continue
        visible = _strip_mxp_sgml(_strip_ansi(banner))
        normalized = ' '.join(visible.split())
        if not normalized:
            continue
        key = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
        entries.append({
            'server': s,
            'text': normalized,
            'length': len(normalized),
            'hash': key,
        })

    # Sort by length for efficient windowed comparison.
    entries.sort(key=lambda e: e['length'])

    # Pre-compute the minimum length ratio required.
    ratio_floor = threshold / 100.0

    result = {}
    n = len(entries)
    for i in range(n):
        for j in range(i + 1, n):
            # Length pre-filter: short/long < ratio_floor means
            # similarity cannot reach threshold.
            if entries[i]['length'] < entries[j]['length'] * ratio_floor:
                break
            # Skip exact duplicates — already grouped elsewhere.
            if entries[i]['hash'] == entries[j]['hash']:
                continue
            score = fuzz.ratio(
                entries[i]['text'], entries[j]['text'],
                score_cutoff=threshold)
            if score:
                for src, tgt in ((i, j), (j, i)):
                    src_key = (entries[src]['server']['host'],
                               entries[src]['server']['port'])
                    rec = {'server': entries[tgt]['server'],
                           'score': score}
                    result.setdefault(src_key, []).append(rec)

    # Sort each server's similar list by descending score.
    for similars in result.values():
        similars.sort(key=lambda r: -r['score'])

    if result:
        total_pairs = sum(len(v) for v in result.values()) // 2
        print(f"  found {total_pairs} similar-banner pairs"
              f" across {len(result)} servers"
              f" (threshold {threshold}%)", file=sys.stderr)

    return result


def _merge_similar_banner_groups(groups, default_encoding=None,
                                 threshold=95.0):
    """Merge banner groups whose representative text is fuzzy-similar.

    Groups produced by :func:`_group_by_banner` are compared pairwise
    (using the same length pre-filter and rapidfuzz ratio as
    :func:`_find_similar_banners`).  Similar groups are merged: the
    largest group keeps its banner image and the smaller groups' servers
    are added as ``similar_servers`` with their similarity score.

    :param groups: dict from :func:`_group_by_banner`
    :param default_encoding: used only for logging context
    :param threshold: minimum similarity ratio (0--100)
    :returns: list of group dicts, each with an additional
        ``similar_servers`` key (list of ``(server, score)`` tuples)
    """
    from rapidfuzz import fuzz

    # Build an indexed list of (hash_key, normalized_text, group).
    entries = []
    for key, group in groups.items():
        banner = group['banner']
        visible = _strip_mxp_sgml(_strip_ansi(banner))
        normalized = ' '.join(visible.split())
        entries.append({
            'key': key,
            'text': normalized,
            'length': len(normalized),
            'group': group,
        })
    entries.sort(key=lambda e: e['length'])

    ratio_floor = threshold / 100.0

    # Union-Find to cluster similar groups.
    parent = list(range(len(entries)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            # Attach smaller cluster to larger.
            sa = len(entries[ra]['group']['servers'])
            sb = len(entries[rb]['group']['servers'])
            if sa < sb:
                ra, rb = rb, ra
            parent[rb] = ra

    scores = {}
    n = len(entries)
    for i in range(n):
        for j in range(i + 1, n):
            if entries[i]['length'] < entries[j]['length'] * ratio_floor:
                break
            score = fuzz.ratio(
                entries[i]['text'], entries[j]['text'],
                score_cutoff=threshold)
            if score:
                union(i, j)
                scores[(i, j)] = score
                scores[(j, i)] = score

    # Collect clusters.
    clusters = {}
    for i in range(n):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    merged = []
    total_merged = 0
    for root, members in clusters.items():
        # The root's group is the primary (largest).
        primary = entries[root]['group']
        result_group = dict(primary)
        result_group['similar_servers'] = []
        for idx in members:
            if idx == root:
                continue
            score = scores.get((root, idx)) or scores.get((idx, root))
            if score is None:
                # Transitive — find best score via any shared member.
                for other in members:
                    s = scores.get((idx, other)) or scores.get(
                        (other, idx))
                    if s is not None:
                        score = s
                        break
            if score is None:
                score = threshold
            for s in entries[idx]['group']['servers']:
                result_group['similar_servers'].append((s, score))
            total_merged += 1
        result_group['similar_servers'].sort(
            key=lambda t: (-t[1], t[0]['host'].lower()))
        merged.append(result_group)

    if total_merged:
        print(f"  merged {total_merged} similar banner groups"
              f" in gallery (threshold {threshold}%)",
              file=sys.stderr)

    return merged


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

def _generate_rst(rst_path, display_fn, *args, **kwargs):
    """Generate an RST file by calling *display_fn* under redirect_stdout.

    :param rst_path: path to the output RST file
    :param display_fn: callable that prints RST to stdout
    :param args: positional arguments forwarded to *display_fn*
    :param kwargs: keyword arguments forwarded to *display_fn*
    :returns: return value of *display_fn*
    """
    with open(rst_path, 'w') as fout, \
            contextlib.redirect_stdout(fout):
        result = display_fn(*args, **kwargs)
    print(f"  wrote {rst_path}", file=sys.stderr)
    return result


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
    if os.path.getsize(output_path) == 0:
        return True
    out_mtime = os.path.getmtime(output_path)
    for src in source_paths:
        if src and os.path.isfile(src) and os.path.getmtime(src) > out_mtime:
            return True
    return False


_IMAGE_RE = re.compile(r'^\.\. image:: /(_static/banners/\S+)', re.MULTILINE)


def _rst_references_missing_images(rst_path, docs_dir):
    """Check if an RST file references banner images that do not exist.

    :param rst_path: path to the RST file
    :param docs_dir: root docs directory (e.g. ``docs-bbs/``)
    :returns: True if any referenced banner image is missing on disk
    """
    try:
        with open(rst_path, 'r') as f:
            content = f.read()
    except OSError:
        return False
    for m in _IMAGE_RE.finditer(content):
        img_path = os.path.join(docs_dir, m.group(1))
        if not os.path.isfile(img_path):
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


def _group_small_slices(labels, counts, max_other=0.25,
                        min_count=None):
    """Group pie slices into 'Other'.

    Keeps the largest slices until they cover at least
    ``1 - max_other`` of the total, then groups the remainder.
    If *min_count* is given, slices at or below that absolute count
    are always grouped regardless of their share.

    :param labels: list of label strings
    :param counts: list of corresponding counts
    :param max_other: maximum fraction of total allowed in 'Other'
    :param min_count: absolute count at or below which slices are grouped
    :returns: (labels, counts) with small entries merged into 'Other'
    """
    total = sum(counts)
    if total == 0:
        return labels, counts
    # Sort descending so we keep the largest slices first.
    paired = sorted(zip(labels, counts), key=lambda x: -x[1])
    keep_labels, keep_counts = [], []
    kept_total = 0
    other = 0
    target = total * (1 - max_other)
    for label, count in paired:
        if min_count is not None and count <= min_count:
            other += count
        elif kept_total >= target:
            other += count
        else:
            keep_labels.append(label)
            keep_counts.append(count)
            kept_total += count
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


def _create_pie_chart(sorted_items, output_path, min_count=None, top_n=None,
                      group=True):
    """Create a standard pie chart from sorted (label, count) pairs.

    :param sorted_items: list of (label, count) tuples, sorted descending
    :param output_path: path to write the output PNG
    :param min_count: group slices at or below this count into 'Other'
    :param top_n: if set, keep only the top N items before grouping
    :param group: if False, skip grouping small slices into 'Other'
    """
    if not sorted_items:
        return
    if top_n is not None:
        sorted_items = sorted_items[:top_n]
    labels = [s for s, _ in sorted_items]
    counts = [c for _, c in sorted_items]
    if group:
        labels, counts = _group_small_slices(
            labels, counts,
            min_count=min_count)
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


def create_location_plot(stats, output_path, top_n=15):
    """Create pie chart of server locations by country.

    :param stats: statistics dict with ``country_counts`` key
    :param output_path: path to write the output PNG
    :param top_n: keep only the top N countries
    """
    country_counts = stats.get('country_counts', {})
    if not country_counts:
        return
    sorted_items = sorted(country_counts.items(),
                          key=lambda x: x[1], reverse=True)
    _create_pie_chart(sorted_items, output_path, top_n=top_n)


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
            host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', s['host'])
            anchor = f"{filename}_{host_safe}_{s['port']}"
            grouped_keys[(s['host'], s['port'])] = (
                filename, toc_label, anchor)

    for s in servers:
        key = (s['host'], s['port'])
        if key in grouped_keys:
            s[file_key], s[toc_key], s['_detail_anchor'] = (
                grouped_keys[key])
        else:
            s[file_key] = filename_fn(s)
            s[toc_key] = standalone_label_fn(s)
            s['_detail_anchor'] = ''


def display_fingerprint_summary(servers, server_label_fn):
    """Print summary table of protocol fingerprints.

    :param servers: list of server records
    :param server_label_fn: callable(server) -> display label string
    """
    print(_render_template('fingerprint_summary.rst.j2'),
          end='')

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
            'Fingerprint': f':ref:`{fp[:12]}\u2026 <fp_{fp}>`',
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

    def _fmt_opts(opts):
        return ', '.join(f"``{o}``" for o in sorted(opts))

    refused_display = [
        o for o in sorted(sample['refused'])
        if o in TELNET_OPTIONS_OF_INTEREST
    ]
    other_refused = (len(sample['refused'])
                     - len(refused_display))
    negotiated_offered = sorted(
        k for k, v in sample['server_offered'].items() if v)
    negotiated_requested = sorted(
        k for k, v in sample['server_requested'].items()
        if v)

    print(_render_template(
        'fingerprint_options.rst.j2',
        fp_hash=fp_hash,
        server_count=len(fp_servers),
        offered=(_fmt_opts(sample['offered'])
                 if sample['offered'] else None),
        requested=(_fmt_opts(sample['requested'])
                   if sample['requested'] else None),
        refused_display=(_fmt_opts(refused_display)
                         if refused_display else None),
        other_refused=other_refused,
        negotiated_offered=(_fmt_opts(negotiated_offered)
                            if negotiated_offered else None),
        negotiated_requested=(
            _fmt_opts(negotiated_requested)
            if negotiated_requested else None),
        dsr_requests=sample.get('dsr_requests', 0),
        dsr_replies=sample.get('dsr_replies', 0),
    ))


def display_encoding_groups(servers, detail_subdir, file_key,
                            server_label_fn, server_sort_key, tls_fn,
                            figure_path=None):
    """Print servers-by-encoding page.

    :param servers: list of server records
    :param detail_subdir: subdirectory for detail links (e.g. ``'bbs_detail'``)
    :param file_key: record key for the detail filename (e.g. ``'_bbs_file'``)
    :param server_label_fn: callable(server) -> display label string
    :param server_sort_key: callable(server) -> sort key
    :param tls_fn: callable(server) -> truthy if TLS supported
    :param figure_path: optional relative path to a plot image to embed
    """
    by_encoding = {}
    for s in servers:
        key = s['display_encoding']
        by_encoding.setdefault(key, []).append(s)

    groups = []
    for name, members in sorted(
            by_encoding.items(),
            key=lambda x: (-len(x[1]), x[0])):
        sorted_members = []
        for s in sorted(members, key=server_sort_key):
            sorted_members.append({
                '_label': server_label_fn(s),
                '_detail_file': s[file_key],
                '_tls': _copy_btn_markup(s, tls_fn),
            })
        groups.append((name, sorted_members))

    print(_render_template(
        'encoding_groups.rst.j2',
        groups=groups,
        detail_subdir=detail_subdir,
        figure_path=figure_path,
    ))


def display_location_groups(servers, detail_subdir, file_key,
                            server_label_fn, server_sort_key, tls_fn,
                            figure_path=None):
    """Print servers-by-location page.

    :param servers: list of server records (must have ``_country_code``
        and ``_country_name`` keys)
    :param detail_subdir: subdirectory for detail links (e.g. ``'bbs_detail'``)
    :param file_key: record key for the detail filename (e.g. ``'_bbs_file'``)
    :param server_label_fn: callable(server) -> display label string
    :param server_sort_key: callable(server) -> sort key
    :param tls_fn: callable(server) -> truthy if TLS supported
    :param figure_path: optional relative path to a plot image to embed
    """
    from .geoip import _country_flag

    by_country = {}
    for s in servers:
        code = s.get('_country_code', '')
        name = s.get('_country_name', 'Unknown')
        key = code or 'XX'
        by_country.setdefault(key, (name, []))[1].append(s)

    groups = []
    for key, (name, members) in sorted(
            by_country.items(),
            key=lambda x: (-len(x[1][1]), x[1][0])):
        flag = (_country_flag(key) + ' '
                if key != 'XX' else '')
        sorted_members = []
        for s in sorted(members, key=server_sort_key):
            sorted_members.append({
                '_label': server_label_fn(s),
                '_detail_file': s[file_key],
                '_tls': _copy_btn_markup(s, tls_fn),
            })
        groups.append((key, flag, name, sorted_members))

    print(_render_template(
        'location_groups.rst.j2',
        groups=groups,
        detail_subdir=detail_subdir,
        figure_path=figure_path,
    ))


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


def _prepare_banner_page_groups(page_groups, file_key,
                                 server_name_fn, tls_fn):
    """Enrich banner groups with template-ready attributes.

    :param page_groups: list of banner group dicts
    :param file_key: record key for detail filename
    :param server_name_fn: callable(server) -> display name
    :param tls_fn: callable(server) -> truthy if TLS supported
    :returns: list of enriched group dicts
    """
    from .geoip import _country_flag
    enriched = []
    for group in page_groups:
        g = dict(group)
        enriched_servers = []
        for s in group['servers']:
            sd = dict(s)
            sd['_name'] = server_name_fn(s)
            sd['_detail_file'] = s[file_key]
            sd['_detail_anchor'] = s.get('_detail_anchor', '')
            sd['_tls'] = _copy_btn_markup(s, tls_fn)
            sd['_flag'] = _country_flag(s.get('_country_code', ''))
            enriched_servers.append(sd)
        g['servers'] = enriched_servers
        enriched_similar = []
        for s, score in group.get('similar_servers', []):
            sd = dict(s)
            sd['_name'] = server_name_fn(s)
            sd['_detail_file'] = s[file_key]
            sd['_detail_anchor'] = s.get('_detail_anchor', '')
            sd['_tls'] = _copy_btn_markup(s, tls_fn)
            sd['_flag'] = _country_flag(s.get('_country_code', ''))
            sd['_score'] = f"{score:.0f}"
            enriched_similar.append(sd)
        g['similar_servers'] = enriched_similar
        enriched.append(g)
    return enriched


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
    merged = _merge_similar_banner_groups(
        groups, default_encoding=default_encoding)

    if server_sort_key is None:
        server_sort_key = lambda g: g['servers'][0]['host'].lower()  # noqa: E731

    sorted_groups = sorted(
        merged,
        key=server_sort_key)

    total_groups = len(sorted_groups)
    total_servers = sum(len(g['servers']) for g in sorted_groups)

    pages = []
    for i in range(0, max(len(sorted_groups), 1), page_size):
        pages.append(sorted_groups[i:i + page_size])
    total_pages = len(pages)

    # Compute labels for all pages
    page_labels = [
        (p + 1, _page_initial_range(pg, server_name_fn))
        for p, pg in enumerate(pages)
    ]

    # Write landing page: banner_gallery.rst
    landing_path = os.path.join(docs_path, "banner_gallery.rst")
    with open(landing_path, 'w') as fout:
        fout.write(_render_template(
            'banner_gallery_landing.rst.j2',
            entity_name=entity_name,
            total_groups=total_groups,
            total_servers=total_servers,
            page_labels=page_labels,
        ))
    print(f"  wrote {landing_path}", file=sys.stderr)

    # Write content pages: banner_gallery_1.rst .. _N.rst
    for page_num, page_groups in enumerate(pages, 1):
        page_label = _page_initial_range(
            page_groups, server_name_fn)
        rst_path = os.path.join(
            docs_path, f"banner_gallery_{page_num}.rst")
        enriched = _prepare_banner_page_groups(
            page_groups, file_key, server_name_fn, tls_fn)
        with open(rst_path, 'w') as fout:
            fout.write(_render_template(
                'banner_gallery_page.rst.j2',
                page_groups=enriched,
                page_num=page_num,
                total_pages=total_pages,
                page_label=page_label,
                detail_subdir=detail_subdir,
            ))
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
    """Create stacked bar chart of telnet option negotiation patterns."""
    offered = stats['option_offered']
    requested = stats['option_requested']
    both = stats.get('option_both', {})

    all_opts = set()
    for opt in TELNET_OPTIONS_OF_INTEREST:
        if offered.get(opt, 0) > 0 or requested.get(opt, 0) > 0 or both.get(opt, 0) > 0:
            all_opts.add(opt)
    for opt, count in offered.items():
        if count >= 3:
            all_opts.add(opt)
    for opt, count in requested.items():
        if count >= 3:
            all_opts.add(opt)
    for opt, count in both.items():
        if count >= 3:
            all_opts.add(opt)

    if not all_opts:
        return

    options = sorted(all_opts,
                     key=lambda o: offered.get(o, 0) + requested.get(o, 0) + both.get(o, 0),
                     reverse=True)
    offered_counts = [offered.get(o, 0) for o in options]
    requested_counts = [requested.get(o, 0) for o in options]
    both_counts = [both.get(o, 0) for o in options]

    x = np.arange(len(options))
    width = 0.6

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x, offered_counts, width,
           label='Server Offers',
           color=PLOT_GREEN, edgecolor='#222222', alpha=0.85)
    ax.bar(x, requested_counts, width,
           bottom=offered_counts,
           label='Server Requests',
           color=PLOT_CYAN, edgecolor='#222222', alpha=0.85)
    bottom_both = [o + r for o, r in zip(offered_counts, requested_counts)]
    ax.bar(x, both_counts, width,
           bottom=bottom_both,
           label='Server Both',
           color=PLOT_YELLOW, edgecolor='#222222', alpha=0.85)

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


def _classify_option(servers, option_name):
    """Classify servers by negotiation direction for a telnet option.

    :param servers: list of server records
    :param option_name: telnet option name (e.g. ``'CHARSET'``, ``'BINARY'``)
    :returns: tuple of (both, will_only, do_only) server lists
    """
    both = []
    will_only = []
    do_only = []
    for s in servers:
        has_will = option_name in s['offered']
        has_do = option_name in s['requested']
        if has_will and has_do:
            both.append(s)
        elif has_will:
            will_only.append(s)
        elif has_do:
            do_only.append(s)
    return both, will_only, do_only


def create_option_pie_chart(servers, option_name, output_path):
    """Create a pie chart of negotiation support for a telnet option.

    Slices are: Bi-directional, WILL only, DO only, None.

    :param servers: list of server records
    :param option_name: telnet option name (e.g. ``'CHARSET'``)
    :param output_path: path to write the output PNG
    """
    both, will_only, do_only = _classify_option(servers, option_name)
    none_count = (len(servers)
                  - len(both) - len(will_only) - len(do_only))
    items = [
        ('Bi-directional', len(both)),
        ('WILL only', len(will_only)),
        ('DO only', len(do_only)),
        ('None', none_count),
    ]
    items = [(label, count) for label, count in items if count > 0]
    _create_pie_chart(items, output_path, group=False)


def display_charset_section(servers):
    """Print CHARSET and BINARY sections for the statistics page.

    :param servers: list of server records
    """
    _rst_heading("CHARSET", '-')

    print("The default encoding of Telnet is the system locale, usually")
    print("UTF-8. By strict compliance, without negotiation of BINARY")
    print("transmission all protocol text *should* be limited to 7-bit")
    print("ASCII. The encoding used *should* be negotiated by CHARSET.")
    print()
    print("Any server capable of negotiating CHARSET or LANG through")
    print("NEW_ENVIRON is also presumed to support BINARY, regardless")
    print("of its response to the BINARY telnet option. In practice,")
    print("many servers transmit 8-bit data without negotiating either")
    print("mode.")
    print()

    total = len(servers)
    charset_both, charset_will, charset_do = _classify_option(
        servers, 'CHARSET')
    charset_any = len(charset_both) + len(charset_will) + len(charset_do)

    print(".. figure:: _static/plots/charset.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the proportion of servers"
          " that negotiate the CHARSET telnet option.")
    print()
    print(f"   {charset_any} of {total} servers negotiate CHARSET"
          f" ({100 * charset_any / total:.1f}%).")
    print()

    _rst_heading("BINARY", '-')

    binary_both, binary_will, binary_do = _classify_option(
        servers, 'BINARY')
    binary_any = len(binary_both) + len(binary_will) + len(binary_do)

    print(".. figure:: _static/plots/binary.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the proportion of servers"
          " that negotiate the BINARY telnet option.")
    print()
    print(f"   {binary_any} of {total} servers negotiate BINARY"
          f" ({100 * binary_any / total:.1f}%).")
    print()



# ---------------------------------------------------------------------------
# Unified detail page helpers
# ---------------------------------------------------------------------------

def _render_banner_section(server, banners_path, default_encoding=None,
                           ice_colors=False):
    """Render banner and return RST text.

    Also sets ``server['_banner_png']`` and
    ``server['_banner_display_width']`` as side effects.

    :param server: server record dict
    :param banners_path: directory for banner PNGs
    :param default_encoding: default encoding for banner combining
    :param ice_colors: if True, treat SGR 5 (blink) as bright background
    :returns: RST string (may be empty)
    """
    banner = _combine_banners(
        server, default_encoding=default_encoding)
    effective_enc = server.get('encoding_override') or (
        default_encoding or server['display_encoding'])
    if banner and not _is_garbled(banner):
        label = (f"{server['host']}:{server['port']}"
                 f" ({server.get('data_path', '?')})")
        banner_fname, display_w = _banner_to_png(
            banner, banners_path, effective_enc,
            columns=server.get('column_override'),
            rows=server.get('row_override'),
            no_ambig=server.get('no_ambig_override', False),
            ice_colors=ice_colors,
            server_label=label)
        if banner_fname:
            server['_banner_png'] = banner_fname
            if display_w:
                server['_banner_display_width'] = display_w
            return _render_template(
                'banner_image.rst.j2',
                banner_fname=banner_fname,
                alt_text=_rst_escape(_banner_alt_text(banner)),
                display_w=display_w) + '\n'
    elif banner:
        if default_encoding:
            return ("*Banner not shown (legacy encoding"
                    " not supported).*\n\n")
        return ("*Banner not shown -- this server likely"
                " uses a legacy encoding such as CP437.*\n\n")
    return ''


def _render_similar_banners(server, similar_banners, file_key,
                            server_name_fn=None):
    """Render similar-banner note for a server detail page.

    :param server: server record dict
    :param similar_banners: dict from :func:`_find_similar_banners`
    :param file_key: record key for detail filename (e.g. ``'_bbs_file'``)
    :param server_name_fn: callable(server) -> display name
    :returns: RST string (may be empty)
    """
    if not similar_banners:
        return ''
    key = (server['host'], server['port'])
    similars = similar_banners.get(key)
    if not similars:
        return ''
    if server_name_fn is None:
        server_name_fn = lambda s: f"{s['host']}:{s['port']}"  # noqa: E731
    from .geoip import _country_flag
    enriched = []
    for sim in similars:
        s = sim['server']
        enriched.append({
            '_name': server_name_fn(s),
            '_detail_file': s.get(file_key, ''),
            '_detail_anchor': s.get('_detail_anchor', ''),
            '_flag': _country_flag(s.get('_country_code', '')),
            '_score': f"{sim['score']:.0f}",
        })
    min_score = enriched[-1]['_score']
    return _render_template(
        'similar_banners.rst.j2',
        similars=enriched,
        min_score=min_score) + '\n'


def _render_json_section(server, data_dir, mode):
    """Render collapsible JSON section.

    :param server: server record dict
    :param data_dir: path to data directory
    :param mode: ``'mud'`` or ``'bbs'``
    :returns: RST string (may be empty)
    """
    data_path = server.get('data_path', '')
    if not data_path or not data_dir:
        return ''
    json_file = os.path.join(data_dir, "server", data_path)
    if mode == 'mud':
        desc = ("The complete JSON record collected during"
                " the scan,\nincluding Telnet negotiation"
                " results and any\nMSSP metadata.")
    else:
        desc = ("The complete JSON record collected during"
                " the scan,\nincluding Telnet negotiation"
                " results and\nbanner data.")

    raw_json = ''
    if os.path.isfile(json_file):
        with open(json_file, encoding='utf-8',
                  errors='surrogateescape') as jf:
            raw_json = jf.read().rstrip()
    if not raw_json:
        return ''
    return _render_template(
        'collapsible_json.rst.j2',
        description=desc,
        json_lines=raw_json.split('\n')) + '\n'


def _render_log_section(server, logs_dir, sec_char):
    """Render collapsible connection log section.

    :param server: server record dict
    :param logs_dir: path to log directory
    :param sec_char: RST underline character
    :returns: RST string (may be empty)
    """
    if not logs_dir:
        return ''
    host = server['host']
    port = server['port']
    log_path = os.path.join(logs_dir, f"{host}:{port}.log")
    if not os.path.isfile(log_path):
        return ''
    with open(log_path, encoding='utf-8',
              errors='surrogateescape') as lf:
        log_text = lf.read().rstrip()
    if not log_text:
        return ''
    log_lines = []
    for line in log_text.split('\n'):
        log_lines.extend(_clean_log_line(line))
    heading = f"Connection Log\n{sec_char * 14}\n\n"
    return heading + _render_template(
        'collapsible_log.rst.j2',
        log_lines=log_lines,
        host=host,
        port=port) + '\n'


def _render_fingerprint_section(server, sec_char, fp_counts=None):
    """Render telnet fingerprint section.

    :param server: server record dict
    :param sec_char: RST underline character
    :param fp_counts: dict mapping fingerprint to count
    :returns: RST string
    """
    fp = server['fingerprint']
    lines = []
    title = "Telnet Fingerprint"
    lines.append(title)
    lines.append(sec_char * len(title))
    lines.append('')
    lines.append(f":ref:`{fp} <fp_{fp}>`")
    lines.append('')
    if fp_counts:
        other_count = fp_counts.get(fp, 1) - 1
        if other_count > 0:
            word = 'server' if other_count == 1 else 'servers'
            lines.append(f"*This fingerprint is shared by"
                         f" {other_count} other {word}.*")
        else:
            lines.append("*This fingerprint is unique"
                         " to this server.*")
        lines.append('')
    if server['offered']:
        lines.append(
            "**Options offered by server**: "
            + ', '.join(f"``{o}``"
                        for o in sorted(server['offered'])))
        lines.append('')
    if server['requested']:
        lines.append(
            "**Options requested from client**: "
            + ', '.join(f"``{o}``"
                        for o in sorted(server['requested'])))
        lines.append('')
    return '\n'.join(lines) + '\n'
