#!/usr/bin/env python
"""Generate RST documentation and matplotlib plots from MUD server fingerprint data.

Reads JSON session files from telnetlib3's data directory and produces:
- docs/statistics.rst: summary stats and plots
- docs/server_list.rst: searchable server table
- docs/fingerprints.rst: fingerprint summary with links to detail pages
- docs/servers.rst: index of per-MUD detail pages
- docs/server_detail/*.rst: per-fingerprint detail pages
- docs/mud_detail/*.rst: per-MUD detail pages
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
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import tabulate as tabulate_mod
import wcwidth
from ansi2html import Ansi2HTMLConverter

_ANSI_CONV = Ansi2HTMLConverter(inline=True, dark_bg=True, scheme='xterm')

DOCS_PATH = os.path.join(os.path.dirname(__file__), "docs-muds")
PLOTS_PATH = os.path.join(DOCS_PATH, "_static", "plots")
STATIC_PATH = os.path.join(DOCS_PATH, "_static")
DETAIL_PATH = os.path.join(DOCS_PATH, "server_detail")
MUD_DETAIL_PATH = os.path.join(DOCS_PATH, "mud_detail")
LINK_REGEX = re.compile(r'[^a-zA-Z0-9]')
_URL_RE = re.compile(r'https?://[^\s<>"\']+')
_MSSP_URL_SKIP = frozenset(('DISCORD', 'ICON'))
GITHUB_DATA_BASE = ("https://github.com/jquast/modem.xyz"
                     "/tree/master/data-muds/server")

# MUD protocols we track (from MSSP flags and/or telnet negotiation)
MUD_PROTOCOLS = [
    'MSSP', 'GMCP', 'MSDP', 'MCCP', 'MCCP2',
    'MXP', 'MSP', 'MCP', 'ZMP',
]

# Telnet options we care about for display
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

LOCITERM_URL = 'https://lociterm.com/telnetsupport.json'


def _load_telnetsupport(data_dir):
    """Fetch or load the LociTerm telnetsupport.json server list.

    Attempts to download a fresh copy from lociterm.com, falling back to
    a local cached copy if the fetch fails.

    :param data_dir: path to data directory
    :returns: dict mapping ``(host, port)`` to entry dict
    """
    import urllib.request

    local_path = os.path.join(data_dir, 'telnetsupport.json')

    # Try to fetch fresh copy
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
            print(f"  loaded local telnetsupport.json ({len(data)} entries)",
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

    Sets ``_loci_supported`` and ``_loci_ssl`` on each server record.

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


def load_server_data(data_dir):
    """Load all server fingerprint JSON files from the data directory.

    :param data_dir: path to telnetlib3 data directory
    :returns: list of parsed server record dicts
    """
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
            mssp = session_data.get('mssp', {})
            option_states = session_data.get('option_states', {})

            # Use the most recent session
            session = sessions[-1]

            record = {
                'host': session.get('host', session.get('ip', 'unknown')),
                'ip': session.get('ip', ''),
                'port': session.get('port', 0),
                'connected': session.get('connected', ''),
                'fingerprint': probe.get('fingerprint', fp_dir),
                'data_path': f"{fp_dir}/{fname}",
                'offered': fp_data.get('offered-options', []),
                'requested': fp_data.get('requested-options', []),
                'refused': fp_data.get('refused-options', []),
                'server_offered': option_states.get('server_offered', {}),
                'server_requested': option_states.get('server_requested', {}),
                'encoding': session_data.get('encoding', 'unknown'),
                'banner_before': session_data.get('banner_before_return', ''),
                'banner_after': session_data.get('banner_after_return', ''),
                'timing': session_data.get('timing', {}),
                'has_mssp': bool(mssp),
                'mssp': mssp,
                # Extract commonly used MSSP fields
                'name': _first_str(mssp.get('NAME', '')),
                'codebase': ', '.join(_listify(mssp.get('CODEBASE', ''))),
                'family': ', '.join(_listify(mssp.get('FAMILY', ''))),
                'genre': ', '.join(_listify(mssp.get('GENRE', ''))),
                'gameplay': ', '.join(_listify(mssp.get('GAMEPLAY', ''))),
                'players': _parse_int(mssp.get('PLAYERS', '')),
                'created': _first_str(mssp.get('CREATED', '')),
                'status': ', '.join(_listify(mssp.get('STATUS', ''))),
                'website': _first_str(mssp.get('WEBSITE', '')),
                'description': _first_str(mssp.get('DESCRIPTION', '')),
                'location': ', '.join(_listify(mssp.get('LOCATION', ''))),
                'language': ', '.join(_listify(mssp.get('LANGUAGE', ''))),
                'discord': _first_str(mssp.get('DISCORD', '')),
            }

            record['tls_port'] = _detect_tls_port(record)
            record['uptime_days'] = _parse_uptime_days(
                mssp.get('UPTIME', ''), record['connected'])

            # Fallback: scan MSSP for any URL if WEBSITE was not provided
            if not record['website']:
                record['website'] = _find_mssp_url(mssp)

            # Fallback: extract URL from banner text
            if not record['website']:
                for banner_key in ('banner_before', 'banner_after'):
                    banner_text = record[banner_key]
                    if banner_text:
                        match = _URL_RE.search(_strip_ansi(banner_text))
                        if match:
                            record['website'] = match.group(0)
                            break

            # Determine protocol support from both MSSP flags and negotiation
            record['protocols'] = _detect_protocols(record)

            # Infer adult content from MSSP fields
            record['adult'] = _is_adult(record)

            # Detect pay-to-play or pay-for-perks
            record['pay_to_play'] = _is_pay_to_play(record)

            records.append(record)

    return records


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

    :returns: True if MSSP ``ADULT MATERIAL`` is '1' or ``MINIMUM AGE`` >= 18
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

    :returns: True if MSSP ``PAY TO PLAY`` or ``PAY FOR PERKS`` is non-zero
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

    Skips fields already handled separately (DISCORD, ICON, WEBSITE).

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
    """Detect MUD protocol support from MSSP flags and telnet negotiation."""
    protocols = {}
    mssp = record['mssp']
    offered = set(record['offered'])
    requested = set(record['requested'])
    server_offered = record['server_offered']
    server_requested = record['server_requested']

    # All negotiated options (offered + requested that were accepted)
    negotiated = set()
    for opt, accepted in server_offered.items():
        if accepted:
            negotiated.add(opt)
    for opt, accepted in server_requested.items():
        if accepted:
            negotiated.add(opt)

    for proto in MUD_PROTOCOLS:
        # Check MSSP flag first
        mssp_val = mssp.get(proto, '')
        if mssp_val and str(mssp_val) == '1':
            protocols[proto] = 'mssp'
        elif proto in negotiated or proto in offered or proto in requested:
            protocols[proto] = 'negotiated'
        else:
            # Some protocols have hex codes that appear in server_offered
            protocols[proto] = 'no'

    # Special: MSSP is supported if we have MSSP data at all
    if record['has_mssp']:
        protocols['MSSP'] = 'mssp'
    elif 'MSSP' in negotiated:
        protocols['MSSP'] = 'negotiated'

    return protocols


def deduplicate_servers(records):
    """Deduplicate by host:port, keeping the most recent session.

    :param records: list of server record dicts
    :returns: deduplicated list
    """
    by_host_port = {}
    for rec in records:
        key = (rec['host'], rec['port'])
        existing = by_host_port.get(key)
        if existing is None or rec['connected'] > existing['connected']:
            by_host_port[key] = rec
    return sorted(by_host_port.values(), key=lambda r: (r['name'] or r['host']).lower())


def compute_statistics(servers):
    """Compute aggregate statistics from server list.

    :param servers: list of deduplicated server records
    :returns: dict of statistics
    """
    connected_times = sorted(s['connected'] for s in servers if s['connected'])
    stats = {
        'total_servers': len(servers),
        'with_mssp': sum(1 for s in servers if s['has_mssp']),
        'unique_fingerprints': len(set(s['fingerprint'] for s in servers)),
        'total_players': sum(s['players'] or 0 for s in servers),
        'unique_codebases': len(set(
            s['codebase'] for s in servers if s['codebase']
        )),
        'unique_families': len(set(
            s['family'] for s in servers if s['family']
        )),
        'scan_time_first': connected_times[0] if connected_times else '',
        'scan_time_last': connected_times[-1] if connected_times else '',
    }

    # Protocol support counts
    proto_counts = Counter()
    for s in servers:
        for proto, status in s['protocols'].items():
            if status != 'no':
                proto_counts[proto] += 1
    stats['protocol_counts'] = dict(proto_counts)

    # Codebase families
    family_counts = Counter()
    for s in servers:
        if s['family']:
            for fam in _listify(s['mssp'].get('FAMILY', '')):
                if fam:
                    family_counts[fam] += 1
    stats['family_counts'] = dict(family_counts)

    # Specific codebases
    codebase_counts = Counter()
    for s in servers:
        if s['codebase']:
            for cb in _listify(s['mssp'].get('CODEBASE', '')):
                if cb:
                    codebase_counts[cb] += 1
    stats['codebase_counts'] = dict(codebase_counts)


    # Creation years
    year_counts = Counter()
    for s in servers:
        year = s['created']
        if year:
            try:
                year_counts[int(year)] += 1
            except ValueError:
                pass
    stats['year_counts'] = dict(year_counts)

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


def create_protocol_support_plot(stats, output_path):
    """Create horizontal bar chart of MUD protocol support counts."""
    proto_counts = stats['protocol_counts']
    if not proto_counts:
        return

    protocols = sorted(proto_counts.keys(), key=lambda p: proto_counts[p])
    counts = [proto_counts[p] for p in protocols]
    total = stats['total_servers']

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(protocols, counts, color=PLOT_GREEN, edgecolor=PLOT_CYAN,
                   linewidth=0.5, alpha=0.85)

    for bar, count in zip(bars, counts):
        pct = count / total * 100 if total else 0
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                f' {count} ({pct:.0f}%)',
                va='center', color=PLOT_FG, fontsize=10)

    ax.set_xlabel('Number of Servers', fontsize=12)
    ax.set_xlim(0, max(counts) * 1.3 if counts else 10)
    ax.grid(True, axis='x')

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def _group_small_slices(labels, counts, threshold=0.01, min_count=None):
    """Group pie slices into 'Other'.

    Slices are grouped if they fall at or below *threshold* fraction of the
    total, or if *min_count* is given and their count is at or below that
    value.

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


def create_codebase_families_plot(stats, output_path):
    """Create pie chart of codebase families."""
    family_counts = stats['family_counts']
    if not family_counts:
        return

    sorted_items = sorted(family_counts.items(), key=lambda x: x[1], reverse=True)
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

    ax.legend(wedges, [f'{l} ({c})' for l, c in zip(labels, counts)],
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

    top = sorted(codebase_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    labels = [cb for cb, _ in top]
    counts = [c for _, c in top]
    labels, counts = _group_small_slices(labels, counts, min_count=2)
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
    bars = ax.bar([str(y) for y in all_years], counts,
                  color=PLOT_GREEN, edgecolor=PLOT_CYAN,
                  linewidth=0.5, alpha=0.85)

    ax.set_xlabel('Year Created', fontsize=12)
    ax.set_ylabel('Number of MUDs', fontsize=12)
    ax.grid(True, axis='y')

    # Rotate labels for readability
    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight',
                transparent=True, metadata={'CreationDate': None})
    plt.close()


def create_telnet_options_plot(stats, output_path):
    """Create grouped bar chart of telnet option negotiation patterns."""
    offered = stats['option_offered']
    requested = stats['option_requested']

    # Collect all options that were offered or requested (interesting ones)
    all_opts = set()
    for opt in TELNET_OPTIONS_OF_INTEREST:
        if offered.get(opt, 0) > 0 or requested.get(opt, 0) > 0:
            all_opts.add(opt)
    # Also include any with significant counts
    for opt, count in offered.items():
        if count >= 3:
            all_opts.add(opt)
    for opt, count in requested.items():
        if count >= 3:
            all_opts.add(opt)

    if not all_opts:
        return

    # Sort by total (offered + requested), descending
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


_RST_SECTION_RE = re.compile(r'([=\-~#+^"]{4,})')


def _rst_escape(text):
    """Escape text for safe RST inline use."""
    if not text:
        return ''
    result = (text.replace('\\', '\\\\').replace('`', '\\`')
              .replace('*', '\\*').replace('|', '\\|'))
    # Break up runs of RST section/transition characters (=-~#+^") so
    # docutils does not interpret them as headings or transitions.
    result = _RST_SECTION_RE.sub(
        lambda m: m.group(0)[0] + '\u200B' + m.group(0)[1:], result)
    if result.endswith('_'):
        result = result[:-1] + '\\_'
    return result


def _strip_ansi(text):
    """Remove ANSI escape sequences from text."""
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def _is_garbled(text, threshold=0.3):
    """Detect text that is mostly Unicode replacement characters.

    Banners from servers using CP437 or other legacy encodings may arrive
    as strings full of U+FFFD because the scanner decoded them as ASCII.

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

    :param text: banner text possibly containing MXP/SGML
    :returns: cleaned text
    """
    # Strip MXP mode-switch escapes (e.g. \x1b[7z) but keep text that follows
    text = re.sub(r'\x1b\[\d+z', '', text)
    text = re.sub(r'<!--.*?-->', '', text)
    # Strip SGML declarations — full and abbreviated forms
    text = re.sub(r'<!(EL(EMENT)?|ATTLIST|EN(TITY)?)\b.*', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
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


def _combine_banners(server):
    """Combine banner_before and banner_after when they contain unique content.

    Replacement characters (U+FFFD) from failed decoding are stripped so
    that partially decodable banners display cleanly.

    :param server: server record dict
    :returns: combined banner text
    """
    banner_before = (server['banner_before'] or '').replace('\ufffd', '')
    banner_after = (server['banner_after'] or '').replace('\ufffd', '')
    before_clean = _strip_mxp_sgml(_strip_ansi(banner_before)).strip()
    after_clean = _strip_mxp_sgml(_strip_ansi(banner_after)).strip()
    if before_clean and after_clean and after_clean not in before_clean:
        return banner_before.rstrip() + '\r\n' + banner_after.lstrip()
    return banner_before or banner_after


def _truncate(text, maxlen=200):
    """Truncate text to maxlen characters, filtering non-printable bytes."""
    text = _strip_ansi(text)
    text = text.replace('\r\n', '\n').replace('\n\r', '\n').replace('\r', '\n')
    # Filter non-printable characters (keep printable ASCII + common unicode)
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

    # Normalize all line ending variants: \r\n, \n\r, lone \r, lone \n → \n
    text = text.replace('\r\n', '\n').replace('\n\r', '\n').replace('\r', '\n')
    text = _strip_mxp_sgml(text)
    # Strip DEC private mode sequences (e.g. \x1b[?1000h mouse tracking)
    text = re.sub(r'\x1b\[\?[0-9;]*[a-zA-Z]', '', text)
    # Filter control characters but keep ANSI escapes and printable text
    cleaned = []
    i = 0
    while i < len(text):
        if text[i] == '\x1b':
            # Keep the full ANSI escape sequence
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

    # Truncate by lines
    lines = text.split('\n')[:maxlines]
    text = '\n'.join(lines)

    # Truncate by visible character count (ignoring ANSI sequences)
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

    # Wrap long lines to 100 display columns using sequence-aware wrapping
    wrapped_lines = []
    for line in text.split('\n'):
        wrapped = wcwidth.wrap(
            line, width=100, drop_whitespace=False,
            break_long_words=True, break_on_hyphens=False,
        )
        wrapped_lines.extend(wrapped if wrapped else [''])
    text = '\n'.join(wrapped_lines)

    # Convert ANSI to HTML, brighten dark blues for visibility on dark bg
    html_content = _ANSI_CONV.convert(text, full=False)
    html_content = html_content.replace('#0000ee', '#5555ff')
    html_content = html_content.replace('#5c5cff', '#7777ff')
    aria_name = html_mod.escape(name or 'MUD server')
    return (f'<pre class="ansi-banner" role="img"'
            f' aria-label="ANSI art banner for {aria_name}">'
            f'{html_content}</pre>')


def _telnet_url(host, port):
    """Build a telnet:// URL string.

    :param host: hostname
    :param port: port number
    :returns: telnet URL, omitting port if default (23)
    """
    if port == 23:
        return f"telnet://{host}"
    return f"telnet://{host}:{port}"


def _lociterm_url(host, port, tls_port='', loci_ssl=False):
    """Build a LociTerm play URL, preferring TLS when available.

    :param host: hostname
    :param port: primary port number
    :param tls_port: TLS port string from MSSP, or '' if unavailable
    :param loci_ssl: True if telnetsupport.json indicates SSL
    :returns: LociTerm URL string with ``&ssl=1`` when TLS is known
    """
    if tls_port and tls_port not in ('1', str(port)):
        return (f"https://lociterm.com/play/"
                f"?host={host}&port={tls_port}&ssl=1")
    if tls_port or loci_ssl:
        return (f"https://lociterm.com/play/"
                f"?host={host}&port={port}&ssl=1")
    return f"https://lociterm.com/play/?host={host}&port={port}"


def _mud_filename(server):
    """Generate a unique, filesystem-safe filename for a MUD detail page.

    :param server: server record dict
    :returns: sanitized filename string (without .rst extension)
    """
    host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', server['host'])
    return f"{host_safe}_{server['port']}"


def _rst_heading(title, char):
    """Print an RST section heading with the given underline character."""
    print(title)
    print(char * max(len(title), 4))
    print()


def _group_shared_hostname(servers):
    """Group servers sharing a hostname without unique MSSP names.

    Servers with the same hostname and the same display name (MSSP NAME, or
    hostname when no MSSP NAME is set) are grouped for a combined detail page.

    :param servers: list of deduplicated server records
    :returns: dict mapping ``(hostname, display_name)`` to list of servers,
              only for groups with 2+ members
    """
    by_key = {}
    for s in servers:
        display_name = s['name'] or s['host']
        key = (s['host'], display_name)
        by_key.setdefault(key, []).append(s)

    groups = {}
    for key, members in by_key.items():
        if len(members) >= 2:
            groups[key] = sorted(members, key=lambda s: s['port'])
    return groups


def _assign_mud_filenames(servers, hostname_groups):
    """Assign ``_mud_file`` to each server record.

    Grouped servers share a hostname-based filename.  Ungrouped servers use
    the ``host_port`` format from :func:`_mud_filename`.

    :param servers: list of server records (modified in place)
    :param hostname_groups: dict from :func:`_group_shared_hostname`
    """
    grouped_keys = {}
    hosts_with_groups = {}
    for (host, name), members in hostname_groups.items():
        hosts_with_groups.setdefault(host, []).append((name, members))

    for host, host_groups in hosts_with_groups.items():
        host_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', host)
        if len(host_groups) == 1:
            _name, members = host_groups[0]
            for s in members:
                grouped_keys[(s['host'], s['port'])] = host_safe
        else:
            # Multiple groups on same hostname — disambiguate with name
            for name, members in host_groups:
                name_safe = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
                filename = f"{host_safe}_{name_safe}"
                for s in members:
                    grouped_keys[(s['host'], s['port'])] = filename

    for s in servers:
        key = (s['host'], s['port'])
        if key in grouped_keys:
            s['_mud_file'] = grouped_keys[key]
        else:
            s['_mud_file'] = _mud_filename(s)


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
    print(f"- **Servers responding**: {stats['total_servers']}")
    print(f"- **With MSSP data**: {stats['with_mssp']}")
    print(f"- **Unique protocol fingerprints**: {stats['unique_fingerprints']}")
    print(f"- **Unique codebases**: {stats['unique_codebases']}")
    print(f"- **Unique codebase families**: {stats['unique_families']}")
    footnotes = []
    if stats['total_players']:
        print(f"- **Total players online**: {stats['total_players']} [#scan]_")
        scan_time = _format_scan_time(stats['scan_time_last'])
        if scan_time:
            footnotes.append(f".. [#scan] measured {scan_time}")
    print()
    print("These statistics reflect the most recent scan of all servers in the")
    print("`mudlist.txt "
          "<https://github.com/jquast/muds.modem.xyz/blob/master/"
          "data/mudlist.txt>`_ input list.")
    print("Each server is probed using `telnetlib3 "
          "<https://github.com/jquast/telnetlib3>`_,")
    print("which connects to each address, performs Telnet option negotiation,")
    print("and collects any MSSP metadata the server provides.")
    print()
    return footnotes


def display_plots():
    """Print figure directives for all plots."""
    print("The charts below summarize data from servers that report")
    print("MSSP metadata. Servers without MSSP appear in the")
    print(":doc:`server_list` but are not included in these breakdowns.")
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
    print("   Distribution of MUD codebase families (from MSSP data).")
    print()

    print("Top Codebases")
    print("--------------")
    print()
    print(".. figure:: _static/plots/codebases.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Pie chart showing the most common specific"
          " codebase versions across all servers reporting MSSP data.")
    print()
    print("   Most common specific codebase versions.")
    print()

    print("Creation Years")
    print("---------------")
    print()
    print(".. figure:: _static/plots/creation_years.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Bar chart showing when MUDs were created, by year,"
          " spanning from the earliest to the most recent.")
    print()
    print("   When MUDs were created, by year, as reported via MSSP data.")
    print()

    print("Protocol Support")
    print("-----------------")
    print()
    print(".. figure:: _static/plots/protocol_support.png")
    print("   :align: center")
    print("   :width: 800px")
    print("   :alt: Horizontal bar chart showing how many servers support"
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
    print("   :alt: Grouped bar chart comparing how many servers offer"
          " versus request each Telnet option during negotiation.")
    print()
    print("   Telnet options offered vs requested by servers during negotiation.")
    print()


def display_server_table(servers):
    """Print the main server listing table with telnet:// links."""
    print("MUD Servers")
    print("===========")
    print()
    print("All servers that responded to a Telnet connection during the most")
    print("recent scan. Click a column header to sort. Use the search box to")
    print("filter by name, codebase family, or genre.")
    print()
    print(".. list-table:: Column Descriptions")
    print("   :widths: 20 80")
    print("   :class: field-descriptions")
    print()
    print("   * - **Players**")
    print("     - Number of players online at scan time, reported via"
          " MSSP. Blank if the server does not report MSSP.")
    print("   * - **Name**")
    print("     - Server name (from MSSP) or hostname. Links to a detail page.")
    print("   * - **Code/Family**")
    print("     - Codebase and codebase family -- the server"
          " software and its lineage (e.g. PennMUSH/TinyMUD, FluffOS/LPMud).")
    print("   * - **Genre**")
    print("     - Game genre or theme (e.g. Fantasy, Sci-Fi, Social)."
          " Servers detected as adult content (MSSP ``ADULT MATERIAL``"
          " or ``MINIMUM AGE`` >= 18) are tagged with ``/Adult``.")
    print("   * - **Created**")
    print("     - Year the MUD was originally created, from MSSP data.")
    print()

    rows = []
    for s in servers:
        name = s['name'] or s['host']
        mud_file = s['_mud_file']
        name_cell = f":doc:`{_rst_escape(name)} <mud_detail/{mud_file}>`"
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

        # Build Code/Family column: "Codebase/Family" or just one
        codebase = s['codebase'] or ''
        family = s['family'] or ''
        if codebase and family and codebase.lower() != family.lower():
            code_family = f"{codebase}/{family}"
        else:
            code_family = codebase or family

        # Build Genre column, append /Adult if detected
        genre = s['genre'] or ''
        if s['adult'] and 'adult' not in genre.lower():
            genre = f"{genre}/Adult" if genre else 'Adult'

        players = str(s['players']) if s['players'] is not None else ''
        created = s['created'] or ''

        rows.append({
            'Players': players,
            'Name': name_cell,
            'Code/Family': _rst_escape(code_family[:30]),
            'Genre': _rst_escape(genre[:25]),
            'Created': created,
        })

    table_str = tabulate_mod.tabulate(rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="MUD Servers")


def display_fingerprint_summary(servers):
    """Print summary table of protocol fingerprints."""
    print("Fingerprints")
    print("============")
    print()
    print("A fingerprint is a hash of a server's Telnet option negotiation")
    print("behavior -- which options it offers to the client, which it requests")
    print("from the client, and which it refuses. Servers running the same software")
    print("version typically produce identical fingerprints. A majority of servers")
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
    print("     - Sample server names sharing this fingerprint.")
    print()

    # Group by fingerprint
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
        server_names = ', '.join(
            s['name'] or s['host'] for s in fp_servers[:3]
        )
        if len(fp_servers) > 3:
            server_names += f', ... (+{len(fp_servers) - 3})'

        rows.append({
            'Fingerprint': f':ref:`{fp[:16]}... <fp_{fp}>`',
            'Servers': str(len(fp_servers)),
            'Offers': _rst_escape(offered[:30]),
            'Requests': _rst_escape(requested[:30]),
            'Examples': _rst_escape(server_names[:50]),
        })

    table_str = tabulate_mod.tabulate(rows, headers="keys", tablefmt="rst")
    print_datatable(table_str, caption="Protocol Fingerprints")

    # TOC for detail pages
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
        footnotes = display_summary_stats(stats)
        display_plots()
        for fn in footnotes:
            print(fn)
            print()
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
    """Generate the servers.rst index page with toctree to per-MUD pages."""
    rst_path = os.path.join(DOCS_PATH, "servers.rst")
    with open(rst_path, 'w') as fout, contextlib.redirect_stdout(fout):
        print("Servers")
        print("=======")
        print()
        print("Individual detail pages for each MUD server scanned in this")
        print("census. Each page shows the server's ANSI login banner,")
        print("MSSP metadata (if available), protocol support,")
        print("fingerprint data, the raw JSON scan record, and the")
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
            name = s['name'] or s['host']
            print(f"   {_rst_escape(name)} <mud_detail/{mud_file}>")
        print()
    print(f"  wrote {rst_path}", file=sys.stderr)


def generate_mud_detail(server, logs_dir=None, data_dir=None, fp_counts=None):
    """Generate a detail page for one MUD server.

    :param server: server record dict
    :param logs_dir: path to directory containing per-host:port .log files
    :param data_dir: path to telnetlib3 data directory for embedding raw JSON
    :param fp_counts: dict mapping fingerprint hash to server count
    """
    mud_file = server['_mud_file']
    detail_path = os.path.join(MUD_DETAIL_PATH, f"{mud_file}.rst")
    name = server['name'] or server['host']
    footnotes = []

    with open(detail_path, 'w') as fout, contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(name)
        print(escaped_name)
        print("=" * max(len(escaped_name), 4))
        print()

        # Banner (first, before address)
        banner = _combine_banners(server)
        if banner and not _is_garbled(banner):
            banner_html = _banner_to_html(banner, name=name)
            print(".. raw:: html")
            print()
            for line in banner_html.split('\n'):
                print(f"   {line}")
            print()
        elif banner:
            print("*Banner not shown -- this server likely uses a legacy"
                  " encoding such as CP437.*")
            print()

        # Server URLs section
        host = server['host']
        port = server['port']
        url = _telnet_url(host, port)

        print("Server URLs")
        print("-----------")
        print()
        print(f".. raw:: html")
        print()
        print(f'   <p class="mud-connect">')
        print(f'   <strong>Telnet</strong>: '
              f'<a href="{url}" class="telnet-link">{url}</a>')
        print(f'   <button class="copy-btn" data-host="{host}"'
              f' data-port="{port}"'
              f' title="Copy host and port"'
              f' aria-label="Copy {host} port {port} to clipboard">')
        print(f'   <span class="copy-icon" aria-hidden="true">'
              f'&#x1F4CB;</span>')
        print(f'   </button>')
        print(f'   </p>')
        print()
        if server.get('_loci_supported'):
            loci_url = _lociterm_url(host, port, server['tls_port'],
                                     server.get('_loci_ssl'))
            print(f"- **Open in Browser**: "
                  f"`Play on LociTerm <{loci_url}>`__")
        if server['website']:
            href = server['website']
            if not href.startswith(('http://', 'https://')):
                href = f'http://{href}'
            print(f"- **Website**: `{_rst_escape(server['website'])}"
                  f" <{href}>`_")
        if server['tls_port']:
            tls_port = server['tls_port']
            if tls_port == '1' or tls_port == str(port):
                tls_url = f"telnets://{host}:{port}"
            else:
                tls_url = f"telnets://{host}:{tls_port}"
            print(f"- **TLS/SSL**: `{tls_url} <{tls_url}>`_")
        print()

        if server['has_mssp'] and server['description']:
            print(f"*{_rst_escape(server['description'][:300])}*")
            print()

        encoding = server['encoding'].lower()
        is_legacy_encoding = encoding not in ('ascii', 'utf-8', 'unknown')
        banner_garbled = banner and _is_garbled(banner)

        has_info = (server['has_mssp'] or is_legacy_encoding
                    or banner_garbled)
        if has_info:
            print("Server Info")
            print("-----------")
            print()
            if server['codebase']:
                print(f"- **Codebase**: {_rst_escape(server['codebase'])}")
            if server['family']:
                print(f"- **Family**: {_rst_escape(server['family'])}")
            if server['genre']:
                print(f"- **Genre**: {_rst_escape(server['genre'])}")
            if server['gameplay']:
                print(f"- **Gameplay**: {_rst_escape(server['gameplay'])}")
            if server['players'] is not None:
                scan_time = _format_scan_time(server['connected'])
                if scan_time:
                    print(f"- **Players online**: {server['players']} [#scan]_")
                    footnotes.append(f".. [#scan] measured {scan_time}")
                else:
                    print(f"- **Players online**: {server['players']}")
            if server['uptime_days'] is not None:
                print(f"- **Uptime**: {server['uptime_days']} days")
            if server['created']:
                print(f"- **Created**: {server['created']}")
            if server['status']:
                print(f"- **Status**: {_rst_escape(server['status'])}")
            if server['discord']:
                discord_url = server['discord']
                if not discord_url.startswith(('http://', 'https://')):
                    discord_url = f'https://{discord_url}'
                print(f"- **Discord**: `{_rst_escape(server['discord'])}"
                      f" <{discord_url}>`_")
            if server['location']:
                print(f"- **Location**: {_rst_escape(server['location'])}")
            if server['language']:
                print(f"- **Language**: {_rst_escape(server['language'])}")
            if is_legacy_encoding or banner_garbled:
                enc_label = server['encoding'] if is_legacy_encoding else 'CP437'
                print(f"- **Encoding**: {enc_label}")
                print()
                print(f"  This server uses a legacy encoding:")
                print()
                print(f"  ``telnetlib3-client --encoding"
                      f" {enc_label.lower()} --force-binary"
                      f" {host} {port}``")
                print()
            if server['pay_to_play']:
                pay_play = _first_str(server['mssp'].get('PAY TO PLAY', ''))
                pay_perks = _first_str(server['mssp'].get('PAY FOR PERKS', ''))
                if pay_play and pay_play not in ('0', 'no', 'No', 'NO', ''):
                    print("- **Pay to Play**: :pay-icon:`$` Yes")
                if pay_perks and pay_perks not in ('0', 'no', 'No', 'NO', ''):
                    print("- **Pay for Perks**: :pay-icon:`$` Yes")
            print()

        # Protocol support
        proto_flags = [
            p for p in MUD_PROTOCOLS
            if server['protocols'].get(p, 'no') != 'no'
        ]
        if proto_flags:
            print("Protocol Support")
            print("----------------")
            print()
            print("MUD-specific protocols detected via MSSP flags or")
            print("Telnet negotiation.")
            print()
            for proto in MUD_PROTOCOLS:
                status = server['protocols'].get(proto, 'no')
                if status == 'mssp':
                    print(f"- **{proto}**: :proto-yes:`Yes` (MSSP)")
                elif status == 'negotiated':
                    print(f"- **{proto}**: :proto-negotiated:`Negotiated`")
                else:
                    print(f"- **{proto}**: :proto-no:`No`")
            print()

        # Fingerprint link
        fp = server['fingerprint']
        print("Telnet Fingerprint")
        print("------------------")
        print()
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
                  + ', '.join(f"``{o}``" for o in sorted(server['offered'])))
            print()
        if server['requested']:
            print("**Options requested from client**: "
                  + ', '.join(f"``{o}``" for o in sorted(server['requested'])))
            print()

        # Raw JSON data source
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

        # Connection log
        if logs_dir:
            log_path = os.path.join(logs_dir, f"{server['host']}:{server['port']}.log")
            if os.path.isfile(log_path):
                with open(log_path) as lf:
                    log_text = lf.read().rstrip()
                if log_text:
                    print("Connection Log")
                    print("--------------")
                    print()
                    print("Debug-level log of the Telnet negotiation session,")
                    print("showing each IAC (Interpret As Command) exchange")
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

        # Footnotes at bottom of page
        for fn in footnotes:
            print(fn)
            print()


def _write_mud_port_section(server, sec_char, logs_dir=None, data_dir=None,
                            fp_counts=None, fn_suffix=''):
    """Write the detail content sections for one server port.

    Used by :func:`generate_mud_detail_group` to emit each port's content
    at a lower heading level than a standalone page.

    :param server: server record dict
    :param sec_char: RST underline character for section headings
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    :param fn_suffix: suffix for footnote labels to avoid clashes
    :returns: list of footnote strings to print at page end
    """
    footnotes = []
    name = server['name'] or server['host']
    host = server['host']
    port = server['port']

    # Banner
    banner = _combine_banners(server)
    if banner and not _is_garbled(banner):
        banner_html = _banner_to_html(banner, name=name)
        print(".. raw:: html")
        print()
        for line in banner_html.split('\n'):
            print(f"   {line}")
        print()
    elif banner:
        print("*Banner not shown -- this server likely uses a legacy"
              " encoding such as CP437.*")
        print()

    # Server URLs
    url = _telnet_url(host, port)

    _rst_heading("Server URLs", sec_char)
    print(f".. raw:: html")
    print()
    print(f'   <p class="mud-connect">')
    print(f'   <strong>Telnet</strong>: '
          f'<a href="{url}" class="telnet-link">{url}</a>')
    print(f'   <button class="copy-btn" data-host="{host}"'
          f' data-port="{port}"'
          f' title="Copy host and port"'
          f' aria-label="Copy {host} port {port} to clipboard">')
    print(f'   <span class="copy-icon" aria-hidden="true">'
          f'&#x1F4CB;</span>')
    print(f'   </button>')
    print(f'   </p>')
    print()
    if server.get('_loci_supported'):
        loci_url = _lociterm_url(host, port, server['tls_port'],
                                 server.get('_loci_ssl'))
        print(f"- **Open in Browser**: "
              f"`Play on LociTerm <{loci_url}>`__")
    if server['website']:
        href = server['website']
        if not href.startswith(('http://', 'https://')):
            href = f'http://{href}'
        print(f"- **Website**: `{_rst_escape(server['website'])}"
              f" <{href}>`_")
    if server['tls_port']:
        tls_port = server['tls_port']
        if tls_port == '1' or tls_port == str(port):
            tls_url = f"telnets://{host}:{port}"
        else:
            tls_url = f"telnets://{host}:{tls_port}"
        print(f"- **TLS/SSL**: `{tls_url} <{tls_url}>`_")
    print()

    if server['has_mssp'] and server['description']:
        print(f"*{_rst_escape(server['description'][:300])}*")
        print()

    encoding = server['encoding'].lower()
    is_legacy_encoding = encoding not in ('ascii', 'utf-8', 'unknown')
    banner_garbled = banner and _is_garbled(banner)

    has_info = (server['has_mssp'] or is_legacy_encoding
                or banner_garbled)
    if has_info:
        _rst_heading("Server Info", sec_char)
        if server['codebase']:
            print(f"- **Codebase**: {_rst_escape(server['codebase'])}")
        if server['family']:
            print(f"- **Family**: {_rst_escape(server['family'])}")
        if server['genre']:
            print(f"- **Genre**: {_rst_escape(server['genre'])}")
        if server['gameplay']:
            print(f"- **Gameplay**: {_rst_escape(server['gameplay'])}")
        if server['players'] is not None:
            scan_time = _format_scan_time(server['connected'])
            fn_label = f"scan{fn_suffix}"
            if scan_time:
                print(f"- **Players online**: {server['players']}"
                      f" [#{fn_label}]_")
                footnotes.append(f".. [#{fn_label}] measured {scan_time}")
            else:
                print(f"- **Players online**: {server['players']}")
        if server['uptime_days'] is not None:
            print(f"- **Uptime**: {server['uptime_days']} days")
        if server['created']:
            print(f"- **Created**: {server['created']}")
        if server['status']:
            print(f"- **Status**: {_rst_escape(server['status'])}")
        if server['discord']:
            discord_url = server['discord']
            if not discord_url.startswith(('http://', 'https://')):
                discord_url = f'https://{discord_url}'
            print(f"- **Discord**: `{_rst_escape(server['discord'])}"
                  f" <{discord_url}>`_")
        if server['location']:
            print(f"- **Location**: {_rst_escape(server['location'])}")
        if server['language']:
            print(f"- **Language**: {_rst_escape(server['language'])}")
        if is_legacy_encoding or banner_garbled:
            enc_label = server['encoding'] if is_legacy_encoding else 'CP437'
            print(f"- **Encoding**: {enc_label}")
            print()
            print(f"  This server uses a legacy encoding:")
            print()
            print(f"  ``telnetlib3-client --encoding"
                  f" {enc_label.lower()} --force-binary"
                  f" {host} {port}``")
            print()
        if server['pay_to_play']:
            pay_play = _first_str(server['mssp'].get('PAY TO PLAY', ''))
            pay_perks = _first_str(server['mssp'].get('PAY FOR PERKS', ''))
            if pay_play and pay_play not in ('0', 'no', 'No', 'NO', ''):
                print("- **Pay to Play**: :pay-icon:`$` Yes")
            if pay_perks and pay_perks not in ('0', 'no', 'No', 'NO', ''):
                print("- **Pay for Perks**: :pay-icon:`$` Yes")
        print()

    # Protocol support
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
                print(f"- **{proto}**: :proto-yes:`Yes` (MSSP)")
            elif status == 'negotiated':
                print(f"- **{proto}**: :proto-negotiated:`Negotiated`")
            else:
                print(f"- **{proto}**: :proto-no:`No`")
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
              + ', '.join(f"``{o}``" for o in sorted(server['offered'])))
        print()
    if server['requested']:
        print("**Options requested from client**: "
              + ', '.join(f"``{o}``" for o in sorted(server['requested'])))
        print()

    # Raw JSON data source
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

    # Connection log
    if logs_dir:
        log_path = os.path.join(logs_dir, f"{host}:{port}.log")
        if os.path.isfile(log_path):
            with open(log_path) as lf:
                log_text = lf.read().rstrip()
            if log_text:
                _rst_heading("Connection Log", sec_char)
                print("Debug-level log of the Telnet negotiation session,")
                print("showing each IAC (Interpret As Command) exchange")
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


def generate_mud_detail_group(hostname, group_servers, logs_dir=None,
                              data_dir=None, fp_counts=None):
    """Generate a combined detail page for servers sharing a hostname.

    Each server gets its own sub-heading by ``hostname:port``, with all
    detail sections nested underneath.

    :param hostname: shared hostname
    :param group_servers: list of server records sharing this hostname
    :param logs_dir: path to log directory
    :param data_dir: path to data directory
    :param fp_counts: dict mapping fingerprint to server count
    """
    mud_file = group_servers[0]['_mud_file']
    detail_path = os.path.join(MUD_DETAIL_PATH, f"{mud_file}.rst")
    display_name = group_servers[0]['name'] or hostname

    with open(detail_path, 'w') as fout, contextlib.redirect_stdout(fout):
        escaped_name = _rst_escape(display_name)
        print(escaped_name)
        print("=" * max(len(escaped_name), 4))
        print()

        all_footnotes = []
        for server in group_servers:
            port = server['port']
            sub_title = f"{hostname}:{port}"
            escaped_sub = _rst_escape(sub_title)
            print(escaped_sub)
            print("-" * max(len(escaped_sub), 4))
            print()

            footnotes = _write_mud_port_section(
                server, '~', logs_dir=logs_dir, data_dir=data_dir,
                fp_counts=fp_counts, fn_suffix=f'_{port}')
            all_footnotes.extend(footnotes)

        for fn in all_footnotes:
            print(fn)
            print()


def generate_mud_details(servers, logs_dir=None, data_dir=None,
                         hostname_groups=None):
    """Generate all per-MUD detail pages.

    :param servers: list of server records
    :param logs_dir: path to directory containing per-host:port .log files
    :param data_dir: path to telnetlib3 data directory for embedding raw JSON
    :param hostname_groups: dict from :func:`_group_shared_hostname`, or None
    """
    _clean_dir(MUD_DETAIL_PATH)
    os.makedirs(MUD_DETAIL_PATH, exist_ok=True)

    fp_counts = Counter(s['fingerprint'] for s in servers)

    # Collect grouped server keys to skip in individual generation
    grouped_keys = set()
    if hostname_groups:
        for members in hostname_groups.values():
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

    # Generate combined pages for grouped servers
    if hostname_groups:
        for (_hostname, _name), members in sorted(hostname_groups.items()):
            generate_mud_detail_group(
                _hostname, members, logs_dir=logs_dir,
                data_dir=data_dir, fp_counts=fp_counts)
            rebuilt += 1

    total = len(servers) - len(grouped_keys) + len(hostname_groups or {})
    if rebuilt < total:
        print(f"  wrote {rebuilt}/{total} MUD detail pages"
              f" to {MUD_DETAIL_PATH} ({total - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} MUD detail pages to {MUD_DETAIL_PATH}",
              file=sys.stderr)


def generate_fingerprint_detail(fp_hash, fp_servers):
    """Generate a detail page for one fingerprint group.

    :param fp_hash: fingerprint hash string
    :param fp_servers: list of server records sharing this fingerprint
    """
    detail_path = os.path.join(DETAIL_PATH, f"{fp_hash}.rst")
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
                  + ', '.join(f"``{o}``" for o in sorted(sample['offered'])))
        else:
            print("**Offered by server**: none")
        print()

        if sample['requested']:
            print("**Requested from client**: "
                  + ', '.join(f"``{o}``" for o in sorted(sample['requested'])))
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

        # Option states (showing what was actually negotiated)
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
                      + ', '.join(f"``{o}``" for o in sorted(negotiated_offered)))
                print()
            if negotiated_requested:
                print("**Server requested (accepted)**: "
                      + ', '.join(f"``{o}``" for o in sorted(negotiated_requested)))
                print()

        # Server list
        print("Servers")
        print("-------")
        print()

        for s in fp_servers:
            name = s['name'] or s['host']
            mud_file = s['_mud_file']
            tls = ' :tls-lock:`\U0001f512`' if s['tls_port'] else ''
            print(f":doc:`{_rst_escape(name)} <../mud_detail/{mud_file}>`"
                  f"{tls}")
            print()

            if s['has_mssp']:
                if s['codebase']:
                    print(f"  - Codebase: {_rst_escape(s['codebase'])}")
                if s['family']:
                    print(f"  - Family: {_rst_escape(s['family'])}")
                if s['genre']:
                    print(f"  - Genre: {_rst_escape(s['genre'])}")
                if s['players'] is not None:
                    print(f"  - Players: {s['players']}")
                if s['created']:
                    print(f"  - Created: {s['created']}")
                if s['status']:
                    print(f"  - Status: {_rst_escape(s['status'])}")
                if s['website']:
                    href = s['website']
                    if not href.startswith(('http://', 'https://')):
                        href = f'http://{href}'
                    print(f"  - Website: `{_rst_escape(s['website'])}"
                          f" <{href}>`_")
                if s['location']:
                    print(f"  - Location: {_rst_escape(s['location'])}")

                # Protocol flags
                proto_flags = [
                    p for p in MUD_PROTOCOLS
                    if s['protocols'].get(p, 'no') != 'no'
                ]
                if proto_flags:
                    print(f"  - Protocols: {', '.join(proto_flags)}")
                print()

            # Banner excerpt
            banner = _combine_banners(s)
            if banner and not _is_garbled(banner):
                banner_html = _banner_to_html(
                    banner, maxlen=300, maxlines=10,
                    name=(s['name'] or s['host']))
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
        print(f"  wrote {rebuilt}/{len(by_fp)} fingerprint detail pages"
              f" to {DETAIL_PATH} ({len(by_fp) - rebuilt} unchanged)",
              file=sys.stderr)
    else:
        print(f"  wrote {rebuilt} fingerprint detail pages to {DETAIL_PATH}",
              file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Generate MUD server statistics site from telnetlib3 data.')
    parser.add_argument(
        '--data-dir', default=os.path.join(os.path.dirname(__file__), 'data-muds'),
        help='Path to data directory (default: ./data-muds)')
    parser.add_argument(
        '--logs-dir', default=os.path.join(os.path.dirname(__file__), 'logs'),
        help='Path to scan log directory (default: ./logs)')
    parser.add_argument(
        '--server-list',
        default=os.path.join(os.path.dirname(__file__), 'data-muds',
                             'mudlist.txt'),
        help='Path to server list file for filtering (default:'
             ' ./data-muds/mudlist.txt)')
    args = parser.parse_args()

    data_dir = os.path.abspath(args.data_dir)
    logs_dir = os.path.abspath(args.logs_dir)
    if os.path.isdir(logs_dir):
        print(f"Using logs from {logs_dir}", file=sys.stderr)
    else:
        logs_dir = None
    print(f"Loading data from {data_dir} ...", file=sys.stderr)

    records = load_server_data(data_dir)
    print(f"  loaded {len(records)} session records", file=sys.stderr)

    servers = deduplicate_servers(records)
    print(f"  {len(servers)} unique servers after deduplication", file=sys.stderr)

    listed = _parse_server_list(args.server_list)
    servers = [s for s in servers if (s['host'], s['port']) in listed]
    print(f"  {len(servers)} servers after filtering by {args.server_list}",
          file=sys.stderr)

    telnetsupport = _load_telnetsupport(data_dir)
    _annotate_lociterm(servers, telnetsupport)

    hostname_groups = _group_shared_hostname(servers)
    _assign_mud_filenames(servers, hostname_groups)
    if hostname_groups:
        n_groups = len(hostname_groups)
        n_combined = sum(len(m) for m in hostname_groups.values())
        print(f"  {n_groups} hostname groups ({n_combined} servers combined)",
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
    generate_mud_details(servers, logs_dir=logs_dir, data_dir=data_dir,
                         hostname_groups=hostname_groups)
    generate_fingerprint_details(servers)

    # Clean up old results.rst if it exists
    old_results = os.path.join(DOCS_PATH, "results.rst")
    if os.path.exists(old_results):
        os.remove(old_results)
        print(f"  removed old {old_results}", file=sys.stderr)

    print("Done. Run sphinx-build to generate HTML.", file=sys.stderr)


if __name__ == '__main__':
    main()
