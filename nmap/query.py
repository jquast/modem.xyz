#!/usr/bin/env python3
"""Display nmap scan results from chunk XML files.

Reads completed chunk XMLs from nmap-allports/ and presents a summary
with colored tables using blessed and prettytable.

Usage::

    python3 nmap_report.py
    python3 nmap_report.py --output-dir nmap-allports/
    python3 nmap_report.py --host 192.168.1.1
    python3 nmap_report.py --port 23
    python3 nmap_report.py --search gopher
"""

import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

from blessed import Terminal
from prettytable import PrettyTable

# Well-known BBS service names for display.
PORT_NAMES = {
    11: 'Finger',
    17: 'QOTD',
    18: 'MSP',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    64: 'PETSCII-40',
    70: 'Gopher',
    79: 'Finger',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    128: 'PETSCII-80',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    513: 'RLogin',
    563: 'NNTPS',
    587: 'SMTP-Sub',
    993: 'IMAPS',
    995: 'POP3S',
    1123: 'WebSocket',
    5500: 'Hotline',
    5501: 'Hotline-T',
    6667: 'IRC',
    11235: 'WSS',
    24553: 'BINKPS',
    24554: 'BINKP',
}

# Ports we specifically care about (BBS services).
BBS_PORTS = set(PORT_NAMES.keys())

# Banner signatures — checked in order, first match wins.
_BANNER_SIGS = [
    ('SSH-',        'SSH'),
    ('HTTP/',       'HTTP'),
    ('<!DOCTYPE',   'HTTP'),
    ('<html',       'HTTP'),
    ('220 ',        None),      # could be FTP or SMTP, disambiguate below
    ('220-',        None),      # FTP/SMTP multi-line greeting
    ('+OK',         'POP3'),
    ('* OK',        'IMAP'),
    ('200 ',        None),      # could be NNTP or other
    ('201 ',        'NNTP'),
    (':irc',        'IRC'),
    ('ERROR :',     'IRC'),
    ('binkp',       'BINKP'),
    ('\\x80',        'BINKP'),
    ('**EMSI_',     'RLogin'),
    ('EMSI_',       'RLogin'),
    ('(CONNECT',    'RLogin'),
    ('RFB ',        'VNC'),
    ('CONNECTED TO CM1', 'MajorMUD'),
    ('GameType:',   'GameSrv'),
    ('<?xml',       'HTTP'),
    ('dp9ik@',      'Plan9'),
    ('teamtalk',    'TeamTalk'),
    ('\\x16\\x03',   'TLS'),
    ('\\x05\\x00\\x00\\x00\\x0B', 'MySQL-X'),
    ('\\x9B',       'Atari'),
    ('\\x0E\\x0D',  'PETSCII'),
    ('VOTIFIER',    'Minecraft'),
    ('MariaDB',     'MySQL'),
    ('5.5.5-',      'MySQL'),
    ('\\x0A5.',     'MySQL'),
    ('\\x0A8.',     'MySQL'),
    ('SET /Dev/',   'SkotOS'),
    ('MOO version', 'MOO'),
    ('#$#mcp',      'MOO'),
    ('SRS:Ready',   'Splashtop'),
    ('VTUN',        'VTun'),
    ('\\x00\\x0D\\x0A', 'RLogin'),
    ('Failed to detect protocol', 'RLogin'),
    ('Expected RLogin', 'RLogin'),
    ('Synchronet BBS', 'Telnet'),
    ('sYNCHRONET bbs', 'Telnet'),
    ('login:',      'RLogin'),
]

# Common alternate port ranges.
_PORT_HINTS = {
    range(2002, 2004): 'RLogin',
    range(2300, 2400): 'Telnet',
    range(2023, 2024): 'Telnet',
    range(6660, 6670): 'IRC',
    range(6690, 6700): 'IRC',
    range(8080, 8081): 'HTTP',
    range(8443, 8444): 'HTTPS',
    range(8888, 8889): 'HTTP',
    range(2222, 2223): 'SSH',
    range(10023, 10024): 'Telnet',
    range(32400, 32401): 'Plex',
    range(5222, 5223): 'XMPP',
    range(3306, 3308): 'MySQL',
    range(6969, 6970): 'BitTorrent',
    range(5269, 5270): 'XMPP',
    range(64738, 64739): 'Mumble',
}


def guess_service(port_num, banner):
    """Guess service name from banner content and port number.

    :param port_num: port number
    :param banner: banner string (may be empty)
    :returns: guessed service name or None
    """
    b = banner.strip()

    if b:
        # Telnet IAC always wins — can run on any port.
        if not b.startswith('\\x00') and not b.startswith('\x00'):
            for iac in ('\\xFF\\xFB', '\\xFF\\xFC', '\\xFF\\xFD', '\\xFF\\xFE',
                        '\\xff\\xfb', '\\xff\\xfc', '\\xff\\xfd', '\\xff\\xfe',
                        '\xff\xfb', '\xff\xfc', '\xff\xfd', '\xff\xfe'):
                if iac in banner:
                    return 'Telnet'
        # Banner signature checks.
        for sig, name in _BANNER_SIGS:
            if b.lower().startswith(sig.lower()):
                if name:
                    return name
                if sig in ('220 ', '220-'):
                    bl = b.lower()
                    if 'smtp' in bl or 'esmtp' in bl or 'mail' in bl:
                        return 'SMTP'
                    if 'ftp' in bl or 'filezilla' in bl or 'vsftpd' in bl:
                        return 'FTP'
                    if 'synchronet' in bl:
                        return 'FTP'
                    if 'pure-ftpd' in bl or 'proftpd' in bl:
                        return 'FTP'
                    return 'FTP/SMTP'
                if sig == '200 ':
                    bl = b.lower()
                    if 'nntp' in bl or 'news' in bl or 'posting' in bl:
                        return 'NNTP'
                break
        # IRC: ":hostname NOTICE" pattern.
        if b.startswith(':') and ' NOTICE ' in b:
            return 'IRC'
        # ANSI escapes without IAC — rlogin.
        if '\x1b[' in banner or '\\x1B[' in banner or '\\x1b[' in banner:
            return 'RLogin'
        # Bare \x00 response — rlogin null-byte acknowledgement.
        if b in ('\\x00', '\x00'):
            return 'RLogin'
        # PETSCII detection: inverted case pattern.
        alpha = ''.join(ch for ch in b if ch.isalpha())
        if len(alpha) >= 4:
            lower_start = sum(1 for i, ch in enumerate(alpha[:-1])
                              if ch.islower() and alpha[i + 1].isupper())
            upper_start = sum(1 for i, ch in enumerate(alpha[:-1])
                              if ch.isupper() and alpha[i + 1].islower())
            if lower_start > upper_start and lower_start >= 2:
                return 'PETSCII'

    for port_range, name in _PORT_HINTS.items():
        if port_num in port_range:
            return name

    # Fall back to well-known port name.
    if port_num in PORT_NAMES:
        return PORT_NAMES[port_num]

    return None


def _set_double_border(table):
    """Apply CP437 double-line border characters."""
    table.horizontal_char = '═'
    table.vertical_char = '║'
    table.junction_char = '╬'
    table.top_junction_char = '╦'
    table.bottom_junction_char = '╩'
    table.left_junction_char = '╠'
    table.right_junction_char = '╣'
    table.top_left_junction_char = '╔'
    table.top_right_junction_char = '╗'
    table.bottom_left_junction_char = '╚'
    table.bottom_right_junction_char = '╝'


def _make_table(t, title=None, field_names=None):
    """Create a styled PrettyTable.

    :param t: blessed Terminal instance
    :param title: optional table title
    :param field_names: list of column names
    :returns: configured PrettyTable
    """
    tbl = PrettyTable()
    _set_double_border(tbl)
    tbl.max_table_width = _TABLE_WIDTH
    if title:
        tbl.title = t.magenta(title)
    if field_names:
        tbl.field_names = [t.cyan(n) for n in field_names]
        # Prevent numeric/short columns from ever wrapping.
        for name in field_names:
            col = t.cyan(name)
            if name in ('Port', 'Hosts', 'Hosts', '+'):
                tbl.min_width[col] = 5
            elif name in ('Version', 'OS', 'Service', 'Guess', 'State', 'Reason'):
                tbl.min_width[col] = max(len(name), 8)
    return tbl


def parse_chunks(chunk_dir):
    """Parse all completed chunk XML files.

    :param chunk_dir: path to chunks directory
    :returns: list of host dicts with addresses, ports, banners
    """
    hosts = []
    for xml_path in sorted(glob.glob(os.path.join(chunk_dir, '*.xml'))):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        root = tree.getroot()
        for host_el in root.findall('host'):
            h = {
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'timed_out': False,
            }
            if host_el.get('timedout') == 'true':
                h['timed_out'] = True
            for addr in host_el.findall('address'):
                h['addresses'].append({
                    'addr': addr.get('addr'),
                    'type': addr.get('addrtype'),
                })
            hostnames_el = host_el.find('hostnames')
            if hostnames_el is not None:
                for hn in hostnames_el.findall('hostname'):
                    h['hostnames'].append(hn.get('name'))
            ports_el = host_el.find('ports')
            if ports_el is not None:
                for port in ports_el.findall('port'):
                    state = port.find('state')
                    banner = ''
                    for script in port.findall('script'):
                        if script.get('id') == 'banner':
                            banner = script.get('output', '')
                    h['ports'].append({
                        'port': int(port.get('portid')),
                        'proto': port.get('protocol', 'tcp'),
                        'state': state.get('state') if state is not None else '?',
                        'reason': state.get('reason') if state is not None else '',
                        'banner': banner,
                    })
            hosts.append(h)
    return hosts


def host_addr(host):
    """Return the primary display address for a host."""
    for a in host['addresses']:
        if a['type'] == 'ipv4':
            return a['addr']
    if host['addresses']:
        return host['addresses'][0]['addr']
    return '?'


def host_label(host):
    """Return hostname or IP for display."""
    if host['hostnames']:
        return host['hostnames'][0]
    return host_addr(host)


def show_summary(t, hosts):
    """Print scan summary dashboard."""
    with_ports = [h for h in hosts if h['ports']]
    timed_out = [h for h in hosts if h['timed_out']]

    tbl = PrettyTable(header=False, border=False, padding_width=2)
    tbl.align = 'l'
    tbl.add_row([t.white('Hosts scanned'), t.bold_white(str(len(hosts)))])
    tbl.add_row([t.white('With open ports'), t.bold_green(str(len(with_ports)))])
    tbl.add_row([t.white('Timed out'), t.bold_yellow(str(len(timed_out)))])
    tbl.add_row([t.white('No open ports'),
                 t.darkgrey(str(len(hosts) - len(with_ports)))])
    port_counts = Counter()
    for h in with_ports:
        for p in h['ports']:
            port_counts[p['port']] += 1
    tbl.add_row([t.white('Unique ports seen'), t.bold_cyan(str(len(port_counts)))])

    print()
    print(t.magenta('  ╔══ SCAN SUMMARY ══╗'))
    print('  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_port_frequency(t, hosts):
    """Print service frequency table, grouping ports by service name."""
    with_ports = [h for h in hosts if h['ports']]

    # Collect a representative banner per port for guessing.
    port_banners = {}
    for h in with_ports:
        for p in h['ports']:
            if p['port'] not in port_banners and p.get('banner'):
                port_banners[p['port']] = p['banner']

    # Group by service: count unique hosts per service, collect ports.
    svc_hosts = defaultdict(set)
    svc_ports = defaultdict(set)
    for h in with_ports:
        addr = host_addr(h)
        for p in h['ports']:
            name = guess_service(p['port'], p.get('banner', ''))
            if not name:
                name = str(p['port'])
            svc_hosts[name].add(addr)
            svc_ports[name].add(p['port'])

    # Sort by host count descending.
    ranked = sorted(svc_hosts.items(), key=lambda x: -len(x[1]))

    tbl = _make_table(t, title='SERVICE FREQUENCY',
                      field_names=['Service', 'Hosts', 'Ports', 'Bar'])
    tbl.align[t.cyan('Service')] = 'l'
    tbl.align[t.cyan('Hosts')] = 'r'
    tbl.align[t.cyan('Ports')] = 'l'
    tbl.align[t.cyan('Bar')] = 'l'

    max_count = len(ranked[0][1]) if ranked else 1

    for name, host_set in ranked[:40]:
        count = len(host_set)
        ports = sorted(svc_ports[name])
        port_str = ', '.join(str(p) for p in ports[:8])
        if len(ports) > 8:
            port_str += f' (+{len(ports) - 8})'
        bar_len = int(count / max_count * 30)
        # Color: green if any port is a known BBS port, yellow if
        # guessed, cyan if unidentified (numeric name).
        if any(p in BBS_PORTS for p in ports):
            bar = t.green('█' * bar_len)
            display_name = t.green(name)
        elif not name.isdigit():
            bar = t.yellow('█' * bar_len)
            display_name = t.yellow(name)
        else:
            bar = t.cyan('█' * bar_len)
            display_name = t.darkgrey(name)
        tbl.add_row([display_name, count, port_str, bar])

    print('  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_bbs_services(t, hosts):
    """Print service matrix with fuzzy detection from banners."""
    with_ports = [h for h in hosts if h['ports']]
    if not with_ports:
        return

    svc_counts = Counter()
    host_services = {}
    for h in with_ports:
        addr = host_addr(h)
        services = defaultdict(list)
        for p in h['ports']:
            svc = guess_service(p['port'], p.get('banner', ''))
            if svc:
                services[svc].append(p['port'])
                svc_counts[svc] += 1
        if services:
            host_services[addr] = (h, dict(services))

    if not host_services:
        return

    ranked = [name for name, _ in svc_counts.most_common()]
    top_svcs = ranked[:12]
    rest_svcs = set(ranked[10:])

    # Short 3-4 char abbreviations for compact columns.
    _SHORT = {
        'HTTP': 'HTTP', 'HTTPS': 'HTPS', 'Telnet': 'TLNT',
        'SSH': 'SSH', 'BINKP': 'BNKP', 'IRC': 'IRC',
        'SMTP': 'SMTP', 'FTP': 'FTP', 'POP3': 'POP3',
        'SMTP-Sub': 'SUBM', 'Gopher': 'GPHR', 'NNTP': 'NNTP',
        'POP3S': 'P3S', 'MSP': 'MSP', 'Finger': 'FNGR',
        'WebSocket': 'WS', 'WSS': 'WSS', 'ActiveUser': 'AUSR',
        'RLogin': 'RLGN', 'IMAP': 'IMAP', 'IMAPS': 'IMAS',
        'SMTPS': 'SMTS', 'NNTPS': 'NNTS', 'PETSCII-40': 'P40',
        'PETSCII-80': 'P80', 'Hotline': 'HTLN', 'Hotline-T': 'HTLT',
        'BINKPS': 'BNKS', 'QOTD': 'QOTD', 'Plex': 'PLEX',
        'XMPP': 'XMPP',
    }
    short_names = [_SHORT.get(s, s[:4]) for s in top_svcs]

    tbl = PrettyTable()
    _set_double_border(tbl)
    tbl.title = t.magenta('SERVICE MATRIX')
    tbl.field_names = ([t.cyan('Host')]
                       + [t.cyan(s) for s in short_names]
                       + [t.cyan('+')])
    tbl.align[t.cyan('Host')] = 'l'
    tbl.align[t.cyan('+')] = 'r'
    for s in short_names:
        tbl.align[t.cyan(s)] = 'c'
    tbl.max_width[t.cyan('Host')] = 22

    for addr in sorted(host_services,
                       key=lambda a: -len(host_services[a][1])):
        h, services = host_services[addr]
        label = host_label(h)
        if len(label) > 22:
            label = label[:19] + '...'
        row = [t.white(label)]
        for svc in top_svcs:
            ports = services.get(svc, [])
            if ports:
                has_alt = any(p not in BBS_PORTS for p in ports)
                if has_alt:
                    row.append(t.yellow('●'))
                else:
                    row.append(t.green('●'))
            else:
                row.append(t.darkgrey('·'))
        # Count of additional services beyond the top 10.
        other_count = sum(1 for s in services if s in rest_svcs)
        if other_count:
            row.append(t.darkgrey(f'+{other_count}'))
        else:
            row.append('')
        tbl.add_row(row)

    print('  ' + str(tbl).replace('\n', '\n  '))
    print(t.darkgrey(f'  {len(host_services)} hosts, ')
          + t.green('●') + t.darkgrey(' = standard port, ')
          + t.yellow('●') + t.darkgrey(' = alternate port, ')
          + t.darkgrey('+N = more services (use --host for details)'))
    print()


def show_non_bbs_ports(t, hosts):
    """Print open ports not in the known-service list."""
    port_counts = Counter()
    port_hosts = defaultdict(list)
    port_banners = {}
    for h in hosts:
        for p in h['ports']:
            svc = guess_service(p['port'], p.get('banner', ''))
            if p['port'] not in BBS_PORTS and not svc:
                port_counts[p['port']] += 1
                port_hosts[p['port']].append(host_label(h))
                if p['port'] not in port_banners and p.get('banner'):
                    port_banners[p['port']] = p['banner']

    if not port_counts:
        return

    tbl = _make_table(t, title='UNIDENTIFIED OPEN PORTS',
                      field_names=['Port', 'Hosts', 'Example Hosts'])
    tbl.align[t.cyan('Port')] = 'r'
    tbl.align[t.cyan('Hosts')] = 'r'
    tbl.align[t.cyan('Example Hosts')] = 'l'

    for port, count in port_counts.most_common(25):
        examples = ', '.join(h[:25] for h in port_hosts[port][:3])
        if count > 3:
            examples += t.darkgrey(f' (+{count - 3})')
        tbl.add_row([port, count, examples])

    print('  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_banners(t, hosts):
    """Print hosts with captured banners."""
    banner_hosts = []
    for h in hosts:
        for p in h['ports']:
            if p.get('banner'):
                banner_hosts.append((h, p))

    if not banner_hosts:
        return

    tbl = PrettyTable()
    _set_double_border(tbl)
    tbl.title = t.magenta(f'BANNERS CAPTURED ({len(banner_hosts)})')
    tbl.field_names = [t.cyan('Host'), t.cyan('Port'),
                       t.cyan('Service'), t.cyan('Banner')]
    tbl.align[t.cyan('Host')] = 'l'
    tbl.align[t.cyan('Port')] = 'r'
    tbl.align[t.cyan('Service')] = 'l'
    tbl.align[t.cyan('Banner')] = 'l'
    tbl.min_width[t.cyan('Port')] = 5
    tbl.min_width[t.cyan('Service')] = 6
    tbl.max_table_width = _TABLE_WIDTH

    for h, p in sorted(banner_hosts, key=lambda x: x[1]['port']):
        svc = guess_service(p['port'], p.get('banner', '')) or ''
        if svc:
            svc = t.green(svc)
        label = host_label(h)
        if len(label) > 25:
            label = label[:22] + '...'
        banner = p['banner'].replace('\n', '\\n').replace('\r', '')
        if len(banner) > 50:
            banner = banner[:47] + '...'
        tbl.add_row([t.white(label), p['port'], svc, banner])

    print('  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_host_detail(t, hosts, target):
    """Show detailed port info for a specific host."""
    matches = [h for h in hosts
                if target in [a['addr'] for a in h['addresses']]
                or target in h.get('hostnames', [])]
    if not matches:
        print(t.bold_red(f'  Host {target} not found in results'))
        return

    for h in matches:
        tbl = _make_table(
            t, title=f'{host_label(h)} ({host_addr(h)})',
            field_names=['Port', 'Service', 'State', 'Reason', 'Banner'])
        tbl.align[t.cyan('Port')] = 'r'
        tbl.align[t.cyan('Service')] = 'l'
        tbl.align[t.cyan('State')] = 'l'
        tbl.align[t.cyan('Reason')] = 'l'
        tbl.align[t.cyan('Banner')] = 'l'

        if not h['ports']:
            print(t.darkgrey('  No open ports'))
            continue

        for p in sorted(h['ports'], key=lambda x: x['port']):
            svc = guess_service(p['port'], p.get('banner', '')) or ''
            if svc and p['port'] in BBS_PORTS:
                svc = t.green(svc)
            elif svc:
                svc = t.yellow(svc)
            state = p['state']
            if state == 'open':
                state = t.green(state)
            banner = p.get('banner', '').replace('\n', '\\n')
            if len(banner) > 45:
                banner = banner[:42] + '...'
            tbl.add_row([p['port'], svc, state, p.get('reason', ''), banner])

        print('\n  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_port_detail(t, hosts, port_num):
    """Show all hosts with a specific port open."""
    matches = []
    for h in hosts:
        for p in h['ports']:
            if p['port'] == port_num:
                matches.append((h, p))

    name = PORT_NAMES.get(port_num, '')
    title = f'PORT {port_num}'
    if name:
        title += f' ({name})'
    title += f' \u2014 {len(matches)} hosts'

    tbl = _make_table(t, title=title,
                      field_names=['Host', 'State', 'Reason', 'Banner'])
    tbl.align[t.cyan('Host')] = 'l'
    tbl.align[t.cyan('State')] = 'l'
    tbl.align[t.cyan('Reason')] = 'l'
    tbl.align[t.cyan('Banner')] = 'l'

    if not matches:
        print(t.darkgrey('  No hosts with this port open'))
        return

    for h, p in sorted(matches, key=lambda x: host_addr(x[0])):
        banner = p.get('banner', '').replace('\n', '\\n')
        if len(banner) > 50:
            banner = banner[:47] + '...'
        state = p['state']
        if state == 'open':
            state = t.green(state)
        tbl.add_row([t.white(host_label(h)), state, p.get('reason', ''), banner])

    print('\n  ' + str(tbl).replace('\n', '\n  '))
    print()


def show_search(t, hosts, query):
    """Search service names, banners, and hostnames for a pattern."""
    query = query.lower()
    matches = []
    for h in hosts:
        for p in h['ports']:
            svc = (guess_service(p['port'], p.get('banner', '')) or '').lower()
            banner = p.get('banner', '').lower()
            hostname = host_label(h).lower()
            if query in svc or query in banner or query in hostname:
                matches.append((h, p))

    tbl = _make_table(t, title=f'SEARCH: "{query}" \u2014 {len(matches)} matches',
                      field_names=['Host', 'Port', 'Service', 'State', 'Banner'])
    tbl.align[t.cyan('Host')] = 'l'
    tbl.align[t.cyan('Port')] = 'r'
    tbl.align[t.cyan('Service')] = 'l'
    tbl.align[t.cyan('State')] = 'l'
    tbl.align[t.cyan('Banner')] = 'l'

    if not matches:
        print(t.darkgrey('  No matches found'))
        return

    seen = set()
    for h, p in sorted(matches, key=lambda x: (host_addr(x[0]), x[1]['port'])):
        key = (host_addr(h), p['port'])
        if key in seen:
            continue
        seen.add(key)
        svc = guess_service(p['port'], p.get('banner', '')) or ''
        if svc:
            svc = t.green(svc)
        banner = p.get('banner', '').replace('\n', '\\n').replace('\r', '')
        if len(banner) > 45:
            banner = banner[:42] + '...'
        state = p['state']
        if state == 'open':
            state = t.green(state)
        tbl.add_row([t.white(host_label(h)), p['port'], svc, state, banner])

    print('\n  ' + str(tbl).replace('\n', '\n  '))
    print()


_OS_PATTERNS = [
    (re.compile(r'ubuntu', re.IGNORECASE), 'Ubuntu'),
    (re.compile(r'debian', re.IGNORECASE), 'Debian'),
    (re.compile(r'raspbian|raspberry', re.IGNORECASE), 'Raspberry Pi'),
    (re.compile(r'centos', re.IGNORECASE), 'CentOS'),
    (re.compile(r'fedora', re.IGNORECASE), 'Fedora'),
    (re.compile(r'red\s*hat|rhel', re.IGNORECASE), 'RHEL'),
    (re.compile(r'freebsd', re.IGNORECASE), 'FreeBSD'),
    (re.compile(r'openbsd', re.IGNORECASE), 'OpenBSD'),
    (re.compile(r'windows', re.IGNORECASE), 'Windows'),
    (re.compile(r'RebexSSH', re.IGNORECASE), 'Windows'),
    (re.compile(r'MajorTCP', re.IGNORECASE), 'Windows'),
    (re.compile(r'\blinux\b', re.IGNORECASE), 'Linux'),
    (re.compile(r'dp9ik', re.IGNORECASE), 'Plan 9'),
    (re.compile(r'OpenSSH', re.IGNORECASE), 'Linux'),
]

_VERSION_PATTERNS = [
    re.compile(r'Synchronet\s+(?:BBS\s+)?(?:for\s+\w+\s+)?[Vv]ersion\s+([\d.]+[a-z]?)',
               re.IGNORECASE),
    re.compile(r'SynchronetIRCd[- ]([\d.]+)', re.IGNORECASE),
    re.compile(r'Synchronet\s+FTP\s+Server\s+[Vv]([\d.]+)', re.IGNORECASE),
    re.compile(r'SBBS\s+([\d.]+)', re.IGNORECASE),
]


def _extract_version(banner):
    """Extract Synchronet version from a banner string.

    :param banner: raw banner text
    :returns: version string or None
    """
    for pat in _VERSION_PATTERNS:
        m = pat.search(banner)
        if m:
            return m.group(1)
    return None


_SOFTWARE_PATTERNS = [
    (re.compile(r'cryptlib\(SBBS\)|cryptlib-SBBS', re.IGNORECASE), 'Synchronet'),
    (re.compile(r'Synchronet|SBBS', re.IGNORECASE), 'Synchronet'),
    (re.compile(r'Mystic', re.IGNORECASE), 'Mystic'),
    (re.compile(r'MajorTCP|MajorBBS|MajorMUD', re.IGNORECASE), 'MajorBBS'),
    (re.compile(r'Enigma.*BBS', re.IGNORECASE), 'Enigma½'),
    (re.compile(r'WWIV', re.IGNORECASE), 'WWIV'),
    (re.compile(r'Talisman', re.IGNORECASE), 'Talisman'),
]


def _extract_software(banner):
    """Extract BBS software name from a banner string.

    :param banner: raw banner text
    :returns: software name or None
    """
    for pat, name in _SOFTWARE_PATTERNS:
        if pat.search(banner):
            return name
    return None


def _extract_os(banner):
    """Extract OS name from a banner string.

    :param banner: raw banner text
    :returns: OS name or None (first specific match wins, generic 'Linux' last)
    """
    for pat, name in _OS_PATTERNS:
        if pat.search(banner):
            return name
    return None


def show_versions(t, hosts):
    """Print BBS software, Synchronet version, and OS summary."""
    host_version = {}
    host_os = {}
    host_software = {}
    for h in hosts:
        label = host_label(h)
        for p in h['ports']:
            banner = p.get('banner', '')
            if label not in host_version:
                ver = _extract_version(banner)
                if ver:
                    host_version[label] = ver
            if label not in host_os:
                os_name = _extract_os(banner)
                if os_name:
                    host_os[label] = os_name
            if label not in host_software:
                sw = _extract_software(banner)
                if sw:
                    host_software[label] = sw

    if host_version:
        ver_hosts = defaultdict(list)
        for label, ver in host_version.items():
            ver_hosts[ver].append(label)
        ranked = sorted(ver_hosts.items(), key=lambda x: (-len(x[1]), x[0]))

        tbl = _make_table(
            t, title=f'SYNCHRONET VERSIONS ({len(host_version)} hosts)',
            field_names=['Version', 'Hosts', 'Systems'])
        tbl.align[t.cyan('Version')] = 'l'
        tbl.align[t.cyan('Hosts')] = 'r'
        tbl.align[t.cyan('Systems')] = 'l'

        for ver, ver_host_list in ranked:
            display = ', '.join(sorted(ver_host_list))
            if len(display) > 70:
                display = display[:67] + '...'
            tbl.add_row([t.green(ver), len(ver_host_list), display])

        print('  ' + str(tbl).replace('\n', '\n  '))
        print()

    if host_software:
        sw_hosts = defaultdict(list)
        for label, sw in host_software.items():
            sw_hosts[sw].append(label)
        ranked = sorted(sw_hosts.items(), key=lambda x: (-len(x[1]), x[0]))

        tbl = _make_table(
            t, title=f'BBS SOFTWARE ({len(host_software)} hosts)',
            field_names=['Software', 'Hosts', 'Systems'])
        tbl.align[t.cyan('Software')] = 'l'
        tbl.align[t.cyan('Hosts')] = 'r'
        tbl.align[t.cyan('Systems')] = 'l'

        for sw, sw_host_list in ranked:
            display = ', '.join(sorted(sw_host_list))
            if len(display) > 70:
                display = display[:67] + '...'
            tbl.add_row([t.yellow(sw), len(sw_host_list), display])

        print('  ' + str(tbl).replace('\n', '\n  '))
        print()

    if host_os:
        os_hosts = defaultdict(list)
        for label, os_name in host_os.items():
            os_hosts[os_name].append(label)
        ranked = sorted(os_hosts.items(), key=lambda x: (-len(x[1]), x[0]))

        tbl = _make_table(
            t, title=f'OPERATING SYSTEMS ({len(host_os)} hosts)',
            field_names=['OS', 'Hosts', 'Systems'])
        tbl.align[t.cyan('OS')] = 'l'
        tbl.align[t.cyan('Hosts')] = 'r'
        tbl.align[t.cyan('Systems')] = 'l'

        for os_name, os_host_list in ranked:
            display = ', '.join(sorted(os_host_list))
            if len(display) > 70:
                display = display[:67] + '...'
            tbl.add_row([t.cyan(os_name), len(os_host_list), display])

        print('  ' + str(tbl).replace('\n', '\n  '))
        print()


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DATA = os.path.join(_SCRIPT_DIR, 'data', 'banner-scan')
_TABLE_WIDTH = 0


def main():
    global _TABLE_WIDTH
    parser = argparse.ArgumentParser(
        description='Display nmap scan results from chunk XMLs.')
    parser.add_argument(
        '--output-dir', default=_DEFAULT_DATA,
        help='Directory containing chunks/ (default: data/allports/)')
    parser.add_argument(
        '--host', default=None,
        help='Show detailed view for a specific host')
    parser.add_argument(
        '--port', type=int, default=None,
        help='Show all hosts with a specific port open')
    parser.add_argument(
        '--search', default=None,
        help='Search service names, banners, and hostnames (case-insensitive)')
    parser.add_argument(
        '--versions', action='store_true',
        help='Show Synchronet version summary')
    parser.add_argument(
        '--software', default=None,
        help='List hosts running a BBS software (synchronet, mystic, majorbbs)')
    parser.add_argument(
        '--os', default=None, dest='os_filter',
        help='List hosts running an OS (linux, windows, debian, freebsd, ...)')
    parser.add_argument(
        '--service', default=None,
        help='List hosts with a service (telnet, irc, gopher, rlogin, ...)')
    args = parser.parse_args()

    chunk_dir = os.path.join(args.output_dir, 'chunks')
    if not os.path.isdir(chunk_dir):
        print(f"Error: {chunk_dir} not found", file=sys.stderr)
        sys.exit(1)

    t = Terminal(force_styling=True)
    _TABLE_WIDTH = max(120, t.width - 2) if t.is_a_tty else 160
    hosts = parse_chunks(chunk_dir)

    if not hosts:
        print(t.bold_yellow('  No results found yet.'))
        return

    if args.versions:
        show_versions(t, hosts)
        return

    if args.software:
        query = args.software.lower()
        matches = []
        for h in hosts:
            for p in h['ports']:
                sw = _extract_software(p.get('banner', ''))
                if sw and query in sw.lower():
                    matches.append(host_label(h))
                    break
        matches = sorted(set(matches))
        tbl = _make_table(t, title=f'SOFTWARE: {args.software} ({len(matches)} hosts)',
                          field_names=['Host'])
        tbl.align[t.cyan('Host')] = 'l'
        for m in matches:
            tbl.add_row([t.white(m)])
        print('\n  ' + str(tbl).replace('\n', '\n  '))
        print()
        return

    if args.os_filter:
        query = args.os_filter.lower()
        matches = []
        for h in hosts:
            for p in h['ports']:
                os_name = _extract_os(p.get('banner', ''))
                if os_name and query in os_name.lower():
                    matches.append(host_label(h))
                    break
        matches = sorted(set(matches))
        tbl = _make_table(t, title=f'OS: {args.os_filter} ({len(matches)} hosts)',
                          field_names=['Host'])
        tbl.align[t.cyan('Host')] = 'l'
        for m in matches:
            tbl.add_row([t.white(m)])
        print('\n  ' + str(tbl).replace('\n', '\n  '))
        print()
        return

    if args.service:
        query = args.service.lower()
        matches = []
        for h in hosts:
            for p in h['ports']:
                svc = guess_service(p['port'], p.get('banner', ''))
                if svc and query in svc.lower():
                    matches.append((host_label(h), p['port'], svc))
        seen = set()
        unique = []
        for label, port, svc in sorted(matches):
            key = (label, port)
            if key not in seen:
                seen.add(key)
                unique.append((label, port, svc))
        tbl = _make_table(
            t, title=f'SERVICE: {args.service} ({len(unique)} matches)',
            field_names=['Host', 'Port', 'Service'])
        tbl.align[t.cyan('Host')] = 'l'
        tbl.align[t.cyan('Port')] = 'r'
        tbl.align[t.cyan('Service')] = 'l'
        for label, port, svc in unique:
            tbl.add_row([t.white(label), port, t.green(svc)])
        print('\n  ' + str(tbl).replace('\n', '\n  '))
        print()
        return

    if args.search:
        show_search(t, hosts, args.search)
        return

    if args.host:
        show_host_detail(t, hosts, args.host)
        return

    if args.port is not None:
        show_port_detail(t, hosts, args.port)
        return

    show_summary(t, hosts)
    show_port_frequency(t, hosts)
    show_bbs_services(t, hosts)
    show_versions(t, hosts)
    show_non_bbs_ports(t, hosts)
    show_banners(t, hosts)


if __name__ == '__main__':
    main()
