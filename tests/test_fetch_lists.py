"""Tests for fetch_lists.py list fetching and merging."""

import io
import json
import zipfile

from make_stats.common import _load_ssh_overrides
from fetch_lists import (
    _load_list,
    _load_rejected,
    _merge_entries,
    _merge_ssh_entries,
    _remove_rlogin_dupes,
    _write_merged_list,
    fetch_commodorebbs,
    fetch_ibbs_csv,
    fetch_relay_cfg,
    fetch_sbbsimsg,
    fetch_telnetsupport,
)


class TestLoadList:

    def test_empty_file(self, tmp_path):
        p = tmp_path / 'empty.txt'
        p.write_text('')
        header, entries = _load_list(str(p))
        assert header == []
        assert entries == {}

    def test_missing_file(self, tmp_path):
        header, entries = _load_list(str(tmp_path / 'missing.txt'))
        assert header == []
        assert entries == {}

    def test_header_comments_preserved(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('# comment\n# another\nexample.com 23\n')
        header, entries = _load_list(str(p))
        assert header == ['# comment', '# another']
        assert ('example.com', 23) in entries

    def test_entries_parsed(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('example.com 23\ntest.org 4000 utf-8\n')
        header, entries = _load_list(str(p))
        assert header == []
        assert entries[('example.com', 23)] == 'example.com 23'
        assert entries[('test.org', 4000)] == 'test.org 4000 utf-8'

    def test_encoding_and_columns_preserved(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('host.com 23 cp437 90\n')
        _, entries = _load_list(str(p))
        assert entries[('host.com', 23)] == 'host.com 23 cp437 90'

    def test_case_insensitive_keys(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('Example.COM 23\n')
        _, entries = _load_list(str(p))
        assert ('example.com', 23) in entries

    def test_inline_comments_after_header(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('# header\nexample.com 23\n# mid comment\ntest.org 80\n')
        header, entries = _load_list(str(p))
        assert len(header) == 1
        assert len(entries) == 2

    def test_blank_header_lines(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('# comment\n\nexample.com 23\n')
        header, entries = _load_list(str(p))
        assert header == ['# comment', '']
        assert len(entries) == 1

    def test_invalid_port_skipped(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('example.com notaport\nvalid.com 23\n')
        _, entries = _load_list(str(p))
        assert len(entries) == 1
        assert ('valid.com', 23) in entries

    def test_ssh_line_preserved(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('example.com 23 cp437\nexample.com ssh 2222\n')
        _, entries = _load_list(str(p))
        assert ('example.com', 23) in entries
        assert ('example.com', 'ssh') in entries
        assert entries[('example.com', 'ssh')] == 'example.com ssh 2222'

    def test_ssh_line_default_port(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('example.com 23\nexample.com ssh\n')
        _, entries = _load_list(str(p))
        assert ('example.com', 'ssh') in entries
        assert entries[('example.com', 'ssh')] == 'example.com ssh'


class TestWriteMergedList:

    def test_writes_atomically(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('original')
        entries = {('example.com', 23): 'example.com 23'}
        _write_merged_list(str(p), ['# header'], entries)
        assert not (tmp_path / 'list.txt.new').exists()
        content = p.read_text()
        assert '# header\n' in content
        assert 'example.com 23\n' in content

    def test_dry_run_does_not_write(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('original')
        entries = {('example.com', 23): 'example.com 23'}
        _write_merged_list(str(p), [], entries, dry_run=True)
        assert p.read_text() == 'original'

    def test_entries_sorted(self, tmp_path):
        p = tmp_path / 'list.txt'
        p.write_text('')
        entries = {
            ('zebra.com', 23): 'zebra.com 23',
            ('alpha.com', 80): 'alpha.com 80',
        }
        _write_merged_list(str(p), [], entries)
        lines = p.read_text().strip().split('\n')
        assert lines[0] == 'alpha.com 80'
        assert lines[1] == 'zebra.com 23'


class TestMergeEntries:

    def test_adds_new_entries(self):
        existing = {}
        added, rej, alt, cross = _merge_entries(
            existing, [('example.com', 23)])
        assert added == 1
        assert rej == 0
        assert ('example.com', 23) in existing

    def test_skips_existing(self):
        existing = {('example.com', 23): 'example.com 23'}
        added, rej, alt, cross = _merge_entries(
            existing, [('example.com', 23)])
        assert added == 0

    def test_case_insensitive_dedup(self):
        existing = {('example.com', 23): 'Example.COM 23'}
        added, _, _, _ = _merge_entries(existing, [('Example.COM', 23)])
        assert added == 0
        assert existing[('example.com', 23)] == 'Example.COM 23'

    def test_encoding_hint_applied(self):
        existing = {}
        _merge_entries(existing, [('bbs.c64.com', 6400)],
                       encoding_hint='petscii')
        assert existing[('bbs.c64.com', 6400)] == 'bbs.c64.com 6400 petscii'

    def test_no_encoding_hint(self):
        existing = {}
        _merge_entries(existing, [('mud.org', 4000)])
        assert existing[('mud.org', 4000)] == 'mud.org 4000'

    def test_ssl_flag_appended(self):
        existing = {}
        _merge_entries(existing, [('secure.mud.org', 4712, True)])
        assert existing[('secure.mud.org', 4712)] == 'secure.mud.org 4712 ssl'

    def test_ssl_with_encoding_hint(self):
        existing = {}
        _merge_entries(existing, [('secure.mud.org', 4712, True)],
                       encoding_hint='utf-8')
        assert existing[('secure.mud.org', 4712)] == 'secure.mud.org 4712 utf-8 ssl'

    def test_no_ssl_flag(self):
        existing = {}
        _merge_entries(existing, [('plain.mud.org', 23, False)])
        assert existing[('plain.mud.org', 23)] == 'plain.mud.org 23'

    def test_idempotent(self):
        existing = {}
        _merge_entries(existing, [('a.com', 23), ('b.com', 80)])
        added, _, _, _ = _merge_entries(
            existing, [('a.com', 23), ('b.com', 80)])
        assert added == 0
        assert len(existing) == 2

    def test_preserves_existing_overrides(self):
        existing = {('bbs.com', 23): 'bbs.com 23 cp437 90'}
        _merge_entries(existing, [('bbs.com', 23)],
                       encoding_hint='petscii')
        assert existing[('bbs.com', 23)] == 'bbs.com 23 cp437 90'

    def test_skips_rejected_entries(self):
        existing = {}
        rejected = {('dead.com', 23), ('gone.org', 80)}
        added, rej, alt, cross = _merge_entries(
            existing,
            [('dead.com', 23), ('new.com', 80), ('gone.org', 80)],
            rejected=rejected)
        assert added == 1
        assert rej == 2
        assert ('new.com', 80) in existing
        assert ('dead.com', 23) not in existing

    def test_rejected_case_insensitive(self):
        existing = {}
        rejected = {('dead.com', 23)}
        added, rej, alt, cross = _merge_entries(
            existing, [('DEAD.COM', 23)], rejected=rejected)
        assert added == 0
        assert rej == 1

    def test_skips_cross_list_hosts(self):
        existing = {}
        exclude = {'mudserver.org', 'anothermud.com'}
        added, rej, alt, cross = _merge_entries(
            existing,
            [('mudserver.org', 4000), ('newbbs.com', 23),
             ('AnotherMud.COM', 5555)],
            exclude_hosts=exclude)
        assert added == 1
        assert cross == 2
        assert ('newbbs.com', 23) in existing
        assert ('mudserver.org', 4000) not in existing


class TestLoadRejected:

    def test_missing_file(self, tmp_path):
        result = _load_rejected(
            str(tmp_path / 'missing.json'), 'bbs')
        assert result == set()

    def test_loads_entries(self, tmp_path):
        p = tmp_path / 'decisions.json'
        p.write_text(json.dumps({
            'rejected': {
                'bbs': {'dead.com:23': 'dead', 'gone.org:80': 'dns'},
                'mud': {'old.mud:4000': 'duplicate'},
            }
        }))
        bbs = _load_rejected(str(p), 'bbs')
        assert ('dead.com', 23) in bbs
        assert ('gone.org', 80) in bbs
        assert ('old.mud', 4000) not in bbs

        mud = _load_rejected(str(p), 'mud')
        assert ('old.mud', 4000) in mud
        assert ('dead.com', 23) not in mud

    def test_empty_rejected(self, tmp_path):
        p = tmp_path / 'decisions.json'
        p.write_text(json.dumps({'cross': {}, 'dupes': {}}))
        result = _load_rejected(str(p), 'bbs')
        assert result == set()

    def test_malformed_entries_skipped(self, tmp_path):
        p = tmp_path / 'decisions.json'
        p.write_text(json.dumps({
            'rejected': {
                'bbs': {
                    'valid.com:23': 'dead',
                    'no-port': 'bad',
                    'bad:port:format': 'bad',
                },
            }
        }))
        result = _load_rejected(str(p), 'bbs')
        assert len(result) == 1
        assert ('valid.com', 23) in result


class TestFetchRelayCfg:

    def test_parses_host_colon_port(self, tmp_path):
        p = tmp_path / 'relay.cfg'
        p.write_text('example.com:23\ntest.org:4000\n')
        result = fetch_relay_cfg(str(p))
        assert ('example.com', 23) in result
        assert ('test.org', 4000) in result

    def test_skips_comments_and_blanks(self, tmp_path):
        p = tmp_path / 'relay.cfg'
        p.write_text('# comment\n\nexample.com:23\n')
        result = fetch_relay_cfg(str(p))
        assert len(result) == 1

    def test_space_separated_fallback(self, tmp_path):
        p = tmp_path / 'relay.cfg'
        p.write_text('example.com 23\n')
        result = fetch_relay_cfg(str(p))
        assert ('example.com', 23) in result

    def test_invalid_port_skipped(self, tmp_path):
        p = tmp_path / 'relay.cfg'
        p.write_text('example.com:abc\nvalid.com:23\n')
        result = fetch_relay_cfg(str(p))
        assert len(result) == 1

    def test_deduplicates_within_source(self, tmp_path):
        p = tmp_path / 'relay.cfg'
        p.write_text('example.com:23\nExample.COM:23\n')
        result = fetch_relay_cfg(str(p))
        assert len(result) == 1


class TestFetchCommodorebbs:

    def test_parses_json(self, tmp_path, monkeypatch):
        data = [
            {'address': 'bbs.c64.com', 'port': 6400, 'online': True},
            {'address': 'retro.bbs.org', 'port': 23, 'online': False},
        ]
        p = tmp_path / 'bbs.json'
        p.write_text(json.dumps(data))
        monkeypatch.setattr(
            'fetch_lists.COMMODOREBBS_URL', 'file://' + str(p))
        result = fetch_commodorebbs('file://' + str(p))
        assert ('bbs.c64.com', 6400) in result
        assert ('retro.bbs.org', 23) in result

    def test_skips_empty_address(self, tmp_path, monkeypatch):
        data = [
            {'address': '', 'port': 23},
            {'address': None, 'port': 23},
            {'address': 'valid.com', 'port': 80},
        ]
        p = tmp_path / 'bbs.json'
        p.write_text(json.dumps(data))
        result = fetch_commodorebbs('file://' + str(p))
        assert len(result) == 1

    def test_skips_missing_port(self, tmp_path):
        data = [{'address': 'bbs.com'}]
        p = tmp_path / 'bbs.json'
        p.write_text(json.dumps(data))
        result = fetch_commodorebbs('file://' + str(p))
        assert len(result) == 0


class TestFetchTelnetsupport:

    def test_parses_json_and_saves_local(self, tmp_path):
        data = [
            {'host': 'aardwolf.org', 'port': 23, 'ssl': 0, 'up': 1},
            {'host': 'batmud.bat.org', 'port': 23, 'ssl': 0, 'up': 1},
        ]
        p = tmp_path / 'ts.json'
        p.write_text(json.dumps(data))
        local = tmp_path / 'telnetsupport.json'
        result = fetch_telnetsupport(
            'file://' + str(p), local_path=str(local))
        assert ('aardwolf.org', 23, False) in result
        assert ('batmud.bat.org', 23, False) in result
        assert local.exists()
        saved = json.loads(local.read_text())
        assert len(saved) == 2

    def test_ssl_flag_detected(self, tmp_path):
        data = [
            {'host': 'secure.mud.org', 'port': 4712, 'ssl': 1, 'up': 1},
            {'host': 'plain.mud.org', 'port': 23, 'ssl': 0, 'up': 1},
        ]
        p = tmp_path / 'ts.json'
        p.write_text(json.dumps(data))
        local = tmp_path / 'telnetsupport.json'
        result = fetch_telnetsupport(
            'file://' + str(p), local_path=str(local))
        assert ('secure.mud.org', 4712, True) in result
        assert ('plain.mud.org', 23, False) in result

    def test_skips_empty_host(self, tmp_path):
        data = [
            {'host': '', 'port': 23},
            {'host': 'valid.org', 'port': 4000},
        ]
        p = tmp_path / 'ts.json'
        p.write_text(json.dumps(data))
        local = tmp_path / 'telnetsupport.json'
        result = fetch_telnetsupport(
            'file://' + str(p), local_path=str(local))
        assert len(result) == 1
        assert result[0][0] == 'valid.org'

    def test_deduplicates_within_source(self, tmp_path):
        data = [
            {'host': 'mud.org', 'port': 23},
            {'host': 'MUD.ORG', 'port': 23},
        ]
        p = tmp_path / 'ts.json'
        p.write_text(json.dumps(data))
        local = tmp_path / 'telnetsupport.json'
        result = fetch_telnetsupport(
            'file://' + str(p), local_path=str(local))
        assert len(result) == 1


class TestRemoveRloginDupes:

    def test_removes_513_when_other_port_exists(self):
        entries = {
            ('example.com', 23): 'example.com 23',
            ('example.com', 513): 'example.com 513',
        }
        removed = _remove_rlogin_dupes(entries)
        assert removed == 1
        assert ('example.com', 23) in entries
        assert ('example.com', 513) not in entries

    def test_keeps_513_when_only_port(self):
        entries = {
            ('rlogin-only.com', 513): 'rlogin-only.com 513',
        }
        removed = _remove_rlogin_dupes(entries)
        assert removed == 0
        assert ('rlogin-only.com', 513) in entries

    def test_no_rlogin_entries(self):
        entries = {
            ('a.com', 23): 'a.com 23',
            ('b.com', 4000): 'b.com 4000',
        }
        removed = _remove_rlogin_dupes(entries)
        assert removed == 0
        assert len(entries) == 2

    def test_multiple_hosts(self):
        entries = {
            ('a.com', 23): 'a.com 23',
            ('a.com', 513): 'a.com 513',
            ('b.com', 513): 'b.com 513',
            ('c.com', 2323): 'c.com 2323',
            ('c.com', 513): 'c.com 513 utf-8',
        }
        removed = _remove_rlogin_dupes(entries)
        assert removed == 2
        assert ('a.com', 513) not in entries
        assert ('c.com', 513) not in entries
        assert ('b.com', 513) in entries

    def test_empty_dict(self):
        entries = {}
        removed = _remove_rlogin_dupes(entries)
        assert removed == 0


class TestMergeSshEntries:

    def test_adds_ssh_for_known_host(self):
        existing = {('example.com', 23): 'example.com 23'}
        ssh_map = {'example.com': ('example.com', 2222)}
        added = _merge_ssh_entries(existing, ssh_map)
        assert added == 1
        assert ('example.com', 'ssh') in existing
        assert existing[('example.com', 'ssh')] == 'example.com ssh 2222'

    def test_skips_unknown_host(self):
        existing = {('known.com', 23): 'known.com 23'}
        ssh_map = {'unknown.com': ('unknown.com', 22)}
        added = _merge_ssh_entries(existing, ssh_map)
        assert added == 0
        assert ('unknown.com', 'ssh') not in existing

    def test_skips_existing_ssh_entry(self):
        existing = {
            ('example.com', 23): 'example.com 23',
            ('example.com', 'ssh'): 'example.com ssh 22',
        }
        ssh_map = {'example.com': ('example.com', 9922)}
        added = _merge_ssh_entries(existing, ssh_map)
        assert added == 0
        assert existing[('example.com', 'ssh')] == 'example.com ssh 22'

    def test_case_insensitive_host_match(self):
        existing = {('example.com', 23): 'Example.COM 23'}
        ssh_map = {'example.com': ('Example.COM', 2222)}
        added = _merge_ssh_entries(existing, ssh_map)
        assert added == 1
        assert ('example.com', 'ssh') in existing

    def test_multiple_hosts(self):
        existing = {
            ('a.com', 23): 'a.com 23',
            ('b.com', 4000): 'b.com 4000',
        }
        ssh_map = {
            'a.com': ('a.com', 2222),
            'b.com': ('b.com', 22),
            'c.com': ('c.com', 22),
        }
        added = _merge_ssh_entries(existing, ssh_map)
        assert added == 2
        assert ('a.com', 'ssh') in existing
        assert ('b.com', 'ssh') in existing
        assert ('c.com', 'ssh') not in existing


def _make_ibbs_zip(csv_content):
    """Return bytes of a zip containing bbslist.csv with csv_content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('bbslist.csv', csv_content)
    return buf.getvalue()


class TestFetchIbbsCsv:

    def test_parses_telnet_entries(self, tmp_path, monkeypatch):
        csv_content = (
            'bbsName,TelnetAddress,TelnetPort,SSHPort,WebAddress,'
            'software,bbsSysop,location\n'
            'Test BBS,testbbs.com,23,,http://testbbs.com,'
            'Synchronet,SysopA,USA\n'
        )
        zip_bytes = _make_ibbs_zip(csv_content)
        csv_out = str(tmp_path / 'ibbs.csv')

        def fake_urlopen(req, timeout=30):
            class Resp:
                def read(self):
                    return zip_bytes
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return Resp()

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        telnet, ssh = fetch_ibbs_csv(
            daily_url='http://fake/ibbs.zip',
            monthly_url='http://fake/ibbs2.zip',
            csv_out=csv_out)
        assert ('testbbs.com', 23) in telnet
        assert 'testbbs.com' not in ssh

    def test_parses_ssh_entries(self, tmp_path, monkeypatch):
        csv_content = (
            'bbsName,TelnetAddress,TelnetPort,SSHPort,WebAddress,'
            'software,bbsSysop,location\n'
            'SSH BBS,sshbbs.com,23,2222,,Mystic BBS,SysopB,CA\n'
        )
        zip_bytes = _make_ibbs_zip(csv_content)
        csv_out = str(tmp_path / 'ibbs.csv')

        def fake_urlopen(req, timeout=30):
            class Resp:
                def read(self):
                    return zip_bytes
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return Resp()

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        telnet, ssh = fetch_ibbs_csv(
            daily_url='http://fake/ibbs.zip',
            monthly_url='http://fake/ibbs2.zip',
            csv_out=csv_out)
        assert ('sshbbs.com', 23) in telnet
        assert ssh['sshbbs.com'] == ('sshbbs.com', 2222)

    def test_saves_csv_atomically(self, tmp_path, monkeypatch):
        csv_content = (
            'bbsName,TelnetAddress,TelnetPort,SSHPort\n'
            'A BBS,a.com,23,\n'
        )
        zip_bytes = _make_ibbs_zip(csv_content)
        csv_out = str(tmp_path / 'ibbs.csv')

        def fake_urlopen(req, timeout=30):
            class Resp:
                def read(self):
                    return zip_bytes
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return Resp()

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        fetch_ibbs_csv(
            daily_url='http://fake/ibbs.zip',
            monthly_url='http://fake/ibbs2.zip',
            csv_out=csv_out)
        assert not (tmp_path / 'ibbs.csv.new').exists()
        import os
        assert os.path.isfile(csv_out)

    def test_falls_back_to_monthly(self, tmp_path, monkeypatch):
        csv_content = (
            'bbsName,TelnetAddress,TelnetPort,SSHPort\n'
            'B BBS,b.com,4000,\n'
        )
        zip_bytes = _make_ibbs_zip(csv_content)
        csv_out = str(tmp_path / 'ibbs.csv')
        call_count = [0]

        def fake_urlopen(req, timeout=30):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError('daily not found')

            class Resp:
                def read(self):
                    return zip_bytes
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return Resp()

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        telnet, ssh = fetch_ibbs_csv(
            daily_url='http://fake/daily.zip',
            monthly_url='http://fake/monthly.zip',
            csv_out=csv_out)
        assert call_count[0] == 2
        assert ('b.com', 4000) in telnet

    def test_raises_when_all_fail(self, tmp_path, monkeypatch):
        import pytest
        csv_out = str(tmp_path / 'ibbs.csv')

        def fake_urlopen(req, timeout=30):
            raise OSError('not found')

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        with pytest.raises(OSError):
            fetch_ibbs_csv(
                daily_url='http://fake/daily.zip',
                monthly_url='http://fake/monthly.zip',
                csv_out=csv_out)

    def test_skips_missing_host(self, tmp_path, monkeypatch):
        csv_content = (
            'bbsName,TelnetAddress,TelnetPort,SSHPort\n'
            'No Host BBS,,23,22\n'
            'A BBS,valid.com,23,\n'
        )
        zip_bytes = _make_ibbs_zip(csv_content)
        csv_out = str(tmp_path / 'ibbs.csv')

        def fake_urlopen(req, timeout=30):
            class Resp:
                def read(self):
                    return zip_bytes
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    pass
            return Resp()

        monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
        telnet, ssh = fetch_ibbs_csv(
            daily_url='http://fake/ibbs.zip',
            monthly_url='http://fake/ibbs2.zip',
            csv_out=csv_out)
        assert len(telnet) == 1
        assert telnet[0][0] == 'valid.com'


class TestFetchSbbsimsg:

    def test_parses_tab_separated(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            'vert.synchro.net\t71.95.196.34\tVertrauen\n'
            'bbs.example.com\t10.0.0.1\tExample BBS\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert ('vert.synchro.net', 23) in result
        assert ('bbs.example.com', 23) in result

    def test_skips_blank_and_comment_lines(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            '# comment line\n'
            '\n'
            'valid.com\t1.2.3.4\tValid BBS\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert len(result) == 1
        assert result[0] == ('valid.com', 23)

    def test_skips_malformed_lines(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            'notabs\n'
            'valid.com\t1.2.3.4\tValid BBS\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert len(result) == 1

    def test_two_field_line_accepted(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text('bbs.example.com\t1.2.3.4\n')
        result = fetch_sbbsimsg(str(p))
        assert len(result) == 1
        assert result[0] == ('bbs.example.com', 23)

    def test_deduplicates_within_source(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            'vert.synchro.net\t71.95.196.34\tVertrauen\n'
            'VERT.SYNCHRO.NET\t71.95.196.34\tVertrauen\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert len(result) == 1

    def test_strips_whitespace(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            '  bbs.example.com  \t10.0.0.1\tExample BBS\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert result[0] == ('bbs.example.com', 23)

    def test_all_port_23(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text(
            'a.com\t1.1.1.1\tA\n'
            'b.com\t2.2.2.2\tB\n'
            'c.com\t3.3.3.3\tC\n'
        )
        result = fetch_sbbsimsg(str(p))
        assert all(port == 23 for _, port in result)

    def test_empty_file(self, tmp_path):
        p = tmp_path / 'sbbsimsg.lst'
        p.write_text('')
        result = fetch_sbbsimsg(str(p))
        assert result == []


class TestEndToEnd:

    def test_full_merge_cycle(self, tmp_path):
        bbs = tmp_path / 'bbslist.txt'
        bbs.write_text('# header\nexisting.com 23 cp437\n')
        header, entries = _load_list(str(bbs))
        _merge_entries(entries, [('new.com', 80)], encoding_hint='petscii')
        _merge_entries(entries, [('existing.com', 23)])
        _write_merged_list(str(bbs), header, entries)
        content = bbs.read_text()
        assert 'existing.com 23 cp437' in content
        assert 'new.com 80 petscii' in content

    def test_idempotent_write(self, tmp_path):
        bbs = tmp_path / 'bbslist.txt'
        bbs.write_text('# header\na.com 23\nb.com 80\n')

        header1, entries1 = _load_list(str(bbs))
        added, _, _, _ = _merge_entries(
            entries1, [('a.com', 23), ('b.com', 80)])
        assert added == 0

        _write_merged_list(str(bbs), header1, entries1)
        header2, entries2 = _load_list(str(bbs))
        assert entries1 == entries2

    def test_rejected_entries_not_added(self, tmp_path):
        bbs = tmp_path / 'bbslist.txt'
        bbs.write_text('existing.com 23\n')
        decisions = tmp_path / 'decisions.json'
        decisions.write_text(json.dumps({
            'rejected': {
                'bbs': {'dead.com:80': 'dead'},
            }
        }))
        rejected = _load_rejected(str(decisions), 'bbs')
        header, entries = _load_list(str(bbs))
        added, rej, alt, cross = _merge_entries(
            entries,
            [('dead.com', 80), ('new.com', 443)],
            rejected=rejected)
        assert added == 1
        assert rej == 1
        assert ('new.com', 443) in entries
        assert ('dead.com', 80) not in entries


class TestLoadSshOverrides:

    def test_missing_file(self, tmp_path):
        result = _load_ssh_overrides(str(tmp_path / 'missing.txt'))
        assert result == {}

    def test_parses_ssh_with_port(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('example.com 23\nexample.com ssh 2222\n')
        result = _load_ssh_overrides(str(p))
        assert result == {'example.com': 2222}

    def test_parses_ssh_default_port(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('example.com 23\nexample.com ssh\n')
        result = _load_ssh_overrides(str(p))
        assert result == {'example.com': 22}

    def test_ignores_comments(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('# example.com ssh 999\nexample.com ssh 2222\n')
        result = _load_ssh_overrides(str(p))
        assert result == {'example.com': 2222}

    def test_ignores_telnet_lines(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('example.com 23 cp437\nother.com 4000\n')
        result = _load_ssh_overrides(str(p))
        assert result == {}

    def test_invalid_ssh_port_skipped(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('example.com ssh badport\nvalid.com ssh 22\n')
        result = _load_ssh_overrides(str(p))
        assert 'example.com' not in result
        assert result == {'valid.com': 22}

    def test_lowercase_host_key(self, tmp_path):
        p = tmp_path / 'bbslist.txt'
        p.write_text('Example.COM ssh 2222\n')
        result = _load_ssh_overrides(str(p))
        assert 'example.com' in result
        assert result['example.com'] == 2222
