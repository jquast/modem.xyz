"""Tests for fetch_lists.py list fetching and merging."""

import json

from fetch_lists import (
    _load_list,
    _load_rejected,
    _merge_entries,
    _write_merged_list,
    fetch_commodorebbs,
    fetch_relay_cfg,
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
        assert ('aardwolf.org', 23) in result
        assert ('batmud.bat.org', 23) in result
        assert local.exists()
        saved = json.loads(local.read_text())
        assert len(saved) == 2

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
