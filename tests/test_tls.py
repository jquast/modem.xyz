"""Tests for TLS/SSL awareness in the moderation tool."""

import json
import os

import pytest

from moderation.data import (
    _parse_ssl_from_line,
    _parse_host_port_ssl_set,
    append_to_list,
    update_list_entry,
)
from moderation.decisions import find_stale_tls_decisions
from moderation.dedup import _filter_tls_pair_groups, _identify_tls_pairs
from moderation.tls import _build_ssl_line, _detect_tls_port, discover_tls_ports


class TestParseSslFromLine:

    @pytest.mark.parametrize("line,expected", [
        ("mud.example.com 4000", False),
        ("mud.example.com 4000 utf-8", False),
        ("mud.example.com 4000 ssl", True),
        ("mud.example.com 4000 utf-8 ssl", True),
        ("mud.example.com 4000 ssl utf-8", True),
        ("mud.example.com 4000 cp437 80 ssl", True),
    ])
    def test_various_formats(self, line, expected):
        assert _parse_ssl_from_line(line) == expected


class TestParseHostPortSslSet:

    def test_mixed_entries(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text(
            "# comment\n"
            "mud.example.com 4000\n"
            "mud.example.com 4001 ssl\n"
            "bbs.example.com 23 cp437\n"
            "\n"
        )
        result = _parse_host_port_ssl_set(str(lst))
        assert ("mud.example.com", 4000, False) in result
        assert ("mud.example.com", 4001, True) in result
        assert ("bbs.example.com", 23, False) in result
        assert len(result) == 3


class TestDetectTlsPort:

    @pytest.mark.parametrize("mssp,expected_port,expected_same", [
        ({"TLS": "3334"}, 3334, False),
        ({"TLS": "1"}, 1, True),
        ({"TLS": "0"}, None, False),
        ({"TLS": "-1"}, None, False),
        ({}, None, False),
        ({"SSL": "4443"}, 4443, False),
        ({"SSL": "1"}, 1, True),
        ({"TLS": "0", "SSL": "5555"}, 5555, False),
        ({"TLS": "bad"}, None, False),
    ])
    def test_detection(self, mssp, expected_port, expected_same):
        port, same = _detect_tls_port(mssp)
        assert port == expected_port
        assert same == expected_same


class TestIdentifyTlsPairs:

    def test_ssl_entries_paired(self):
        records = [
            {"host": "mud.example.com", "port": 4000,
             "fingerprint": "fp1", "ip": "1.2.3.4", "mssp": {}},
            {"host": "mud.example.com", "port": 4001,
             "fingerprint": "fp1", "ip": "1.2.3.4", "mssp": {}},
        ]
        ssl_entries = {
            ("mud.example.com", 4000, False),
            ("mud.example.com", 4001, True),
        }
        paired = _identify_tls_pairs(records, ssl_entries)
        assert ("mud.example.com", 4000) in paired
        assert ("mud.example.com", 4001) in paired

    def test_mssp_advertised_pair(self):
        records = [
            {"host": "mud.example.com", "port": 3333,
             "fingerprint": "fp1", "ip": "1.2.3.4",
             "mssp": {"TLS": "3334"}},
            {"host": "mud.example.com", "port": 3334,
             "fingerprint": "fp1", "ip": "1.2.3.4",
             "mssp": {}},
        ]
        ssl_entries = {
            ("mud.example.com", 3333, False),
            ("mud.example.com", 3334, False),
        }
        paired = _identify_tls_pairs(records, ssl_entries)
        assert ("mud.example.com", 3333) in paired
        assert ("mud.example.com", 3334) in paired

    def test_unrelated_not_paired(self):
        records = [
            {"host": "a.example.com", "port": 4000,
             "fingerprint": "fp1", "ip": "1.2.3.4", "mssp": {}},
            {"host": "b.example.com", "port": 4000,
             "fingerprint": "fp1", "ip": "1.2.3.4", "mssp": {}},
        ]
        ssl_entries = {
            ("a.example.com", 4000, False),
            ("b.example.com", 4000, False),
        }
        paired = _identify_tls_pairs(records, ssl_entries)
        assert len(paired) == 0


class TestFilterTlsPairGroups:

    def test_tls_pair_group_filtered(self):
        groups = {
            ("fp1", "1.2.3.4"): [
                {"host": "mud.example.com", "port": 3333},
                {"host": "mud.example.com", "port": 3334},
            ]
        }
        tls_paired = {
            ("mud.example.com", 3333),
            ("mud.example.com", 3334),
        }
        result = _filter_tls_pair_groups(groups, tls_paired)
        assert len(result) == 0

    def test_mixed_host_group_kept(self):
        groups = {
            ("fp1", "1.2.3.4"): [
                {"host": "a.example.com", "port": 3333},
                {"host": "b.example.com", "port": 3333},
            ]
        }
        tls_paired = {("a.example.com", 3333)}
        result = _filter_tls_pair_groups(groups, tls_paired)
        assert len(result) == 1

    def test_non_paired_group_kept(self):
        groups = {
            ("fp1", "1.2.3.4"): [
                {"host": "mud.example.com", "port": 3333},
                {"host": "mud.example.com", "port": 4444},
            ]
        }
        tls_paired = set()
        result = _filter_tls_pair_groups(groups, tls_paired)
        assert len(result) == 1


class TestBuildSslLine:

    @pytest.mark.parametrize("existing,host,tls_port,expected", [
        ("mud.example.com 4000", "mud.example.com", 4001,
         "mud.example.com 4001 ssl"),
        ("mud.example.com 4000 utf-8", "mud.example.com", 4001,
         "mud.example.com 4001 utf-8 ssl"),
        ("mud.example.com 4000 cp437 80", "mud.example.com", 4001,
         "mud.example.com 4001 cp437 80 ssl"),
        (None, "mud.example.com", 4001,
         "mud.example.com 4001 ssl"),
        ("mud.example.com 4000 ssl", "mud.example.com", 4001,
         "mud.example.com 4001 ssl"),
    ])
    def test_build(self, existing, host, tls_port, expected):
        assert _build_ssl_line(existing, host, tls_port) == expected


class TestDiscoverTlsPorts:

    @staticmethod
    def _make_data(tmp_path, host, port, mssp):
        server_dir = tmp_path / "server" / "fakefp"
        server_dir.mkdir(parents=True)
        data = {
            "server-probe": {
                "fingerprint": "fakefp",
                "session_data": {"mssp": mssp},
            },
            "sessions": [
                {"host": host, "port": port, "ip": "1.2.3.4",
                 "connected": "2026-01-01"}
            ],
        }
        json_path = server_dir / f"{host}_{port}.json"
        json_path.write_text(json.dumps(data))

    def test_different_port_discovered(self, tmp_path):
        self._make_data(tmp_path, "mud.example.com", 4000,
                        {"TLS": "4001"})
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000\n")
        issues = discover_tls_ports(str(tmp_path), str(lst))
        assert len(issues) == 1
        assert issues[0]['tls_port'] == 4001
        assert issues[0]['same_port'] is False

    def test_same_port_discovered(self, tmp_path):
        self._make_data(tmp_path, "mud.example.com", 4000,
                        {"TLS": "1"})
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000\n")
        issues = discover_tls_ports(str(tmp_path), str(lst))
        assert len(issues) == 1
        assert issues[0]['same_port'] is True

    def test_already_has_ssl_skipped(self, tmp_path):
        self._make_data(tmp_path, "mud.example.com", 4000,
                        {"TLS": "1"})
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000 ssl\n")
        issues = discover_tls_ports(str(tmp_path), str(lst))
        assert len(issues) == 0

    def test_tls_port_already_in_list_skipped(self, tmp_path):
        self._make_data(tmp_path, "mud.example.com", 4000,
                        {"TLS": "4001"})
        lst = tmp_path / "list.txt"
        lst.write_text(
            "mud.example.com 4000\n"
            "mud.example.com 4001 ssl\n"
        )
        issues = discover_tls_ports(str(tmp_path), str(lst))
        assert len(issues) == 0

    def test_no_mssp_no_issue(self, tmp_path):
        self._make_data(tmp_path, "mud.example.com", 4000, {})
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000\n")
        issues = discover_tls_ports(str(tmp_path), str(lst))
        assert len(issues) == 0


class TestAppendToList:

    def test_appends_lines(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("existing 1234\n")
        count = append_to_list(str(lst), ["new.host 5678 ssl"])
        assert count == 1
        content = lst.read_text()
        assert "existing 1234\n" in content
        assert "new.host 5678 ssl\n" in content

    def test_handles_no_trailing_newline(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("existing 1234")
        append_to_list(str(lst), ["new.host 5678"])
        content = lst.read_text()
        assert content == "existing 1234\nnew.host 5678\n"

    def test_dry_run(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("existing 1234\n")
        count = append_to_list(str(lst), ["new.host 5678"],
                               dry_run=True)
        assert count == 1
        assert lst.read_text() == "existing 1234\n"

    def test_empty_lines_noop(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("existing 1234\n")
        count = append_to_list(str(lst), [])
        assert count == 0


class TestUpdateListEntry:

    def test_adds_ssl_keyword(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text(
            "mud.example.com 4000\n"
            "other.example.com 5000\n"
        )
        result = update_list_entry(str(lst), "mud.example.com",
                                   4000, "ssl")
        assert result is True
        content = lst.read_text()
        assert "mud.example.com 4000 ssl\n" in content
        assert "other.example.com 5000\n" in content

    def test_no_duplicate_keyword(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000 ssl\n")
        update_list_entry(str(lst), "mud.example.com", 4000,
                          "ssl")
        content = lst.read_text()
        assert content.count("ssl") == 1

    def test_dry_run(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("mud.example.com 4000\n")
        result = update_list_entry(str(lst), "mud.example.com",
                                   4000, "ssl", dry_run=True)
        assert result is True
        assert "ssl" not in lst.read_text()

    def test_host_not_found(self, tmp_path):
        lst = tmp_path / "list.txt"
        lst.write_text("other.example.com 5000\n")
        result = update_list_entry(str(lst), "mud.example.com",
                                   4000, "ssl")
        assert result is False


class TestFindStaleTlsDecisions:

    def test_finds_stale(self):
        decisions = {
            "dupes": {
                "mud.example.com:3333|mud.example.com:3334": {
                    "action": "skip"
                },
                "other.com:4000|other.com:5000": {
                    "action": "skip"
                },
            }
        }
        ssl_entries = {
            ("mud.example.com", 3334, True),
            ("unrelated.com", 9999, True),
        }
        stale = find_stale_tls_decisions(decisions, ssl_entries)
        assert len(stale) == 1
        assert "mud.example.com:3333|mud.example.com:3334" in stale

    def test_no_ssl_entries(self):
        decisions = {"dupes": {"a:1|b:2": {"action": "skip"}}}
        stale = find_stale_tls_decisions(decisions, set())
        assert stale == []

    def test_no_stale(self):
        decisions = {"dupes": {"a.com:1|b.com:2": {"action": "skip"}}}
        ssl_entries = {("c.com", 3, True)}
        stale = find_stale_tls_decisions(decisions, ssl_entries)
        assert stale == []
