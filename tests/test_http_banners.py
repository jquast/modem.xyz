"""Tests for HTTP response banner detection in the moderation tool."""

import json
import os

import pytest

from moderation.banner_analysis import (
    _is_http_banner,
    discover_http_banners,
    review_http_banners,
)


def _make_server_json(host, port, banner_before='', banner_after=''):
    return {
        'server-probe': {
            'fingerprint': 'test',
            'session_data': {
                'banner_before_return': banner_before,
                'banner_after_return': banner_after,
            },
        },
        'sessions': [{'host': host, 'port': port, 'connected': '2026-01-01'}],
    }


def _write_server(data_dir, fingerprint, filename, data):
    fp_dir = os.path.join(data_dir, 'server', fingerprint)
    os.makedirs(fp_dir, exist_ok=True)
    path = os.path.join(fp_dir, filename)
    with open(path, 'w') as f:
        json.dump(data, f)
    return path


class TestIsHttpBanner:

    @pytest.mark.parametrize('text', [
        'HTTP/1.1 400 Bad Request\r\n',
        'HTTP/1.0 200 OK\r\n',
        'HTTP/2 403 Forbidden\r\n',
        '  HTTP/1.1 400 Bad Request\r\n',
        '\n HTTP/1.1 503 Service Unavailable\r\n',
    ])
    def test_detects_http_responses(self, text):
        assert _is_http_banner(text) is True

    @pytest.mark.parametrize('text', [
        'Welcome to the MUD!\r\n',
        'This server uses HTTP/1.1 internally',
        'Connected via HTTP/2 proxy',
        '',
        None,
    ])
    def test_ignores_non_http(self, text):
        assert _is_http_banner(text) is False


class TestDiscoverHttpBanners:

    def test_finds_http_banner_after(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'httphost.example.com', 80,
            banner_after='HTTP/1.1 400 Bad Request\r\n'))
        _write_server(data_dir, 'fp2', 'srv2.json', _make_server_json(
            'goodhost.example.com', 23,
            banner_after='Welcome to the server!\r\n'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text(
            'httphost.example.com 80\n'
            'goodhost.example.com 23\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 1
        assert issues[0]['host'] == 'httphost.example.com'
        assert issues[0]['port'] == 80

    def test_finds_http_banner_before(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'httphost.example.com', 8080,
            banner_before='HTTP/1.0 200 OK\r\nContent-Type: text/html'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text('httphost.example.com 8080\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 1

    def test_skips_unlisted_server(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'httphost.example.com', 80,
            banner_after='HTTP/1.1 400 Bad Request\r\n'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text('otherhost.example.com 23\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 0

    def test_no_server_dir(self, tmp_path):
        list_path = tmp_path / 'list.txt'
        list_path.write_text('host.example.com 23\n')
        issues = discover_http_banners(str(tmp_path), str(list_path))
        assert issues == []

    def test_deduplicates_by_host_port(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'httphost.example.com', 80,
            banner_after='HTTP/1.1 400 Bad Request\r\n'))
        _write_server(data_dir, 'fp2', 'srv2.json', _make_server_json(
            'httphost.example.com', 80,
            banner_after='HTTP/1.1 400 Bad Request\r\n'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text('httphost.example.com 80\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 1

    def test_leading_whitespace_in_banner(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'httphost.example.com', 80,
            banner_after='  \n HTTP/1.1 400 Bad Request\r\n'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text('httphost.example.com 80\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 1

    def test_http_in_middle_not_flagged(self, tmp_path):
        data_dir = str(tmp_path)
        _write_server(data_dir, 'fp1', 'srv1.json', _make_server_json(
            'goodhost.example.com', 23,
            banner_after='Welcome! We support HTTP/1.1 proxying.\r\n'))

        list_path = tmp_path / 'list.txt'
        list_path.write_text('goodhost.example.com 23\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 0

    def test_dict_banner_format(self, tmp_path):
        data_dir = str(tmp_path)
        data = {
            'server-probe': {
                'fingerprint': 'test',
                'session_data': {
                    'banner_before_return': '',
                    'banner_after_return': {
                        'text': 'HTTP/1.1 400 Bad Request\r\n'
                    },
                },
            },
            'sessions': [
                {'host': 'dicthost.example.com', 'port': 80,
                 'connected': '2026-01-01'}
            ],
        }
        _write_server(data_dir, 'fp1', 'srv1.json', data)

        list_path = tmp_path / 'list.txt'
        list_path.write_text('dicthost.example.com 80\n')

        issues = discover_http_banners(data_dir, str(list_path))
        assert len(issues) == 1


class TestReviewHttpBanners:

    def test_remove_from_list(self, tmp_path, monkeypatch):
        list_path = tmp_path / 'mudlist.txt'
        list_path.write_text(
            'httphost.example.com 80\n'
            'goodhost.example.com 23\n')
        logs_dir = tmp_path / 'logs'
        logs_dir.mkdir()

        mud_issues = [{
            'host': 'httphost.example.com',
            'port': 80,
            'data_path': '/fake/path.json',
            'raw_banner': 'HTTP/1.1 400 Bad Request\r\n',
        }]

        monkeypatch.setattr('moderation.banner_analysis._prompt',
                            lambda msg, choices: 'y')

        mud_rm, bbs_rm = review_http_banners(
            mud_issues, [], str(list_path), str(list_path),
            str(logs_dir))

        assert ('httphost.example.com', 80) in mud_rm
        assert bbs_rm == set()
        content = list_path.read_text()
        assert 'httphost.example.com' not in content
        assert 'goodhost.example.com' in content

    def test_skip_preserves_list(self, tmp_path, monkeypatch):
        list_path = tmp_path / 'mudlist.txt'
        list_path.write_text('httphost.example.com 80\n')
        logs_dir = tmp_path / 'logs'
        logs_dir.mkdir()

        mud_issues = [{
            'host': 'httphost.example.com',
            'port': 80,
            'data_path': '/fake/path.json',
            'raw_banner': 'HTTP/1.1 400 Bad Request\r\n',
        }]

        monkeypatch.setattr('moderation.banner_analysis._prompt',
                            lambda msg, choices: 'n')

        mud_rm, bbs_rm = review_http_banners(
            mud_issues, [], str(list_path), str(list_path),
            str(logs_dir))

        assert mud_rm == set()
        assert 'httphost.example.com' in list_path.read_text()

    def test_report_only_no_prompt(self, tmp_path, monkeypatch):
        list_path = tmp_path / 'mudlist.txt'
        list_path.write_text('httphost.example.com 80\n')
        logs_dir = tmp_path / 'logs'
        logs_dir.mkdir()

        mud_issues = [{
            'host': 'httphost.example.com',
            'port': 80,
            'data_path': '/fake/path.json',
            'raw_banner': 'HTTP/1.1 400 Bad Request\r\n',
        }]

        prompt_called = []
        monkeypatch.setattr('moderation.banner_analysis._prompt',
                            lambda msg, choices: prompt_called.append(1))

        mud_rm, bbs_rm = review_http_banners(
            mud_issues, [], str(list_path), str(list_path),
            str(logs_dir), report_only=True)

        assert prompt_called == []
        assert mud_rm == set()

    def test_expunge_deletes_log(self, tmp_path, monkeypatch):
        list_path = tmp_path / 'mudlist.txt'
        list_path.write_text('httphost.example.com 80\n')
        logs_dir = tmp_path / 'logs'
        logs_dir.mkdir()
        log_file = logs_dir / 'httphost.example.com:80.log'
        log_file.write_text('some log content')

        mud_issues = [{
            'host': 'httphost.example.com',
            'port': 80,
            'data_path': '/fake/path.json',
            'raw_banner': 'HTTP/1.1 400 Bad Request\r\n',
        }]

        monkeypatch.setattr('moderation.banner_analysis._prompt',
                            lambda msg, choices: 'x')

        review_http_banners(
            mud_issues, [], str(list_path), str(list_path),
            str(logs_dir))

        assert not log_file.exists()
