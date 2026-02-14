"""Tests for make_stats.geoip module."""

import json
import os
import time
from unittest import mock

import pytest

from make_stats.geoip import (
    _country_flag,
    _load_cache,
    _save_cache,
    _query_batch,
    lookup_countries,
    _TTL_SECONDS,
)


class TestCountryFlag:

    @pytest.mark.parametrize("code,expected", [
        ('US', '\U0001f1fa\U0001f1f8'),
        ('DE', '\U0001f1e9\U0001f1ea'),
        ('JP', '\U0001f1ef\U0001f1f5'),
        ('GB', '\U0001f1ec\U0001f1e7'),
    ])
    def test_valid_codes(self, code, expected):
        assert _country_flag(code) == expected

    @pytest.mark.parametrize("code", ['', 'X', 'USA', None])
    def test_invalid_codes(self, code):
        assert _country_flag(code) == ''

    def test_lowercase_treated_as_uppercase(self):
        assert _country_flag('us') == _country_flag('US')


class TestCache:

    def test_load_missing_file(self, tmp_path):
        with mock.patch('make_stats.geoip._CACHE_FILE',
                        str(tmp_path / 'nonexistent.json')):
            assert _load_cache() == {}

    def test_roundtrip(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        data = {'1.2.3.4': {'country': 'US', 'country_name': 'United States',
                             'ts': 1700000000}}
        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file):
            _save_cache(data)
            loaded = _load_cache()
        assert loaded == data

    def test_save_atomic(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        data = {'1.1.1.1': {'country': 'AU', 'country_name': 'Australia',
                             'ts': 1700000000}}
        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file):
            _save_cache(data)
        assert not os.path.exists(cache_file + '.tmp')
        assert os.path.exists(cache_file)


class TestQueryBatch:

    def test_successful_response(self):
        mock_response = mock.Mock()
        mock_response.json.return_value = [
            {'query': '8.8.8.8', 'status': 'success',
             'countryCode': 'US', 'country': 'United States'},
            {'query': '1.1.1.1', 'status': 'success',
             'countryCode': 'AU', 'country': 'Australia'},
        ]
        mock_response.raise_for_status = mock.Mock()

        with mock.patch('make_stats.geoip.requests.post',
                        return_value=mock_response):
            result = _query_batch(['8.8.8.8', '1.1.1.1'])

        assert result == {
            '8.8.8.8': ('US', 'United States'),
            '1.1.1.1': ('AU', 'Australia'),
        }

    def test_failed_lookup(self):
        mock_response = mock.Mock()
        mock_response.json.return_value = [
            {'query': '0.0.0.0', 'status': 'fail',
             'message': 'reserved range'},
        ]
        mock_response.raise_for_status = mock.Mock()

        with mock.patch('make_stats.geoip.requests.post',
                        return_value=mock_response):
            result = _query_batch(['0.0.0.0'])

        assert result == {'0.0.0.0': ('', 'Unknown')}


class TestLookupCountries:

    def test_annotates_servers(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        servers = [
            {'ip': '8.8.8.8', 'host': 'dns.google'},
            {'ip': '1.1.1.1', 'host': 'one.one.one.one'},
        ]
        mock_response = mock.Mock()
        mock_response.json.return_value = [
            {'query': '1.1.1.1', 'status': 'success',
             'countryCode': 'AU', 'country': 'Australia'},
            {'query': '8.8.8.8', 'status': 'success',
             'countryCode': 'US', 'country': 'United States'},
        ]
        mock_response.raise_for_status = mock.Mock()

        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file), \
             mock.patch('make_stats.geoip.requests.post',
                        return_value=mock_response):
            lookup_countries(servers)

        assert servers[0]['_country_code'] == 'US'
        assert servers[0]['_country_name'] == 'United States'
        assert servers[1]['_country_code'] == 'AU'
        assert servers[1]['_country_name'] == 'Australia'

    def test_uses_cache(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        cache_data = {
            '8.8.8.8': {'country': 'US', 'country_name': 'United States',
                         'ts': time.time()},
        }
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)

        servers = [{'ip': '8.8.8.8', 'host': 'dns.google'}]

        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file), \
             mock.patch('make_stats.geoip.requests.post') as mock_post:
            lookup_countries(servers)

        mock_post.assert_not_called()
        assert servers[0]['_country_code'] == 'US'

    def test_stale_cache_triggers_query(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        old_ts = time.time() - _TTL_SECONDS - 1
        cache_data = {
            '8.8.8.8': {'country': 'US', 'country_name': 'United States',
                         'ts': old_ts},
        }
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)

        servers = [{'ip': '8.8.8.8', 'host': 'dns.google'}]
        mock_response = mock.Mock()
        mock_response.json.return_value = [
            {'query': '8.8.8.8', 'status': 'success',
             'countryCode': 'US', 'country': 'United States'},
        ]
        mock_response.raise_for_status = mock.Mock()

        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file), \
             mock.patch('make_stats.geoip.requests.post',
                        return_value=mock_response):
            lookup_countries(servers)

        mock_response.raise_for_status.assert_called_once()

    def test_empty_ip_skipped(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        servers = [{'ip': '', 'host': 'noip.example'}]

        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file), \
             mock.patch('make_stats.geoip.requests.post') as mock_post:
            lookup_countries(servers)

        mock_post.assert_not_called()
        assert servers[0]['_country_code'] == ''
        assert servers[0]['_country_name'] == 'Unknown'

    def test_deduplicates_ips(self, tmp_path):
        cache_file = str(tmp_path / 'cache.json')
        servers = [
            {'ip': '8.8.8.8', 'host': 'a.example'},
            {'ip': '8.8.8.8', 'host': 'b.example'},
        ]
        mock_response = mock.Mock()
        mock_response.json.return_value = [
            {'query': '8.8.8.8', 'status': 'success',
             'countryCode': 'US', 'country': 'United States'},
        ]
        mock_response.raise_for_status = mock.Mock()

        with mock.patch('make_stats.geoip._CACHE_FILE', cache_file), \
             mock.patch('make_stats.geoip.requests.post',
                        return_value=mock_response) as mock_post:
            lookup_countries(servers)

        args = mock_post.call_args
        assert len(args[1]['json']) == 1
        assert servers[0]['_country_code'] == 'US'
        assert servers[1]['_country_code'] == 'US'
