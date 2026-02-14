"""Tests for Jinja2 template rendering."""

import pytest

from make_stats.common import (
    _jinja_env,
    _prepare_banner_page_groups,
    _render_template,
)


class TestJinjaEnv:

    def test_env_is_cached(self):
        env1 = _jinja_env()
        env2 = _jinja_env()
        assert env1 is env2

    def test_custom_filters_registered(self):
        env = _jinja_env()
        assert 'rst_escape' in env.filters
        assert 'banner_alt_text' in env.filters

    def test_trim_blocks_enabled(self):
        env = _jinja_env()
        assert env.trim_blocks
        assert env.lstrip_blocks


class TestCollapsibleJsonTemplate:

    def test_json_rendered(self):
        result = _render_template(
            'collapsible_json.rst.j2',
            data_path='data-muds/server/test.json',
            github_url='https://github.com/test',
            description='Fingerprint data.',
            json_lines=['{"key": "value"}'],
        )
        assert '<details><summary>Show JSON</summary>' in result
        assert '{"key": "value"}' in result


class TestBannerGalleryPageTemplate:

    def test_page_heading(self):
        result = _render_template(
            'banner_gallery_page.rst.j2',
            page_groups=[],
            page_num=1,
            total_pages=3,
            page_label='[A-F]',
            detail_subdir='detail',
        )
        assert 'Page 1 of 3' in result

    def test_shared_banner_message(self):
        groups = [{
            'banner': 'Welcome',
            'servers': [
                {'_name': 'a.com:23', '_detail_file': 'a', '_tls': '',
                 '_flag': '\U0001f1fa\U0001f1f8', '_banner_png': 'b.png',
                 'host': 'a.com', 'port': 23},
                {'_name': 'b.com:23', '_detail_file': 'b', '_tls': '',
                 '_flag': '\U0001f1e9\U0001f1ea', 'host': 'b.com', 'port': 23},
            ],
        }]
        result = _render_template(
            'banner_gallery_page.rst.j2',
            page_groups=groups,
            page_num=1, total_pages=1,
            page_label='[A]', detail_subdir='detail',
        )
        assert 'shared by the following 2 servers' in result
        assert '\U0001f1fa\U0001f1f8' in result
        assert '\U0001f1e9\U0001f1ea' in result

    def test_single_server_no_shared_message(self):
        groups = [{
            'banner': 'Welcome',
            'servers': [
                {'_name': 'a.com:23', '_detail_file': 'a', '_tls': '',
                 '_flag': '', 'host': 'a.com', 'port': 23},
            ],
        }]
        result = _render_template(
            'banner_gallery_page.rst.j2',
            page_groups=groups,
            page_num=1, total_pages=1,
            page_label='[A]', detail_subdir='detail',
        )
        assert 'shared by' not in result


class TestPrepareBannerPageGroups:

    def test_flag_enrichment(self):
        groups = [{'banner': 'hi', 'servers': [
            {'host': 'a.com', 'port': 23, '_file': 'a',
             '_country_code': 'US'},
            {'host': 'b.com', 'port': 23, '_file': 'b',
             '_country_code': 'DE'},
        ]}]
        result = _prepare_banner_page_groups(
            groups, '_file', lambda s: f"{s['host']}:{s['port']}",
            lambda s: False)
        assert result[0]['servers'][0]['_flag'] == '\U0001f1fa\U0001f1f8'
        assert result[0]['servers'][1]['_flag'] == '\U0001f1e9\U0001f1ea'

    def test_missing_country_code(self):
        groups = [{'banner': 'hi', 'servers': [
            {'host': 'a.com', 'port': 23, '_file': 'a'},
        ]}]
        result = _prepare_banner_page_groups(
            groups, '_file', lambda s: f"{s['host']}:{s['port']}",
            lambda s: False)
        assert result[0]['servers'][0]['_flag'] == ''
