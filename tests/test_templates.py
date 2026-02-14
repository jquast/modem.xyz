"""Tests for Jinja2 template rendering."""

import pytest

from make_stats.common import (
    _jinja_env,
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
