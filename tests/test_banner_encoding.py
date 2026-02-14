"""Tests for banner encoding detection and re-decoding."""

import pytest

from make_stats.common import _combine_banners, _redecode_banner


class TestRedecodeBanner:

    def test_noop_same_encoding(self):
        assert _redecode_banner('hello', 'ascii', 'ascii') == 'hello'

    def test_empty_text(self):
        assert _redecode_banner('', 'ascii', 'cp437') == ''

    def test_none_text(self):
        assert _redecode_banner(None, 'ascii', 'cp437') is None

    def test_ascii_to_cp437_with_surrogates(self):
        raw_bytes = b'\xb0\xb1\xb2\xdb'
        text = raw_bytes.decode('ascii', errors='surrogateescape')
        result = _redecode_banner(text, 'ascii', 'cp437')
        assert result == '░▒▓█'

    def test_ascii_to_cp437_replacement_chars_unchanged(self):
        text = 'hello\ufffdworld'
        result = _redecode_banner(text, 'ascii', 'cp437')
        assert result == text

    def test_unknown_encoding_returns_original(self):
        assert _redecode_banner('test', 'ascii', 'bogus_enc') == 'test'


class TestCombineBanners:

    @staticmethod
    def _server(before='', after='', encoding='ascii',
                encoding_override=''):
        return {
            'banner_before': before,
            'banner_after': after,
            'encoding': encoding,
            'encoding_override': encoding_override,
        }

    def test_replacement_chars_stripped_after_redecode(self):
        raw_bytes = b'\xb0hello\xb1'
        text = raw_bytes.decode('ascii', errors='surrogateescape')
        server = self._server(before=text)
        result = _combine_banners(server, default_encoding='cp437')
        assert '░' in result
        assert '▒' in result
        assert '\ufffd' not in result

    def test_replacement_chars_stripped_when_no_redecode(self):
        server = self._server(before='hello\ufffdworld')
        result = _combine_banners(server, default_encoding=None)
        assert result == 'helloworld'

    def test_pure_ascii_banner_unchanged(self):
        server = self._server(before='Welcome to BBS')
        result = _combine_banners(server, default_encoding='cp437')
        assert result == 'Welcome to BBS'

    def test_encoding_override_used(self):
        raw_bytes = b'\xb0\xb1'
        text = raw_bytes.decode('ascii', errors='surrogateescape')
        server = self._server(before=text, encoding='ascii',
                              encoding_override='cp437')
        result = _combine_banners(server, default_encoding='cp437')
        assert '░' in result
        assert '▒' in result

    def test_no_redecode_when_encodings_match(self):
        server = self._server(before='test', encoding='cp437')
        result = _combine_banners(server, default_encoding='cp437')
        assert result == 'test'

    def test_combines_before_and_after(self):
        server = self._server(before='BEFORE', after='AFTER')
        result = _combine_banners(server)
        assert 'BEFORE' in result
        assert 'AFTER' in result

    def test_deduplicates_after_in_before(self):
        server = self._server(before='Welcome to BBS\r\nLogin:',
                              after='Login:')
        result = _combine_banners(server)
        assert result == 'Welcome to BBS\r\nLogin:'
