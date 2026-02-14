"""Tests for the terminal screenshot renderer."""

import struct
import tempfile
from unittest import mock

import pytest

from make_stats.renderer import (
    _encoding_to_font_group,
    _png_dimensions,
)


class TestEncodingToFontGroup:

    @pytest.mark.parametrize("encoding,expected", [
        ('cp437', 'ibm_vga'),
        ('cp850', 'ibm_vga'),
        ('cp866', 'ibm_vga'),
        ('koi8_r', 'ibm_vga'),
        ('unknown', 'ibm_vga'),
        ('ascii', 'ibm_vga'),
        ('utf_8', 'ibm_vga'),
        ('big5', 'ibm_vga'),
        ('amiga', 'topaz'),
        ('petscii', 'petscii'),
        ('atascii', 'atascii'),
    ])
    def test_mapping(self, encoding, expected):
        assert _encoding_to_font_group(encoding) == expected

    def test_hyphen_normalization(self):
        assert _encoding_to_font_group('cp437-art') == 'ibm_vga'

    def test_case_insensitive(self):
        assert _encoding_to_font_group('AMIGA') == 'topaz'


def _make_png_header(width, height):
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>II', width, height) + b'\x08\x02\x00\x00\x00'
    return sig + struct.pack('>I', 13) + b'IHDR' + ihdr_data


class TestPngDimensions:

    def test_valid_png(self, tmp_path):
        p = tmp_path / 'test.png'
        p.write_bytes(_make_png_header(640, 480))
        assert _png_dimensions(str(p)) == (640, 480)

    def test_not_png(self, tmp_path):
        p = tmp_path / 'not.png'
        p.write_bytes(b'GIF89a' + b'\x00' * 20)
        assert _png_dimensions(str(p)) == (0, 0)

    def test_missing_file(self, tmp_path):
        assert _png_dimensions(str(tmp_path / 'nope.png')) == (0, 0)
