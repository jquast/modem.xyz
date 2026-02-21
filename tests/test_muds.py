"""Tests for MUD-specific statistics functions."""

import io
import contextlib

import pytest

from make_stats.common import _rst_heading, _rst_escape
from make_stats.muds import _normalize_codebase


class TestNormalizeCodebase:

    @pytest.mark.parametrize("raw,expected", [
        ("DikuMUD", "DikuMUD"),
        ("dikumud", "DikuMUD"),
        ("diku", "DikuMUD"),
        ("Diku/MERC", "DikuMUD"),
        ("tbaMUD", "DikuMUD"),
        ("Merc", "DikuMUD"),
        ("SMAUG", "DikuMUD"),
        ("EmpireMUD", "DikuMUD"),
        ("LuminariMUD", "DikuMUD"),
        ("EmlenMud", "DikuMUD"),
        ("CircleMUD/Byliny", "DikuMUD"),
        ("ROM Derivative", "DikuMUD"),
        ("LPMud", "LPMud"),
        ("LPMUD", "LPMud"),
        ("FluffOS", "LPMud"),
        ("FluffOS 3.2.14", "LPMud"),
        ("Dead Souls 3.9", "LPMud"),
        ("TinyMUD", "TinyMUD"),
        ("MUCK", "TinyMUD"),
        ("ProtoMUCK", "TinyMUD"),
        ("ZetaMUCK", "TinyMUD"),
        ("PennMUSH 1.8.8p0", "TinyMUD"),
        ("LambdaMOO", "MOO"),
        ("LambdaMOO-ToastStunt", "MOO"),
        ("CoffeeMUD", "CoffeeMUD"),
        ("CoffeeMUD v5.11.0.3", "CoffeeMUD"),
        ("Custom", "Custom"),
        ("CUSTOM", "Custom"),
        ("Evennia", "Evennia"),
        ("Evennia 0.8.1", "Evennia"),
        ("", ""),
        ("CD.06.06", "CD.06.06"),
    ])
    def test_normalization(self, raw, expected):
        assert _normalize_codebase(raw) == expected


def _capture_description_rst(server, sec_char='-'):
    """Capture RST output of the description section."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        if server['has_mssp'] and server['description']:
            _rst_heading("Description", sec_char)
            print(_rst_escape(server['description']))
            print()
            for key, text in sorted(
                    server.get('descriptions_i18n', {}).items()):
                lang = key.split('-', 1)[1]
                _rst_heading(f"Description ({lang})", sec_char)
                print(_rst_escape(text))
                print()
    return buf.getvalue()


class TestMsspDescription:

    def test_full_description_not_truncated(self):
        desc = "A" * 1500
        server = {
            'has_mssp': True,
            'description': desc,
            'descriptions_i18n': {},
        }
        rst = _capture_description_rst(server)
        assert desc in rst
        assert "Description\n-----------" in rst

    def test_description_heading_present(self):
        server = {
            'has_mssp': True,
            'description': 'A test MUD.',
            'descriptions_i18n': {},
        }
        rst = _capture_description_rst(server)
        assert "Description\n-----------" in rst
        assert "A test MUD." in rst

    def test_no_description_when_empty(self):
        server = {
            'has_mssp': True,
            'description': '',
            'descriptions_i18n': {},
        }
        rst = _capture_description_rst(server)
        assert rst == ''

    def test_no_description_without_mssp(self):
        server = {
            'has_mssp': False,
            'description': 'Should not appear',
            'descriptions_i18n': {},
        }
        rst = _capture_description_rst(server)
        assert rst == ''

    def test_i18n_description(self):
        server = {
            'has_mssp': True,
            'description': 'English description.',
            'descriptions_i18n': {
                'DESCRIPTION-DE': 'Deutsche Beschreibung.',
            },
        }
        rst = _capture_description_rst(server)
        assert "Description\n-----------" in rst
        assert "English description." in rst
        assert "Description (DE)\n----------------" in rst
        assert "Deutsche Beschreibung." in rst

    def test_multiple_i18n_descriptions_sorted(self):
        server = {
            'has_mssp': True,
            'description': 'English.',
            'descriptions_i18n': {
                'DESCRIPTION-FR': 'Francais.',
                'DESCRIPTION-DE': 'Deutsch.',
            },
        }
        rst = _capture_description_rst(server)
        de_pos = rst.index('Description (DE)')
        fr_pos = rst.index('Description (FR)')
        assert de_pos < fr_pos
