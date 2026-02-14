"""Tests for MUD-specific statistics functions."""

import pytest

from make_stats.muds import _normalize_family, _strip_codebase_version


class TestNormalizeFamily:

    @pytest.mark.parametrize("raw,expected", [
        ("DikuMUD", "DikuMUD"),
        ("dikumud", "DikuMUD"),
        ("diku", "DikuMUD"),
        ("Diku/MERC", "DikuMUD"),
        ("tbaMUD", "DikuMUD"),
        ("LPMud", "LPMud"),
        ("LPMUD", "LPMud"),
        ("FluffOS", "LPMud"),
        ("TinyMUD", "TinyMUD"),
        ("MUCK", "TinyMUD"),
        ("CoffeeMUD", "CoffeeMUD"),
        ("Evennia", "Evennia"),
    ])
    def test_normalization(self, raw, expected):
        assert _normalize_family(raw) == expected


class TestStripCodebaseVersion:

    @pytest.mark.parametrize("raw,expected", [
        ("PennMUSH 1.8.8p0", "PennMUSH"),
        ("CoffeeMUD v5.11.0.3", "CoffeeMUD"),
        ("Dead Souls 3.9", "Dead Souls"),
        ("Evennia", "Evennia"),
        ("", ""),
        ("CD.06.06", "CD.06.06"),
    ])
    def test_version_stripping(self, raw, expected):
        assert _strip_codebase_version(raw) == expected
