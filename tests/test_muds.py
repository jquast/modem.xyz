"""Tests for MUD-specific statistics functions."""

import pytest

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
