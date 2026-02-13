"""Wezterm terminal backend for the banner renderer."""

import os
import sys

from make_stats.renderer import TerminalInstance, _HELPER_SCRIPT, _PALETTE


_CJK_FALLBACK_FONT = 'Noto Sans Mono CJK SC'


def _generate_wezterm_config(path, font_family, font_size, columns, rows,
                             east_asian_wide):
    """Write a wezterm Lua config file.

    :param path: output file path
    :param font_family: font family name
    :param font_size: font size
    :param columns: terminal width in columns
    :param rows: terminal height in rows
    :param east_asian_wide: enable treat_east_asian_ambiguous_width_as_wide
    """
    ansi = [_PALETTE[i] for i in range(8)]
    brights = [_PALETTE[i] for i in range(8, 16)]

    ansi_lua = ', '.join(f'"{c}"' for c in ansi)
    brights_lua = ', '.join(f'"{c}"' for c in brights)

    east_asian_str = 'true' if east_asian_wide else 'false'

    if east_asian_wide:
        font_lua = (f'wezterm.font_with_fallback{{"{font_family}", '
                    f'"{_CJK_FALLBACK_FONT}"}}')
    else:
        font_lua = f'wezterm.font("{font_family}")'

    lua = f"""\
local wezterm = require 'wezterm'
local config = {{}}
config.font = {font_lua}
config.font_size = {font_size}
config.initial_cols = {columns}
config.initial_rows = {rows}
config.window_decorations = "NONE"
config.enable_tab_bar = false
config.scrollback_lines = 0
config.bold_brightens_ansi_colors = "BrightOnly"
config.treat_east_asian_ambiguous_width_as_wide = {east_asian_str}
config.window_padding = {{left = 0, right = 0, top = 0, bottom = 0}}
config.hide_mouse_cursor_when_typing = true
config.default_cursor_style = "SteadyBlock"
config.colors = {{
    foreground = "#aaaaaa",
    background = "#000000",
    ansi = {{{ansi_lua}}},
    brights = {{{brights_lua}}},
}}
return config
"""
    with open(path, 'w') as f:
        f.write(lua)


class WeztermInstance(TerminalInstance):
    """Wezterm terminal instance for rendering banners.

    Generates a Lua config file in the temp directory and launches
    wezterm with ``--config-file``.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._config_path = None

    def _required_tool(self):
        return 'wezterm'

    def _build_command(self):
        self._config_path = os.path.join(self._tmpdir, 'wezterm.lua')
        _generate_wezterm_config(
            self._config_path,
            font_family=self._font_family,
            font_size=self._font_size,
            columns=self._columns,
            rows=self._rows,
            east_asian_wide=self._east_asian_wide,
        )
        cmd = [
            'wezterm',
            f'--config-file={self._config_path}',
            'start', '--no-auto-connect',
            '--', sys.executable, _HELPER_SCRIPT,
            self._data_fifo, self._ready_fifo,
            self._window_title,
        ]
        return cmd
