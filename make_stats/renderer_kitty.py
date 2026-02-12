"""Kitty terminal backend for the banner renderer."""

from make_stats.renderer import TerminalInstance, _HELPER_SCRIPT, _PALETTE


class KittyInstance(TerminalInstance):
    """Kitty terminal instance for rendering banners.

    Uses ``kitty --override=`` flags for all configuration.
    """

    def _required_tool(self):
        return 'kitty'

    def _build_command(self):
        cmd = [
            'kitty',
            f'--title={self._window_title}',
            f'--override=font_family={self._font_family}',
            f'--override=font_size={self._font_size}',
            f'--override=initial_window_width={self._columns}c',
            f'--override=initial_window_height={self._rows}c',
            '--override=remember_window_size=no',
            '--override=hide_window_decorations=yes',
            '--override=scrollback_lines=0',
            '--override=cursor_shape=block',
            '--override=cursor_blink_interval=0',
            '--override=confirm_os_window_close=0',
            '--override=bold_is_bright=yes',
            '--override=window_padding_width=0',
            '--override=placement_strategy=top-left',
            '--override=background=#000000',
            '--override=foreground=#aaaaaa',
        ]
        for idx, color in _PALETTE.items():
            cmd.append(f'--override=color{idx}={color}')
        cmd.extend(['--', _HELPER_SCRIPT,
                     self._data_fifo, self._ready_fifo,
                     self._window_title])
        return cmd
