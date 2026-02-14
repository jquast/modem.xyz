"""Wezterm mux-server backend for the banner renderer.

Runs a single wezterm process with multiple windows (one per font group
and column width).  Per-window font overrides are applied via
``user-var-changed`` Lua events triggered by the helper script.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

from make_stats.renderer import (
    TerminalInstance, _file_md5, _FONT_GROUPS, _HELPER_SCRIPT, _PALETTE,
)

_CJK_FALLBACK_FONT = 'Noto Sans Mono CJK SC'


def _generate_mux_config(path, font_size, rows):
    """Write a unified wezterm Lua config for the mux server.

    Includes a ``user-var-changed`` handler that applies per-window
    font overrides when the helper script sets the ``font_group``
    user variable via OSC 1337.

    :param path: output file path
    :param font_size: default font size
    :param rows: default terminal height in rows
    """
    ansi = [_PALETTE[i] for i in range(8)]
    brights = [_PALETTE[i] for i in range(8, 16)]
    ansi_lua = ', '.join(f'"{c}"' for c in ansi)
    brights_lua = ', '.join(f'"{c}"' for c in brights)

    # Build Lua table of font group definitions.
    group_entries = []
    for name, info in _FONT_GROUPS.items():
        family = info['font_family']
        cell_ratio = info.get('cell_ratio', 2.0)
        if name == 'ibm_vga':
            # IBM VGA primary with Hack fallback for Unicode coverage.
            group_entries.append(
                f'    ["{name}"] = {{font = wezterm.font_with_fallback'
                f'{{"{family}", "Hack"}}, '
                f'size = {font_size}, cell_ratio = {cell_ratio}}},')
            # CJK variant adds Noto CJK after Hack.
            group_entries.append(
                f'    ["{name}-cjk"] = {{font = wezterm.font_with_fallback'
                f'{{"{family}", "Hack", "{_CJK_FALLBACK_FONT}"}}, '
                f'size = {font_size}, cell_ratio = {cell_ratio}, cjk = true}},')
        else:
            group_entries.append(
                f'    ["{name}"] = {{font = wezterm.font("{family}"), '
                f'size = {font_size}, cell_ratio = {cell_ratio}}},')
            # CJK variant with fallback font.
            group_entries.append(
                f'    ["{name}-cjk"] = {{font = wezterm.font_with_fallback'
                f'{{"{family}", "{_CJK_FALLBACK_FONT}"}}, '
                f'size = {font_size}, cell_ratio = {cell_ratio}, cjk = true}},')
    groups_lua = '\n'.join(group_entries)

    lua = f"""\
local wezterm = require 'wezterm'
local config = {{}}

config.font = wezterm.font("Hack")
config.font_size = {font_size}
config.initial_cols = 120
config.initial_rows = {rows}
config.window_decorations = "NONE"
config.enable_tab_bar = false
config.scrollback_lines = 0
config.bold_brightens_ansi_colors = "BrightOnly"
config.treat_east_asian_ambiguous_width_as_wide = false
config.window_padding = {{left = 0, right = 0, top = 0, bottom = 0}}
config.hide_mouse_cursor_when_typing = true
config.default_cursor_style = "SteadyBlock"
config.front_end = "Software"
config.colors = {{
    foreground = "#aaaaaa",
    background = "#000000",
    ansi = {{{ansi_lua}}},
    brights = {{{brights_lua}}},
}}

local font_groups = {{
{groups_lua}
}}

wezterm.on('user-var-changed', function(window, pane, name, value)
    if name == 'font_group' then
        -- Value format: "group_name" or "group_name:cols;rows"
        local group_key, cols, rows = value:match('^([^:]+):(%d+);(%d+)$')
        if not group_key then
            group_key = value
        end
        local group = font_groups[group_key]
        if group then
            local overrides = window:get_config_overrides() or {{}}
            overrides.font = group.font
            overrides.font_size = group.size
            overrides.treat_east_asian_ambiguous_width_as_wide = group.cjk or false
            window:set_config_overrides(overrides)
            -- Resize window to target dimensions if specified.
            -- Must compute pixel size from the NEW font metrics since
            -- set_config_overrides changes cell dimensions.
            if cols and rows then
                cols = tonumber(cols)
                rows = tonumber(rows)
                -- At 96 DPI: cell_h = font_size * 96 / 72 (pt→px).
                -- cell_ratio is height/width (2.0 for 8x16, 1.0 for 8x8).
                local cell_h = math.ceil(group.size * 96.0 / 72.0)
                local ratio = group.cell_ratio or 2.0
                local cell_w = math.ceil(cell_h / ratio)
                window:set_inner_size(cols * cell_w, rows * cell_h)
            end
        end
    elseif name == 'redraw' then
        -- Force a repaint cycle.  On Xvfb the software renderer has
        -- no vsync/expose trigger, so we poke it by changing a harmless
        -- config value (cursor_blink_rate on a non-blinking cursor).
        local overrides = window:get_config_overrides() or {{}}
        overrides.cursor_blink_rate = tonumber(value) or 500
        window:set_config_overrides(overrides)
    end
end)

return config
"""
    with open(path, 'w') as f:
        f.write(lua)


class WeztermMuxServer:
    """Single wezterm process managing multiple windows.

    :param font_size: font size for all windows
    :param rows: default terminal height in rows
    :param display_env: X11 DISPLAY value (e.g. ``:99``)
    """

    def __init__(self, font_size=12, rows=60, display_env=None):
        self._font_size = font_size
        self._rows = rows
        self._display_env = display_env
        self._proc = None
        self._socket_path = None
        self._tmpdir = None

    def _cli_env(self):
        """Return environment dict for ``wezterm cli`` commands."""
        env = os.environ.copy()
        if self._display_env is not None:
            env['DISPLAY'] = self._display_env
        if self._socket_path is not None:
            env['WEZTERM_UNIX_SOCKET'] = self._socket_path
        return env

    def start(self):
        """Launch the wezterm mux server.

        Generates a unified Lua config, starts wezterm with a dummy
        initial window, and reads the Unix socket path for CLI commands.

        :raises RuntimeError: if the server fails to start
        """
        self._tmpdir = tempfile.mkdtemp(prefix='wezterm-mux-')
        config_path = os.path.join(self._tmpdir, 'wezterm.lua')
        _generate_mux_config(config_path, self._font_size, self._rows)

        sock_marker = os.path.join(self._tmpdir, 'socket_path')

        env = os.environ.copy()
        if self._display_env is not None:
            env['DISPLAY'] = self._display_env

        stderr_log = os.path.join(self._tmpdir, 'server.log')
        self._stderr_file = open(stderr_log, 'w')

        self._proc = subprocess.Popen(
            ['wezterm', f'--config-file={config_path}',
             'start', '--always-new-process', '--no-auto-connect',
             '--', 'sh', '-c',
             f'printf "%s" "$WEZTERM_UNIX_SOCKET" > {sock_marker}; '
             f'exec sleep 86400'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_file,
            env=env,
        )

        # Wait for socket path to be written.
        for _ in range(100):
            if os.path.exists(sock_marker):
                with open(sock_marker, 'r') as f:
                    path = f.read().strip()
                if path:
                    self._socket_path = path
                    break
            if self._proc.poll() is not None:
                # Read stderr for diagnostics.
                self._stderr_file.close()
                try:
                    with open(stderr_log, 'r') as f:
                        err = f.read().strip()
                except OSError:
                    err = ''
                detail = f": {err}" if err else ""
                raise RuntimeError(
                    f"wezterm mux server exited with code "
                    f"{self._proc.returncode}{detail}")
            time.sleep(0.1)
        else:
            self.stop()
            raise RuntimeError("timed out waiting for wezterm socket path")

        print(f"  wezterm mux server started (socket {self._socket_path})",
              file=sys.stderr)

    def spawn_window(self, helper_args):
        """Spawn a new window in the mux server.

        :param helper_args: argument list for the helper script
        :returns: pane ID string
        :raises RuntimeError: if spawn fails
        """
        cmd = ['wezterm', 'cli', 'spawn', '--new-window', '--',
               sys.executable, _HELPER_SCRIPT] + list(helper_args)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            env=self._cli_env(),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"wezterm cli spawn failed: "
                f"{result.stderr.strip()}")
        return result.stdout.strip()

    def activate_pane(self, pane_id):
        """Activate a pane's window to trigger a repaint.

        On Xvfb, wezterm's software renderer may only repaint the
        active window.  Calling this before a screenshot ensures the
        target window has up-to-date pixel content.

        :param pane_id: pane ID string from :meth:`spawn_window`
        """
        try:
            subprocess.run(
                ['wezterm', 'cli', 'activate-pane',
                 '--pane-id', str(pane_id)],
                capture_output=True, timeout=5,
                env=self._cli_env(),
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    def kill_pane(self, pane_id):
        """Kill a specific pane.

        :param pane_id: pane ID string from :meth:`spawn_window`
        """
        try:
            subprocess.run(
                ['wezterm', 'cli', 'kill-pane', '--pane-id', str(pane_id)],
                capture_output=True, timeout=5,
                env=self._cli_env(),
            )
        except (subprocess.TimeoutExpired, OSError):
            pass

    @property
    def alive(self):
        """Return True if the mux server process is running."""
        return self._proc is not None and self._proc.poll() is None

    def stop(self):
        """Shut down the mux server and clean up."""
        if hasattr(self, '_stderr_file') and self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
        print("  wezterm mux server stopped", file=sys.stderr)


class WeztermMuxInstance(TerminalInstance):
    """A window within a :class:`WeztermMuxServer`.

    Instead of launching its own wezterm process, spawns a pane in
    the shared mux server.  The helper script sets a user variable
    to trigger per-window font overrides in the Lua config.

    :param server: the shared :class:`WeztermMuxServer`
    :param font_group_key: font group key for the Lua user-var override
        (e.g. ``'hack'``, ``'ibm_vga-cjk'``)
    :param font_family: font family name (for display only)
    :param group_name: display name for logging
    :param columns: terminal width in columns
    :param rows: terminal height in rows
    :param font_size: font size (for display only)
    :param east_asian_wide: whether CJK wide mode is active
    :param display_env: X11 DISPLAY value
    """

    def __init__(self, server, font_group_key, **kwargs):
        super().__init__(**kwargs)
        self._server = server
        self._font_group_key = font_group_key
        self._pane_id = None

    def _required_tool(self):
        return 'wezterm'

    def _build_command(self):
        # Not used — start() spawns via the mux server.
        return []

    def start(self):
        """Spawn a new window in the mux server.

        Creates FIFOs, spawns the helper via ``wezterm cli spawn``,
        and locates the X11 window by title.

        :raises RuntimeError: if the window cannot be created
        """
        self._tmpdir = tempfile.mkdtemp(
            prefix=f'render-{self._group_name}-')
        self._data_fifo = os.path.join(self._tmpdir, 'data.fifo')
        self._ready_fifo = os.path.join(self._tmpdir, 'ready.fifo')
        os.mkfifo(self._data_fifo)
        os.mkfifo(self._ready_fifo)

        helper_args = [
            self._data_fifo, self._ready_fifo, self._window_title,
            self._font_group_key, str(self._columns), str(self._rows),
        ]

        try:
            self._pane_id = self._server.spawn_window(helper_args)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(
                f"Failed to spawn window for {self._group_name}: {exc}"
            ) from exc

        # Find the X11 window by title.
        try:
            result = subprocess.run(
                ['xdotool', 'search', '--sync',
                 '--name', f'^{self._window_title}$'],
                capture_output=True, text=True, timeout=10,
                env=self._subprocess_env(),
            )
        except subprocess.TimeoutExpired as exc:
            self.stop()
            raise RuntimeError(
                f"Timed out waiting for window "
                f"({self._window_title})") from exc

        window_ids = result.stdout.strip().split('\n')
        if not window_ids or not window_ids[0]:
            self.stop()
            raise RuntimeError(
                f"Could not find window ({self._window_title})")
        self._window_id = window_ids[0]

        if self._check_dupes:
            # Baseline screenshot for staleness detection.
            time.sleep(0.2)
            baseline_path = os.path.join(self._tmpdir, 'baseline.png')
            self._xwd_capture(baseline_path)
            if (os.path.isfile(baseline_path)
                    and os.path.getsize(baseline_path) > 0):
                self._last_capture_md5 = _file_md5(baseline_path)
            try:
                os.unlink(baseline_path)
            except OSError:
                pass

        print(f"  wezterm [{self._group_name}] started: "
              f"window {self._window_id}, font '{self._font_family}'",
              file=sys.stderr)

    def stop(self):
        """Shut down this window and clean up FIFOs."""
        if self._pane_id is not None:
            # Signal helper to exit via empty FIFO payload.
            try:
                fd = os.open(self._data_fifo, os.O_WRONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass
            time.sleep(0.1)
            self._server.kill_pane(self._pane_id)
            self._pane_id = None

        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _activate(self):
        """Activate this pane and raise its X11 window."""
        if self._pane_id is not None:
            self._server.activate_pane(self._pane_id)
        super()._activate()

    @property
    def alive(self):
        """Return True if this window's pane is believed to be running."""
        return self._pane_id is not None and self._server.alive
