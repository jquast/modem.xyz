"""Terminal screenshot renderer for ANSI banners.

Launches real terminal instances (one per font group) and captures
screenshots via ``xdotool`` + ImageMagick ``import``.  Communication
uses named pipes (FIFOs) with bidirectional signaling: a data pipe
sends banner text to the helper script, and a ready pipe signals back
when painting is complete.

Requires: wezterm, xdotool, xwd, ImageMagick (convert), X11 DISPLAY.
"""

import abc
import hashlib
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import warnings

_HELPER_SCRIPT = os.path.join(os.path.dirname(__file__), 'terminal_helper.py')

# CGA/VGA 16-color palette matching ansilove defaults.
_PALETTE = {
    0: '#000000', 1: '#aa0000', 2: '#00aa00', 3: '#aa5500',
    4: '#0000aa', 5: '#aa00aa', 6: '#00aaaa', 7: '#aaaaaa',
    8: '#555555', 9: '#ff5555', 10: '#55ff55', 11: '#ffff55',
    12: '#5555ff', 13: '#ff55ff', 14: '#55ffff', 15: '#ffffff',
}

# Font groups: each maps a font family to the set of encodings it handles.
_FONT_GROUPS = {
    'ibm_vga': {
        'font_family': 'Px IBM VGA8',
        'cell_ratio': 2.0,  # 8x16 native bitmap
        'native_height': 16,
        'encodings': frozenset({
            'cp437', 'cp437_art', 'cp437-art',
            'cp737', 'cp775', 'cp850', 'cp852', 'cp855',
            'cp857', 'cp860', 'cp861', 'cp862', 'cp863',
            'cp865', 'cp866', 'cp869', 'koi8_r', 'unknown',
            'ascii', 'latin_1', 'iso_8859_1', 'iso_8859_1:1987',
            'iso_8859_2', 'utf_8', 'big5', 'gbk', 'shift_jis', 'euc_kr',
        }),
    },
    'topaz': {
        'font_family': 'Topaz a600a1200a400',
        'cell_ratio': 2.0,  # 8x16 native bitmap
        'native_height': 16,
        'encodings': frozenset({'amiga', 'topaz'}),
    },
    'petscii': {
        'font_family': 'Bescii Mono',
        'cell_ratio': 1.0,  # 8x8 native bitmap
        'native_height': 8,
        'encodings': frozenset({'petscii'}),
        'aspect_ratio': 1.2,  # C64 320x200 on 4:3 CRT (6:5)
        'columns': 40,
    },
    'atascii': {
        'font_family': 'EightBit Atari',
        'cell_ratio': 1.0,  # 8x8 native bitmap
        'native_height': 8,
        'encodings': frozenset({'atarist', 'atascii'}),
        'aspect_ratio': 1.25,  # Atari 320x192 on 4:3 CRT (5:4)
        'columns': 40,
    },
}

_EAST_ASIAN_ENCODINGS = frozenset({
    'big5', 'gbk', 'shift_jis', 'euc_kr', 'euc_jp', 'gb2312',
})


def _encoding_to_font_group(encoding):
    """Map a server encoding to its font group name.

    :param encoding: encoding string from scanner or server list
    :returns: font group key from ``_FONT_GROUPS``
    """
    normalized = encoding.lower().replace('-', '_')
    for group_name, group_info in _FONT_GROUPS.items():
        if normalized in group_info['encodings']:
            return group_name
    return 'ibm_vga'


def _is_east_asian_encoding(group_name):
    """Check if a font group handles east Asian encodings.

    :param group_name: font group key from ``_FONT_GROUPS``
    :returns: True if the group includes any CJK encodings
    """
    group_info = _FONT_GROUPS.get(group_name, {})
    return bool(group_info.get('encodings', frozenset()) & _EAST_ASIAN_ENCODINGS)


def _png_dimensions(path):
    """Read pixel dimensions from a PNG file header.

    :param path: path to a PNG file
    :returns: ``(width, height)`` tuple, or ``(0, 0)`` on failure
    """
    try:
        with open(path, 'rb') as fh:
            header = fh.read(24)
        if len(header) >= 24 and header[:8] == b'\x89PNG\r\n\x1a\n':
            w, h = struct.unpack('>II', header[16:24])
            return w, h
    except OSError:
        pass
    return 0, 0


def _file_md5(path):
    """Compute MD5 hex digest of a file's contents.

    :param path: path to a file
    :returns: hex digest string
    """
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


class _FifoTimeout(Exception):
    """Raised when a FIFO operation exceeds its timeout."""


def _alarm_handler(signum, frame):
    raise _FifoTimeout("FIFO operation timed out")


class TerminalInstance(abc.ABC):
    """Abstract base for a terminal process that renders banners.

    Subclasses implement :meth:`_build_command` to produce the
    terminal-specific launch command.  All FIFO communication,
    xdotool window finding, and ImageMagick screenshot logic lives
    in this base class.

    :param font_family: terminal font family config value
    :param group_name: identifier used for window title and FIFO naming
    :param columns: terminal width in columns
    :param rows: terminal height in rows
    :param font_size: font size config value
    :param east_asian_wide: enable ambiguous-width-as-wide for CJK
    """

    def __init__(self, font_family, group_name, columns=80, rows=70,
                 font_size=12, east_asian_wide=False, display_env=None,
                 check_dupes=False):
        self._font_family = font_family
        self._group_name = group_name
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._east_asian_wide = east_asian_wide
        self._display_env = display_env
        self._check_dupes = check_dupes
        self._window_title = f'render-{os.getpid()}-{group_name}'
        self._proc = None
        self._window_id = None
        self._tmpdir = None
        self._data_fifo = None
        self._ready_fifo = None
        self._stderr_file = None
        self._last_capture_md5 = None
        self._last_capture_content_blank = False

    @abc.abstractmethod
    def _build_command(self):
        """Return the full command list to launch the terminal.

        :returns: list of strings suitable for ``subprocess.Popen``
        """

    @abc.abstractmethod
    def _required_tool(self):
        """Return the executable name to check in PATH.

        :returns: string like ``'kitty'`` or ``'wezterm'``
        """

    def _subprocess_env(self):
        """Return environment dict with DISPLAY override if set."""
        if self._display_env is None:
            return None
        env = os.environ.copy()
        env['DISPLAY'] = self._display_env
        return env

    def start(self):
        """Launch the terminal process and find its X11 window ID.

        Creates a temporary directory with two named pipes, launches
        the terminal running the helper script, and locates the window
        via ``xdotool search --sync --name``.

        :raises RuntimeError: if the terminal fails to start or window
            not found
        """
        self._tmpdir = tempfile.mkdtemp(
            prefix=f'render-{self._group_name}-')
        self._data_fifo = os.path.join(self._tmpdir, 'data.fifo')
        self._ready_fifo = os.path.join(self._tmpdir, 'ready.fifo')
        os.mkfifo(self._data_fifo)
        os.mkfifo(self._ready_fifo)

        cmd = self._build_command()
        tool = self._required_tool()

        terminal_log = os.path.join(self._tmpdir, 'terminal.log')
        self._stderr_file = open(terminal_log, 'w')

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self._stderr_file,
            env=self._subprocess_env(),
        )

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
                f"Timed out waiting for {tool} window "
                f"({self._window_title})") from exc

        window_ids = result.stdout.strip().split('\n')
        if not window_ids or not window_ids[0]:
            self.stop()
            raise RuntimeError(
                f"Could not find {tool} window ({self._window_title})")
        self._window_id = window_ids[0]

        if self._check_dupes:
            # Capture a baseline screenshot of the blank terminal so the
            # first real render can detect staleness via MD5 comparison.
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

        print(f"  {tool} [{self._group_name}] started: "
              f"window {self._window_id}, font '{self._font_family}'",
              file=sys.stderr)

    def stop(self):
        """Shut down the terminal process and clean up FIFOs.

        Sends an empty payload to trigger the helper's exit condition,
        then waits for the process to terminate.  Falls back to SIGTERM
        and SIGKILL if needed.
        """
        if self._stderr_file is not None:
            try:
                self._stderr_file.close()
            except OSError:
                pass
            self._stderr_file = None

        if self._proc is not None and self._proc.poll() is None:
            try:
                fd = os.open(self._data_fifo, os.O_WRONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass

            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()

        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    @property
    def alive(self):
        """Return True if the terminal process is running."""
        return self._proc is not None and self._proc.poll() is None

    def _print_helper_log_tail(self, lines=10):
        """Print last few lines of helper.log for diagnostics."""
        if self._tmpdir is None:
            return
        log_path = os.path.join(self._tmpdir, 'helper.log')
        try:
            with open(log_path, 'r') as f:
                all_lines = f.readlines()
            tail = all_lines[-lines:]
            if tail:
                print(f"  helper.log tail:", file=sys.stderr)
                for line in tail:
                    print(f"    {line.rstrip()}", file=sys.stderr)
        except OSError:
            pass

    def _xwd_capture(self, output_path):
        """Capture a screenshot using ``xwd`` + ``convert``.

        Uses plain ``XGetImage`` (no SHM), avoiding the ``EAGAIN``
        failures that ``import``'s ``XShmGetImage`` triggers.

        :param output_path: path to write the output PNG
        :returns: True if the PNG was created successfully
        """
        xwd_path = output_path + '.xwd'
        try:
            result = subprocess.run(
                ['xwd', '-id', self._window_id, '-silent', '-out', xwd_path],
                capture_output=True, timeout=10,
                env=self._subprocess_env(),
            )
            if result.returncode != 0:
                print(f"  xwd failed for {output_path}: "
                      f"{result.stderr.decode(errors='replace').strip()}",
                      file=sys.stderr)
                return False
        except subprocess.TimeoutExpired:
            print(f"  xwd timed out for {output_path}", file=sys.stderr)
            return False

        try:
            result = subprocess.run(
                ['convert', xwd_path, output_path],
                capture_output=True, timeout=10,
            )
            if result.returncode != 0:
                print(f"  convert xwd→png failed for {output_path}: "
                      f"{result.stderr.decode(errors='replace').strip()}",
                      file=sys.stderr)
                return False
        except subprocess.TimeoutExpired:
            print(f"  convert xwd→png timed out for {output_path}",
                  file=sys.stderr)
            return False
        finally:
            try:
                os.unlink(xwd_path)
            except OSError:
                pass

        return True

    def _activate(self):
        """Raise the terminal window to the top of the X11 stacking order.

        On Xvfb without a window manager, ``XGetImage`` reads from the
        screen framebuffer so obscured windows return wrong pixels.
        ``XRaiseWindow`` via ``xdotool windowraise`` brings the target
        window to the top before each screenshot.

        Overridden by mux-based subclasses to also activate the pane.
        """
        if self._window_id is not None:
            try:
                subprocess.run(
                    ['xdotool', 'windowraise', self._window_id],
                    capture_output=True, timeout=5,
                    env=self._subprocess_env(),
                )
            except (subprocess.TimeoutExpired, OSError):
                pass

    def _screenshot_and_crop(self, output_path):
        """Take a screenshot and crop to content bounds.

        :param output_path: path to write the output PNG
        :returns: ``(success, raw_width, raw_height, raw_md5)`` — raw
            dimensions and MD5 are from the uncropped screenshot, or
            ``(0, 0, None)`` on failure
        """
        if not self._xwd_capture(output_path):
            return False, 0, 0, None

        raw_w, raw_h = _png_dimensions(output_path)
        raw_md5 = _file_md5(output_path) if self._check_dupes else None

        # Crop to content bounds on top, right, and bottom (left untouched).
        try:
            result = subprocess.run(
                ['convert', output_path, '-fuzz', '1%', '-trim',
                 '-format', '%X %Y %w %h', 'info:'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                x_offset = int(parts[0])
                y_offset = int(parts[1])
                trim_w = int(parts[2])
                trim_h = int(parts[3])
                pad_top = 1
                pad_bottom = 3
                pad_right = 3
                crop_y = max(0, y_offset - pad_top)
                crop_w = x_offset + trim_w + pad_right
                crop_h = y_offset + trim_h + pad_bottom - crop_y
                subprocess.run(
                    ['convert', output_path,
                     '-crop', f'{crop_w}x{crop_h}+0+{crop_y}', '+repage',
                     output_path],
                    capture_output=True, timeout=10,
                )
        except (subprocess.TimeoutExpired, ValueError, IndexError):
            pass  # cropping is optional, keep original image

        return True, raw_w, raw_h, raw_md5

    def capture(self, text, output_path):
        """Render banner text and capture a screenshot.

        Writes the banner to the data FIFO, waits for the helper to
        signal readiness on the ready FIFO, raises the window to front,
        then captures via ImageMagick ``import`` and trims with ``convert``.

        :param text: UTF-8 banner text with ANSI escape sequences
        :param output_path: path to write the output PNG
        :returns: True if PNG was successfully created
        """
        if not self.alive:
            return False

        tool = self._required_tool()

        # Write banner text to data FIFO
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        try:
            signal.alarm(5)
            fd = os.open(self._data_fifo, os.O_WRONLY)
            try:
                os.write(fd, text.encode('utf-8', errors='surrogateescape'))
            finally:
                os.close(fd)
            signal.alarm(0)
        except (_FifoTimeout, OSError) as exc:
            signal.alarm(0)
            print(f"  {tool} [{self._group_name}] data write "
                  f"failed: {exc}", file=sys.stderr)
            return False
        finally:
            signal.signal(signal.SIGALRM, old_handler)

        # Wait for helper to confirm render-complete (DSR flush).
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        try:
            signal.alarm(30)
            with open(self._ready_fifo, 'r') as f:
                status = f.readline().strip()
            signal.alarm(0)
        except (_FifoTimeout, OSError) as exc:
            signal.alarm(0)
            print(f"  {tool} [{self._group_name}] ready signal "
                  f"failed: {exc}", file=sys.stderr)
            return False
        finally:
            signal.signal(signal.SIGALRM, old_handler)

        if status.startswith('ok'):
            pass  # proceed to screenshot
        elif status.startswith('fail'):
            print(f"  {tool} [{self._group_name}] helper "
                  f"reported: {status}", file=sys.stderr)
            self._print_helper_log_tail()
            return False
        else:
            print(f"  {tool} [{self._group_name}] unexpected "
                  f"status: {status!r}", file=sys.stderr)
            self._print_helper_log_tail()
            return False

        self._activate()
        time.sleep(0.20)

        self._last_capture_content_blank = False
        ok, raw_w, raw_h, raw_md5 = self._screenshot_and_crop(output_path)
        if not ok:
            return False

        # Retry if the RAW screenshot is pixel-identical to the last
        # capture on this instance.  We compare the uncropped image
        # because the fuzz-based crop can produce slightly different
        # boundaries on identical content, defeating MD5 comparison.
        if self._check_dupes:
            if self._last_capture_md5 is not None and raw_md5 is not None:
                if raw_md5 == self._last_capture_md5:
                    retry_delays = (0.15, 0.30, 0.50, 0.75, 1.00)
                    for delay in retry_delays:
                        time.sleep(delay)
                        self._activate()
                        ok, _, _, raw_md5 = self._screenshot_and_crop(
                            output_path)
                        if not ok:
                            return False
                        if raw_md5 != self._last_capture_md5:
                            break
                    else:
                        # All retries exhausted — terminal is stuck.
                        return False

        w, h = _png_dimensions(output_path)
        if 0 < w < 20 and 0 < h < 20:
            if raw_w >= 100 and raw_h >= 100:
                # Terminal captured fine, content was just too sparse to
                # produce a meaningful banner after crop.  Not poison.
                self._last_capture_content_blank = True
                try:
                    os.unlink(output_path)
                except OSError:
                    pass
                return False
            print(f"  render too small ({w}x{h}px), likely poison escape: "
                  f"{output_path}", file=sys.stderr)
            return False

        if (not os.path.isfile(output_path)
                or os.path.getsize(output_path) == 0):
            print(f"  {tool} produced empty output: {output_path}",
                  file=sys.stderr)
            return False

        if self._check_dupes:
            self._last_capture_md5 = raw_md5

        return True


def _apply_crt_effects(path, group_name, columns, font_size):
    """Apply CRT phosphor bloom and scanline effects.

    The input image (1x from ``font_size=12``) is upscaled 2x via
    nearest-neighbor, then bloom and scanlines are applied at the
    final 2x resolution.

    Scanline frequency is derived from the font's native pixel height
    so that each bitmap row gets one scanline, matching the physical
    CRT raster.

    :param path: path to the PNG file (modified in place)
    :param group_name: font group key from ``_FONT_GROUPS``
    :param columns: number of terminal columns used for this capture
    :param font_size: font point size used for rendering (determines scale)
    """
    from PIL import Image, ImageDraw
    import pixelgreat as pg

    img = Image.open(path)
    orig_mode = img.mode
    if orig_mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')

    # --- 2x upscale from 1x to 2x (nearest-neighbor to keep sharp pixels) ---
    img = img.resize((img.width * 2, img.height * 2), Image.NEAREST)

    # --- Bloom at 2x ---
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        result = pg.pixelgreat(
            image=img,
            pixel_size=20,
            output_scale=1,
            bloom_strength=0.67,
            bloom_size=0.5,
            scanline_strength=0,
            grid_strength=0,
            blur=0,
            washout=0,
            pixelate=False,
            rounding=0,
        )

    # --- Scanlines at 2x ---
    # Period is computed from font metrics, not image dimensions (the
    # image is cropped to content so height/rows would be wrong).
    # At 96 DPI, font_size pt = font_size*96/72 px cell height at 1x.
    # The 1x input is upscaled 2x, so each native pixel row occupies
    # font_size*8/(3*native_height) 2x-pixels.
    group_info = _FONT_GROUPS.get(group_name, {})
    native_height = group_info.get('native_height', 16)
    period = font_size * 8.0 / (3.0 * native_height)

    overlay = Image.new('RGBA', result.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    w = result.width - 1
    total_scanlines = int(result.height / period) + 1
    # Dark band must be narrower than the period so bright gaps remain.
    # Target ~40% of the period as the full band width (flat center +
    # soft edges), leaving ~60% bright.
    band_half = period * 0.20
    flat_half = max(0, round(band_half * 0.5))
    edge = max(0, round(band_half * 0.5))
    # Reduced alpha since there is no LANCZOS downscale to soften the
    # scanline bands — they render at final resolution.
    peak_alpha = min(255, int(50 + 40 * (8.0 / max(period, 1))))
    for i in range(total_scanlines):
        cy = round(i * period)
        for offset in range(-flat_half - edge, flat_half + edge + 1):
            y = cy + offset
            if 0 <= y < result.height:
                d = abs(offset)
                if d <= flat_half:
                    alpha = peak_alpha
                elif edge > 0:
                    t = (d - flat_half) / (edge + 1)
                    alpha = int(peak_alpha * (1.0 - t))
                else:
                    alpha = 0
                if alpha > 0:
                    draw.line([(0, y), (w, y)], fill=(0, 0, 0, alpha))
    result = Image.alpha_composite(result.convert('RGBA'), overlay)

    result = result.convert('RGB')

    if orig_mode == 'L':
        result = result.convert('L')
    elif orig_mode == 'LA':
        result = result.convert('LA')
    result.save(path)


class RendererPool:
    """Pool of terminal instances, one per font group and column width.

    Instances are created lazily on first use for each font group.
    Acts as a context manager: on enter, launches a virtual X11 display
    via Xvfb so terminal windows are invisible; on exit, shuts down all
    instances and the virtual display.

    :param columns: default terminal width in columns
    :param rows: terminal height in rows
    :param font_size: font size for all instances
    :param crt_effects: apply CRT bloom and scanlines to output PNGs
    """

    def __init__(self, columns=80, rows=60, font_size=12,
                 crt_effects=True, check_dupes=False):
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._crt_effects = crt_effects
        self._check_dupes = check_dupes
        self._instances = {}
        self._xvfb_proc = None
        self._display_env = None
        self._mux_server = None
        self._next_window_x = 0

    def _start_xvfb(self):
        """Launch a virtual X11 display via Xvfb.

        Finds a free display number starting at :99 and launches Xvfb
        with a screen large enough for terminal rendering.
        """
        if shutil.which('Xvfb') is None:
            raise RuntimeError("Xvfb not found; install xvfb to render banners")
        for display_num in range(99, 200):
            display = f':{display_num}'
            lock_path = f'/tmp/.X{display_num}-lock'
            if os.path.exists(lock_path):
                continue
            self._xvfb_proc = subprocess.Popen(
                ['Xvfb', display, '-screen', '0', '32000x16384x24'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.3)
            if self._xvfb_proc.poll() is not None:
                self._xvfb_proc = None
                continue
            self._display_env = display
            print(f"  Xvfb started on {display}", file=sys.stderr)
            return
        raise RuntimeError(
            "Could not find free display for Xvfb (tried :99 through :199); "
            "check for stale /tmp/.X*-lock files"
        )

    def __enter__(self):
        self._start_xvfb()
        self._start_mux_server()
        return self

    def _start_mux_server(self):
        """Launch the shared wezterm mux server."""
        from make_stats.renderer_wezterm import WeztermMuxServer
        self._mux_server = WeztermMuxServer(
            font_size=self._font_size,
            rows=self._rows,
            display_env=self._display_env,
        )
        try:
            self._mux_server.start()
        except RuntimeError as exc:
            print(f"  mux server failed to start: {exc}", file=sys.stderr)
            self._mux_server = None

    def __exit__(self, *exc):
        for name, instance in self._instances.items():
            try:
                instance.stop()
            except Exception as e:
                print(f"  Warning: failed to stop renderer "
                      f"[{name}]: {e}", file=sys.stderr)
        self._instances.clear()
        if self._mux_server is not None:
            self._mux_server.stop()
            self._mux_server = None
        if self._xvfb_proc is not None:
            self._xvfb_proc.terminate()
            try:
                self._xvfb_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._xvfb_proc.kill()
                self._xvfb_proc.wait()
            self._xvfb_proc = None
            print("  Xvfb stopped", file=sys.stderr)

    def _determine_columns(self, group_name):
        return _FONT_GROUPS.get(group_name, {}).get('columns', self._columns)

    def _make_instance(self, group_name, effective_cols, effective_rows,
                       east_asian_wide=False):
        """Create a WeztermMuxInstance for the given font group.

        :param group_name: font group key from ``_FONT_GROUPS``
        :param effective_cols: resolved column width
        :param effective_rows: resolved row height
        :param east_asian_wide: treat ambiguous-width chars as 2 cells
        :returns: a WeztermMuxInstance, or None if mux server is unavailable
        """
        if self._mux_server is None:
            return None
        from make_stats.renderer_wezterm import WeztermMuxInstance
        group_info = _FONT_GROUPS[group_name]
        display = (f"{group_name}-{effective_cols}"
                   if effective_cols != 80 else group_name)
        if effective_rows != self._rows:
            display += f'-{effective_rows}r'
        font_group_key = group_name
        if east_asian_wide:
            display += '-cjk'
            font_group_key += '-cjk'
        return WeztermMuxInstance(
            server=self._mux_server,
            font_group_key=font_group_key,
            font_family=group_info['font_family'],
            group_name=display,
            columns=effective_cols,
            rows=effective_rows,
            font_size=self._font_size,
            east_asian_wide=east_asian_wide,
            display_env=self._display_env,
            check_dupes=self._check_dupes,
        )

    def _get_instance(self, group_name, columns=None, rows=None,
                      east_asian_wide=False):
        """Get or lazily create an instance for the given group.

        :param group_name: font group key from ``_FONT_GROUPS``
        :param columns: optional column width override
        :param rows: optional row height override
        :param east_asian_wide: treat ambiguous-width chars as 2 cells
        :returns: TerminalInstance or None on failure
        """
        effective_cols = (columns if columns is not None
                          else self._determine_columns(group_name))
        effective_rows = rows if rows is not None else self._rows
        instance_key = (group_name, effective_cols, effective_rows,
                        east_asian_wide)

        if instance_key in self._instances:
            inst = self._instances[instance_key]
            if inst.alive:
                return inst
            print(f"  renderer [{group_name}@{effective_cols}c] died, "
                  f"restarting...", file=sys.stderr)
            try:
                inst.stop()
            except Exception:
                pass

        group_info = _FONT_GROUPS.get(group_name)
        if group_info is None:
            return None

        inst = self._make_instance(group_name, effective_cols, effective_rows,
                                   east_asian_wide)
        try:
            inst.start()
        except RuntimeError as exc:
            print(f"  renderer [{group_name}] failed to start: {exc}",
                  file=sys.stderr)
            return None

        # Position window at a unique x-offset so windows never overlap
        # on Xvfb.  XGetImage reads from the framebuffer, so obscured
        # windows return wrong pixels.
        if inst._window_id is not None:
            try:
                subprocess.run(
                    ['xdotool', 'windowmove', inst._window_id,
                     str(self._next_window_x), '0'],
                    capture_output=True, timeout=5,
                    env=inst._subprocess_env(),
                )
                self._next_window_x += 2000
            except (subprocess.TimeoutExpired, OSError):
                pass

        self._instances[instance_key] = inst
        return inst

    def _restart_mux_server(self):
        """Restart the entire mux server and all instances.

        Used as a last resort when individual instance relaunches fail,
        recovering from corrupted wezterm or X11 state.
        """
        for name, instance in self._instances.items():
            try:
                instance.stop()
            except Exception:
                pass
        self._instances.clear()
        self._next_window_x = 0
        if self._mux_server is not None:
            self._mux_server.stop()
            self._mux_server = None
        time.sleep(0.5)
        self._start_mux_server()

    def capture(self, text, output_path, encoding='cp437', columns=None,
                rows=None):
        """Route a banner to the appropriate terminal instance.

        :param text: preprocessed banner text
        :param output_path: path to write the output PNG
        :param encoding: server encoding for font group selection
        :param columns: optional column width override
        :param rows: optional row height override
        :returns: instance display name on success, None on failure
        """
        group_name = _encoding_to_font_group(encoding)
        east_asian = encoding.lower().replace('-', '_') in _EAST_ASIAN_ENCODINGS
        instance = self._get_instance(
            group_name, columns=columns, rows=rows,
            east_asian_wide=east_asian)
        if instance is None:
            return None
        if not instance.capture(text, output_path):
            # If content was just blank/sparse (not a terminal failure),
            # skip the expensive relaunch — the terminal is fine.
            if getattr(instance, '_last_capture_content_blank', False):
                return None
            # Poison escape may have corrupted terminal state.
            # Relaunch instance and retry once.
            if instance.alive:
                print(f"  renderer [{group_name}] capture failed, "
                      f"relaunching for retry...", file=sys.stderr)
                try:
                    instance.stop()
                except Exception:
                    pass
                time.sleep(0.3)  # let X11 clean up old window
                instance = self._get_instance(
                    group_name, columns=columns, rows=rows,
                    east_asian_wide=east_asian)
                if instance is None or not instance.capture(text, output_path):
                    # Nuclear option: restart entire mux server.
                    print(f"  renderer [{group_name}] retry also failed, "
                          f"restarting mux server...", file=sys.stderr)
                    self._restart_mux_server()
                    instance = self._get_instance(
                        group_name, columns=columns, rows=rows,
                        east_asian_wide=east_asian)
                    if instance is not None:
                        if not instance.capture(text, output_path):
                            return None
                    else:
                        return None
            else:
                return None

        # Correct for non-square pixel aspect ratio (CRT platforms).
        group_info = _FONT_GROUPS.get(group_name, {})
        aspect = group_info.get('aspect_ratio')
        if aspect and os.path.isfile(output_path):
            pct = int(aspect * 100)
            subprocess.run(
                ['convert', output_path,
                 '-filter', 'point', '-resize', f'100%x{pct}%',
                 output_path],
                capture_output=True, timeout=10,
            )

        if self._crt_effects and os.path.isfile(output_path):
            effective_cols = columns if columns is not None else (
                group_info.get('columns', self._columns))
            _apply_crt_effects(output_path, group_name, effective_cols,
                               self._font_size)

        return instance._group_name

    @staticmethod
    def available():
        """Check if terminal screenshot rendering is possible.

        :returns: True if DISPLAY is set or Xvfb is available, and
            wezterm plus xdotool and xwd are found in PATH
        """
        has_display = (os.environ.get('DISPLAY')
                       or shutil.which('Xvfb') is not None)
        if not has_display:
            return False
        for tool in ('xdotool', 'xwd'):
            if shutil.which(tool) is None:
                return False
        return shutil.which('wezterm') is not None
