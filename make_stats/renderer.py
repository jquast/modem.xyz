"""Terminal screenshot renderer for ANSI banners.

Launches real terminal instances (one per font group) and captures
screenshots via ``xdotool`` + ImageMagick ``import``.  Communication
uses named pipes (FIFOs) with bidirectional signaling: a data pipe
sends banner text to the helper script, and a ready pipe signals back
when painting is complete.

Supports kitty and wezterm backends, selected automatically or via
the ``MODEM_RENDERER`` environment variable.

Requires: kitty or wezterm, xdotool, ImageMagick (import + convert),
X11 DISPLAY.
"""

import abc
import os
import shutil
import signal
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
        'encodings': frozenset({
            'cp437', 'cp437_art', 'cp437-art',
            'cp737', 'cp775', 'cp850', 'cp852', 'cp855',
            'cp857', 'cp860', 'cp861', 'cp862', 'cp863',
            'cp865', 'cp866', 'cp869', 'koi8_r', 'unknown',
        }),
    },
    'topaz': {
        'font_family': 'Topaz a600a1200a400',
        'cell_ratio': 2.0,  # 8x16 native bitmap
        'encodings': frozenset({'amiga', 'topaz'}),
    },
    'petscii': {
        'font_family': 'Bescii Mono',
        'cell_ratio': 1.0,  # 8x8 native bitmap
        'encodings': frozenset({'petscii'}),
        'aspect_ratio': 1.2,  # C64 320x200 on 4:3 CRT (6:5)
        'columns': 40,
    },
    'atascii': {
        'font_family': 'EightBit Atari',
        'cell_ratio': 1.0,  # 8x8 native bitmap
        'encodings': frozenset({'atarist', 'atascii'}),
        'aspect_ratio': 1.25,  # Atari 320x192 on 4:3 CRT (5:4)
        'columns': 40,
    },
    'hack': {
        'font_family': 'Hack',
        'cell_ratio': 2.0,  # approximate for Hack at terminal defaults
        'encodings': frozenset({
            'ascii', 'latin_1', 'iso_8859_1', 'iso_8859_1:1987',
            'iso_8859_2', 'utf_8', 'big5', 'gbk', 'shift_jis', 'euc_kr',
        }),
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
                 font_size=12, east_asian_wide=False, display_env=None):
        self._font_family = font_family
        self._group_name = group_name
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._east_asian_wide = east_asian_wide
        self._display_env = display_env
        self._window_title = f'render-{os.getpid()}-{group_name}'
        self._proc = None
        self._window_id = None
        self._tmpdir = None
        self._data_fifo = None
        self._ready_fifo = None

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

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._subprocess_env(),
        )

        try:
            result = subprocess.run(
                ['xdotool', 'search', '--sync',
                 '--name', self._window_title],
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

        print(f"  {tool} [{self._group_name}] started: "
              f"window {self._window_id}, font '{self._font_family}'",
              file=sys.stderr)

    def stop(self):
        """Shut down the terminal process and clean up FIFOs.

        Sends an empty payload to trigger the helper's exit condition,
        then waits for the process to terminate.  Falls back to SIGTERM
        and SIGKILL if needed.
        """
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

        # Wait for helper to signal "ready"
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        try:
            signal.alarm(10)
            with open(self._ready_fifo, 'r') as f:
                ready = f.readline().strip()
            signal.alarm(0)
        except (_FifoTimeout, OSError) as exc:
            signal.alarm(0)
            print(f"  {tool} [{self._group_name}] ready signal "
                  f"failed: {exc}", file=sys.stderr)
            return False
        finally:
            signal.signal(signal.SIGALRM, old_handler)

        if ready != 'ready':
            print(f"  {tool} [{self._group_name}] unexpected "
                  f"signal: {ready!r}", file=sys.stderr)
            return False

        # Brief pause to let the terminal finish rendering the banner.
        time.sleep(0.1)

        # Capture screenshot (import -window reads directly by window ID).
        try:
            result = subprocess.run(
                ['import', '-window', self._window_id, output_path],
                capture_output=True, timeout=10,
                env=self._subprocess_env(),
            )
            if result.returncode != 0:
                print(f"  import failed for {output_path}: "
                      f"{result.stderr.decode(errors='replace').strip()}",
                      file=sys.stderr)
                return False
        except subprocess.TimeoutExpired:
            print(f"  import timed out for {output_path}",
                  file=sys.stderr)
            return False

        # Crop to content height (full width) + 3px bottom padding.
        try:
            result = subprocess.run(
                ['convert', output_path, '-fuzz', '1%', '-trim',
                 '-format', '%Y %h', 'info:'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                y_offset = int(parts[0])
                trim_h = int(parts[1])
                crop_h = y_offset + trim_h + 3
                subprocess.run(
                    ['convert', output_path,
                     '-crop', f'x{crop_h}+0+0', '+repage',
                     output_path],
                    capture_output=True, timeout=10,
                )
        except (subprocess.TimeoutExpired, ValueError, IndexError):
            pass  # cropping is optional, keep original image

        if (not os.path.isfile(output_path)
                or os.path.getsize(output_path) == 0):
            print(f"  {tool} produced empty output: {output_path}",
                  file=sys.stderr)
            return False

        return True


def _apply_crt_effects(path, group_name, columns):
    """Apply CRT phosphor bloom and scanline effects to a banner PNG.

    The image is 2x upscaled (nearest-neighbor) before effects are
    applied for higher-quality output.  Bloom is applied via
    pixelgreat.  Scanlines are 2px dark bands every 4th row of the
    upscaled image for visible effect at 2x scale.

    :param path: path to the PNG file (modified in place)
    :param group_name: font group key from ``_FONT_GROUPS``
    :param columns: number of terminal columns used for this capture
    """
    from PIL import Image, ImageDraw
    import pixelgreat as pg

    img = Image.open(path)
    orig_mode = img.mode
    if orig_mode not in ('RGB', 'RGBA'):
        img = img.convert('RGB')

    # --- 2x upscale (nearest-neighbor to keep sharp pixels) ---
    img = img.resize((img.width * 2, img.height * 2), Image.NEAREST)

    # --- Bloom ---
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        result = pg.pixelgreat(
            image=img,
            pixel_size=10,
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

    # --- Scanlines ---
    # 2px dark line every 4 rows for visible effect at 2x scale.
    overlay = Image.new('RGBA', result.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    for y in range(2, result.height, 4):
        draw.line([(0, y), (result.width - 1, y)], fill=(0, 0, 0, 60))
        draw.line([(0, y + 1), (result.width - 1, y + 1)], fill=(0, 0, 0, 60))
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

    :param backend: ``'kitty'``, ``'wezterm'``, or ``'auto'``
    :param columns: default terminal width in columns
    :param rows: terminal height in rows
    :param font_size: font size for all instances
    :param crt_effects: apply CRT bloom and scanlines to output PNGs
    """

    def __init__(self, backend='auto', columns=80, rows=60, font_size=12,
                 crt_effects=True):
        self._backend = self._resolve_backend(backend)
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._crt_effects = crt_effects
        self._instances = {}
        self._xvfb_proc = None
        self._display_env = None

    @staticmethod
    def _resolve_backend(backend):
        """Resolve ``'auto'`` to a concrete backend name.

        Checks ``MODEM_RENDERER`` env var first, then probes for
        available terminals in order: wezterm, kitty.

        :param backend: ``'kitty'``, ``'wezterm'``, or ``'auto'``
        :returns: ``'kitty'`` or ``'wezterm'``
        :raises RuntimeError: if no backend is available
        """
        if backend != 'auto':
            return backend
        env = os.environ.get('MODEM_RENDERER', '').lower()
        if env in ('kitty', 'wezterm'):
            return env
        if shutil.which('wezterm'):
            return 'wezterm'
        if shutil.which('kitty'):
            return 'kitty'
        raise RuntimeError("No terminal renderer backend found "
                           "(need kitty or wezterm)")

    def _start_xvfb(self):
        """Launch a virtual X11 display via Xvfb.

        Finds a free display number starting at :99 and launches Xvfb
        with a screen large enough for terminal rendering.
        """
        if shutil.which('Xvfb') is None:
            print("  Xvfb not found, rendering on real display",
                  file=sys.stderr)
            return
        for display_num in range(99, 200):
            display = f':{display_num}'
            lock_path = f'/tmp/.X{display_num}-lock'
            if os.path.exists(lock_path):
                continue
            self._xvfb_proc = subprocess.Popen(
                ['Xvfb', display, '-screen', '0', '3200x2400x24'],
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
        print("  Could not find free display for Xvfb, "
              "rendering on real display", file=sys.stderr)

    def __enter__(self):
        self._start_xvfb()
        return self

    def __exit__(self, *exc):
        for name, instance in self._instances.items():
            try:
                instance.stop()
            except Exception as e:
                print(f"  Warning: failed to stop renderer "
                      f"[{name}]: {e}", file=sys.stderr)
        self._instances.clear()
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

    def _make_instance(self, group_name, effective_cols):
        """Create the right TerminalInstance subclass.

        :param group_name: font group key from ``_FONT_GROUPS``
        :param effective_cols: resolved column width
        :returns: a TerminalInstance subclass instance
        """
        group_info = _FONT_GROUPS[group_name]
        east_asian = _is_east_asian_encoding(group_name)
        display = (f"{group_name}-{effective_cols}"
                   if effective_cols != 80 else group_name)
        kwargs = dict(
            font_family=group_info['font_family'],
            group_name=display,
            columns=effective_cols,
            rows=self._rows,
            font_size=self._font_size,
            east_asian_wide=east_asian,
            display_env=self._display_env,
        )
        if self._backend == 'kitty':
            from make_stats.renderer_kitty import KittyInstance
            return KittyInstance(**kwargs)
        from make_stats.renderer_wezterm import WeztermInstance
        return WeztermInstance(**kwargs)

    def _get_instance(self, group_name, columns=None):
        """Get or lazily create an instance for the given group.

        :param group_name: font group key from ``_FONT_GROUPS``
        :param columns: optional column width override
        :returns: TerminalInstance or None on failure
        """
        effective_cols = (columns if columns is not None
                          else self._determine_columns(group_name))
        instance_key = (group_name, effective_cols)

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

        inst = self._make_instance(group_name, effective_cols)
        try:
            inst.start()
        except RuntimeError as exc:
            print(f"  renderer [{group_name}] failed to start: {exc}",
                  file=sys.stderr)
            return None

        self._instances[instance_key] = inst
        return inst

    def capture(self, text, output_path, encoding='cp437', columns=None):
        """Route a banner to the appropriate terminal instance.

        :param text: preprocessed banner text
        :param output_path: path to write the output PNG
        :param encoding: server encoding for font group selection
        :param columns: optional column width override
        :returns: True if PNG was successfully created
        """
        group_name = _encoding_to_font_group(encoding)
        instance = self._get_instance(group_name, columns=columns)
        if instance is None:
            return False
        if not instance.capture(text, output_path):
            return False

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
            _apply_crt_effects(output_path, group_name, effective_cols)

        return True

    @staticmethod
    def available():
        """Check if terminal screenshot rendering is possible.

        :returns: True if DISPLAY is set or Xvfb is available, and at
            least one backend plus xdotool and import are found in PATH
        """
        has_display = (os.environ.get('DISPLAY')
                       or shutil.which('Xvfb') is not None)
        if not has_display:
            return False
        for tool in ('xdotool', 'import'):
            if shutil.which(tool) is None:
                return False
        return (shutil.which('kitty') is not None
                or shutil.which('wezterm') is not None)
