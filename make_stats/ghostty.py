"""Kitty terminal screenshot renderer for ANSI banners.

Launches real kitty terminal instances (one per font group) and
captures screenshots via ``xdotool`` + ImageMagick ``import``.
Communication uses named pipes (FIFOs) with bidirectional signaling:
a data pipe sends banner text to the helper script, and a ready pipe
signals back when painting is complete.

Requires: kitty, xdotool, ImageMagick (import + convert), X11 DISPLAY.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HELPER_SCRIPT = os.path.join(os.path.dirname(__file__), 'ghostty_helper.sh')

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
        'encodings': frozenset({
            'cp437', 'cp437_art', 'cp437-art',
            'cp737', 'cp775', 'cp850', 'cp852', 'cp855',
            'cp857', 'cp860', 'cp861', 'cp862', 'cp863',
            'cp865', 'cp866', 'cp869', 'koi8_r', 'unknown',
        }),
    },
    'topaz': {
        'font_family': 'Amiga Topaz',
        'encodings': frozenset({'amiga', 'topaz'}),
    },
    'petscii': {
        'font_family': 'Bescii Mono',
        'encodings': frozenset({'petscii'}),
        'aspect_ratio': 1.2,  # C64 320x200 on 4:3 CRT (6:5)
        'columns': 40,
    },
    'atascii': {
        'font_family': 'EightBit Atari',
        'encodings': frozenset({'atarist', 'atascii'}),
        'aspect_ratio': 1.25,  # Atari 320x192 on 4:3 CRT (5:4)
        'columns': 40,
    },
    'hack': {
        'font_family': 'Hack',
        'encodings': frozenset({
            'ascii', 'latin_1', 'iso_8859_1', 'iso_8859_1:1987',
            'iso_8859_2', 'utf_8', 'big5', 'gbk', 'shift_jis', 'euc_kr',
        }),
    },
}


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


class _FifoTimeout(Exception):
    """Raised when a FIFO operation exceeds its timeout."""


def _alarm_handler(signum, frame):
    raise _FifoTimeout("FIFO operation timed out")


class GhosttyInstance:
    """A single kitty terminal process for rendering banners.

    Each instance runs a helper script that reads banner text from a
    named pipe, clears the terminal, and displays the text.  After a
    100ms paint settle, the helper signals readiness via a second pipe.
    The controller then captures a screenshot.

    :param font_family: kitty ``font_family`` config value
    :param group_name: identifier used for window title and FIFO naming
    :param columns: terminal width in columns
    :param rows: terminal height in rows
    :param font_size: kitty ``font_size`` config value
    """

    def __init__(self, font_family, group_name, columns=80, rows=70, font_size=12):
        self._font_family = font_family
        self._group_name = group_name
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._window_title = f'kitty-render-{os.getpid()}-{group_name}'
        self._proc = None
        self._window_id = None
        self._tmpdir = None
        self._data_fifo = None
        self._ready_fifo = None

    def start(self):
        """Launch the kitty process and find its X11 window ID.

        Creates a temporary directory with two named pipes, launches
        kitty running the helper script, and locates the window via
        ``xdotool search --sync --name``.

        :raises RuntimeError: if kitty fails to start or window not found
        """
        self._tmpdir = tempfile.mkdtemp(
            prefix=f'kitty-{self._group_name}-')
        self._data_fifo = os.path.join(self._tmpdir, 'data.fifo')
        self._ready_fifo = os.path.join(self._tmpdir, 'ready.fifo')
        os.mkfifo(self._data_fifo)
        os.mkfifo(self._ready_fifo)

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
                     self._data_fifo, self._ready_fifo, self._window_title])

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            result = subprocess.run(
                ['xdotool', 'search', '--sync',
                 '--name', self._window_title],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired as exc:
            self.stop()
            raise RuntimeError(
                f"Timed out waiting for kitty window "
                f"({self._window_title})") from exc

        window_ids = result.stdout.strip().split('\n')
        if not window_ids or not window_ids[0]:
            self.stop()
            raise RuntimeError(
                f"Could not find kitty window ({self._window_title})")
        self._window_id = window_ids[0]

        print(f"  kitty [{self._group_name}] started: "
              f"window {self._window_id}, font '{self._font_family}'",
              file=sys.stderr)

    def stop(self):
        """Shut down the kitty process and clean up FIFOs.

        Sends an empty payload to trigger the helper's exit condition,
        then waits for the process to terminate.  Falls back to SIGTERM
        and SIGKILL if needed.
        """
        if self._proc is not None and self._proc.poll() is None:
            # Send empty payload to trigger shutdown
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
        """Return True if the kitty process is running."""
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
            print(f"  kitty [{self._group_name}] data write "
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
            print(f"  kitty [{self._group_name}] ready signal "
                  f"failed: {exc}", file=sys.stderr)
            return False
        finally:
            signal.signal(signal.SIGALRM, old_handler)

        if ready != 'ready':
            print(f"  kitty [{self._group_name}] unexpected "
                  f"signal: {ready!r}", file=sys.stderr)
            return False

        # Raise window to front before capture
        subprocess.run(
            ['xdotool', 'windowactivate', '--sync', self._window_id],
            capture_output=True, timeout=5,
        )

        # Capture screenshot
        try:
            result = subprocess.run(
                ['import', '-window', self._window_id, output_path],
                capture_output=True, timeout=10,
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
            print(f"  kitty produced empty output: {output_path}",
                  file=sys.stderr)
            return False

        return True


class GhosttyPool:
    """Pool of kitty terminal instances, one per font group.

    Instances are created lazily on first use for each font group.
    Acts as a context manager: on exit, shuts down all instances.

    :param columns: terminal width in columns
    :param rows: terminal height in rows
    :param font_size: font size for all instances
    """

    def __init__(self, columns=80, rows=60, font_size=12):
        self._columns = columns
        self._rows = rows
        self._font_size = font_size
        self._instances = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for name, instance in self._instances.items():
            try:
                instance.stop()
            except Exception as e:
                print(f"  Warning: failed to stop kitty "
                      f"[{name}]: {e}", file=sys.stderr)
        self._instances.clear()

    def _determine_columns(self, group_name):
        return _FONT_GROUPS.get(group_name, {}).get('columns', self._columns)

    def _get_instance(self, group_name):
        """Get or lazily create a GhosttyInstance for the given group.

        :param group_name: font group key from ``_FONT_GROUPS``
        :returns: GhosttyInstance or None on failure
        """
        if group_name in self._instances:
            inst = self._instances[group_name]
            if inst.alive:
                return inst
            print(f"  kitty [{group_name}] died, restarting...",
                  file=sys.stderr)
            try:
                inst.stop()
            except Exception:
                pass

        group_info = _FONT_GROUPS.get(group_name)
        if group_info is None:
            return None

        inst = GhosttyInstance(
            font_family=group_info['font_family'],
            group_name=group_name,
            columns=self._determine_columns(group_name),
            rows=self._rows,
            font_size=self._font_size,
        )
        try:
            inst.start()
        except RuntimeError as exc:
            print(f"  kitty [{group_name}] failed to start: {exc}",
                  file=sys.stderr)
            return None

        self._instances[group_name] = inst
        return inst

    def capture(self, text, output_path, encoding='cp437'):
        """Route a banner to the appropriate kitty instance.

        :param text: preprocessed banner text
        :param output_path: path to write the output PNG
        :param encoding: server encoding for font group selection
        :returns: True if PNG was successfully created
        """
        group_name = _encoding_to_font_group(encoding)
        instance = self._get_instance(group_name)
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
        return True

    @staticmethod
    def available():
        """Check if kitty screenshot rendering is possible.

        :returns: True if DISPLAY is set and kitty, xdotool,
            and import are all found in PATH
        """
        if not os.environ.get('DISPLAY'):
            return False
        for tool in ('kitty', 'xdotool', 'import'):
            if shutil.which(tool) is None:
                return False
        return True
