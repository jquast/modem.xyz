#!/usr/bin/env python3
"""Helper script running inside a terminal instance (wezterm).

Reads banner payloads from a named pipe, clears the screen, displays
each one, uses DSR flush synchronization to confirm the terminal rendered
it, then signals readiness for screenshot via a second named pipe.

In mux mode (when FONT_GROUP, COLS, ROWS are given), sets a user
variable via OSC 1337 to trigger per-window font overrides, and
resizes the terminal via the xterm resize escape.

Usage::

    terminal_helper.py DATA_FIFO READY_FIFO WINDOW_TITLE [FONT_GROUP COLS ROWS]
"""

import base64
import os
import select
import subprocess
import sys
import time
import traceback

# Break out of any in-progress escape sequence, then full terminal reset.
# A poison banner can leave the parser mid-sequence (partial CSI, unterminated
# OSC/DCS/APC/PM/SOS).  Without these prefixes, _CLEAR_SEQ gets swallowed
# and the terminal stays stuck showing the previous banner.
_CLEAR_SEQ = (
    b'\x18'         # CAN — abort any in-progress escape sequence
    b'\x1a'         # SUB — also aborts (some terminals prefer SUB over CAN)
    b'\033\\'       # ST  — terminate any string sequence (OSC/DCS/APC/PM/SOS)
    b'\x0f'         # SI  — restore G0 charset (undo any \x0e shift-out)
    b'\033c'        # RIS — full terminal reset (modes, charset, screen)
    b'\033[?25l'    # hide cursor (RIS re-enables it)
)

_DSR_QUERY = b'\033[6n'


def _set_title(title):
    """Set the terminal window title via OSC escape."""
    os.write(1, f'\033]0;{title}\007'.encode())


def _drain_stdin():
    """Drain any pending bytes from stdin without blocking."""
    fd = sys.stdin.fileno()
    while select.select([fd], [], [], 0)[0]:
        os.read(fd, 4096)


def _wait_for_cpr(timeout=5.0):
    """Wait for a Cursor Position Report after sending DSR query.

    Drains any stale input, sends ``\\033[6n``, and reads stdin until
    a full CPR response (``\\033[<digits>;<digits>R``) is seen, or
    *timeout* seconds elapse.  The terminal must finish processing all
    prior output before it can respond, so this acts as a
    render-complete synchronization barrier.

    :param timeout: maximum seconds to wait for the CPR response
    :returns: True if CPR received, False on timeout
    """
    _drain_stdin()
    os.write(1, _DSR_QUERY)

    fd = sys.stdin.fileno()
    buf = b''
    deadline = _monotonic() + timeout
    while True:
        remaining = deadline - _monotonic()
        if remaining <= 0:
            return False
        ready = select.select([fd], [], [], min(remaining, 0.1))
        if ready[0]:
            data = os.read(fd, 4096)
            if not data:
                return False
            buf += data
            # Scan for CPR: ESC [ <digits> ; <digits> R
            while b'\033[' in buf:
                idx = buf.index(b'\033[')
                tail = buf[idx + 2:]
                found_end = False
                for i, byte in enumerate(tail):
                    if byte == ord('R'):
                        return True
                    if byte not in b'0123456789;':
                        buf = buf[idx + 2 + i + 1:]
                        found_end = True
                        break
                if not found_end:
                    break  # partial sequence, wait for more data


def _monotonic():
    """Monotonic clock wrapper for readability."""
    return time.monotonic()


def _log(msg):
    """Write a debug message to stderr (redirected to helper.log)."""
    os.write(2, (msg + '\n').encode())


def _signal_ready(ready_pipe, message):
    """Write a status message to the ready FIFO.

    :param ready_pipe: path to the ready named pipe
    :param message: status string to send
    :returns: True if successfully written, False on error
    """
    try:
        with open(ready_pipe, 'w') as f:
            f.write(message + '\n')
        return True
    except OSError as exc:
        _log(f'ready signal failed: {exc}')
        return False


def _set_user_var(name, value):
    """Set a wezterm user variable via OSC 1337 SetUserVar.

    :param name: variable name
    :param value: variable value (will be base64-encoded)
    """
    b64 = base64.b64encode(value.encode()).decode()
    os.write(1, f'\033]1337;SetUserVar={name}={b64}\007'.encode())



def main():
    data_pipe = sys.argv[1]
    ready_pipe = sys.argv[2]
    window_title = sys.argv[3]

    # Optional mux-mode arguments.
    font_group = sys.argv[4] if len(sys.argv) > 4 else None
    target_cols = int(sys.argv[5]) if len(sys.argv) > 5 else None
    target_rows = int(sys.argv[6]) if len(sys.argv) > 6 else None

    # Redirect stderr to a log file for debugging.
    log_path = os.path.join(os.path.dirname(data_pipe), 'helper.log')
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(log_fd, 2)
    os.close(log_fd)

    _log(f'helper started: title={window_title}')

    # Disable echo and canonical buffering so DSR cursor-position reports
    # are readable immediately from stdin.  Keep output post-processing
    # (opost/onlcr) enabled so \n is translated to \r\n by the terminal.
    subprocess.call(['stty', '-echo', '-icanon'], stdin=sys.stdin)

    _set_title(window_title)

    # Mux mode: set font group user variable (with optional resize).
    if font_group is not None:
        if target_cols is not None and target_rows is not None:
            _set_user_var('font_group',
                          f'{font_group}:{target_cols};{target_rows}')
            _log(f'set user var font_group={font_group} '
                 f'resize={target_cols}x{target_rows}')
        else:
            _set_user_var('font_group', font_group)
            _log(f'set user var font_group={font_group}')

    # Probe DSR before any banners — the terminal may need a moment to
    # initialize its PTY, so allow a generous timeout on the first try.
    if _wait_for_cpr(timeout=5.0):
        _log('DSR probe OK — render-flush synchronization active')
    else:
        _log('DSR probe failed — terminal does not respond to DSR, '
             'screenshots may capture stale content')

    count = 0
    while True:
        # Block until controller sends a banner (reads until EOF on pipe).
        try:
            fd = os.open(data_pipe, os.O_RDONLY)
        except OSError as exc:
            _log(f'open data_pipe failed: {exc}')
            break
        try:
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)

        payload = b''.join(chunks)
        if not payload:
            _log('empty payload, shutting down')
            break

        count += 1
        nbytes = len(payload)
        _log(f'banner #{count}: {nbytes} bytes')

        # Thorough reset and clear.
        os.write(1, _CLEAR_SEQ)

        # DSR barrier after reset: confirm the terminal processed the
        # clear before writing the new banner.
        if not _wait_for_cpr(timeout=3.0):
            _log(f'banner #{count}: post-reset DSR failed, continuing')

        # Restore title and draw banner.
        _set_title(window_title)
        try:
            os.write(1, payload)
        except OSError as exc:
            _log(f'write failed: {exc}')
            if not _signal_ready(ready_pipe, f'fail write_error: {exc}'):
                break
            continue

        # Force wezterm's software renderer to repaint on Xvfb.
        # On a virtual framebuffer there are no vsync/expose events, so
        # inactive windows may show stale content.  Changing a user var
        # triggers the Lua set_config_overrides handler which forces a
        # repaint cycle.
        if font_group is not None:
            _set_user_var('redraw', str(count))

        # DSR flush: confirm terminal processed all output before
        # signaling the renderer to take a screenshot.  Scale timeout
        # with payload size (base 5s + 1s per 64 KiB).
        flush_timeout = 5.0 + nbytes / 65536
        if _wait_for_cpr(timeout=flush_timeout):
            # Brief pause for compositor to paint the frame after the
            # terminal has processed all escape sequences.
            time.sleep(0.10)
            _log(f'banner #{count}: flush confirmed')
            if not _signal_ready(ready_pipe, f'ok {nbytes}'):
                break
        else:
            _log(f'banner #{count}: flush timeout after {flush_timeout:.1f}s')
            if not _signal_ready(ready_pipe, f'fail flush_timeout'):
                break

    _log(f'helper exiting after {count} banners')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
