#!/usr/bin/env python3
"""Helper script running inside a terminal instance (kitty or wezterm).

Reads banner payloads from a named pipe, clears the screen, displays
each one, then signals readiness for screenshot via a second named pipe.

Usage::

    terminal_helper.py DATA_FIFO READY_FIFO WINDOW_TITLE
"""

import os
import select
import subprocess
import sys
import traceback


def _set_title(title):
    """Set the terminal window title via OSC escape."""
    os.write(1, f'\033]0;{title}\007'.encode())


def _drain_stdin():
    """Drain any pending terminal report responses from stdin.

    Uses select() to wait briefly for data, then reads and discards
    all available input without changing terminal modes.
    """
    fd = sys.stdin.fileno()
    while select.select([fd], [], [], 0.02)[0]:
        os.read(fd, 4096)


def _log(msg):
    """Write a debug message to stderr (visible in terminal)."""
    os.write(2, (msg + '\n').encode())


def main():
    data_pipe = sys.argv[1]
    ready_pipe = sys.argv[2]
    window_title = sys.argv[3]

    # Redirect stderr to a log file for debugging.
    log_path = os.path.join(os.path.dirname(data_pipe), 'helper.log')
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(log_fd, 2)
    os.close(log_fd)

    _log(f'helper started: title={window_title}')

    # Disable echo so terminal report responses don't appear on screen.
    subprocess.call(['stty', '-echo'], stdin=sys.stdin)

    _set_title(window_title)

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
        _log(f'banner #{count}: {len(payload)} bytes')

        # Reset attributes, clear screen, home cursor, hide cursor.
        os.write(1, b'\033[m\033[2J\033[H\033[?25l')

        # Restore title and draw banner.
        _set_title(window_title)
        os.write(1, payload)

        # Drain terminal report responses.
        _drain_stdin()

        # Signal controller: ready for screenshot.
        try:
            with open(ready_pipe, 'w') as f:
                f.write('ready\n')
        except OSError as exc:
            _log(f'ready signal failed: {exc}')
            break

    _log(f'helper exiting after {count} banners')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
