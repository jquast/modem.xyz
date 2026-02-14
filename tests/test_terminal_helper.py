"""Tests for terminal_helper.py."""

import os
import threading

import pytest

from make_stats.terminal_helper import _signal_ready


class TestSignalReady:

    def test_ok_message(self, tmp_path):
        fifo_path = str(tmp_path / 'ready.fifo')
        os.mkfifo(fifo_path)

        result_holder = []

        def reader():
            with open(fifo_path, 'r') as f:
                result_holder.append(f.readline().strip())

        t = threading.Thread(target=reader)
        t.start()

        assert _signal_ready(fifo_path, 'ok 1234')
        t.join(timeout=2)
        assert result_holder == ['ok 1234']

    def test_broken_pipe(self):
        assert not _signal_ready('/nonexistent/path/fifo', 'ok 100')
