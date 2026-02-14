"""Shared utility functions for the moderation package."""

import json
import re
import shutil
import subprocess
import sys
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import wcwidth

from make_stats.common import _strip_ansi

_BAT = shutil.which("bat") or shutil.which("batcat")
_JQ = shutil.which("jq")
_DIGITS_RE = re.compile(r"\d+")

# Default paths relative to the package's parent (the project root).
_HERE = Path(__file__).resolve().parent.parent
DEFAULT_MUD_LIST = _HERE / "mudlist.txt"
DEFAULT_BBS_LIST = _HERE / "bbslist.txt"
DEFAULT_MUD_DATA = _HERE
DEFAULT_BBS_DATA = _HERE
DEFAULT_LOGS = _HERE / "logs"
DEFAULT_DECISIONS = _HERE / "moderation_decisions.json"


def _normalize_banner(text):
    """Normalize banner for comparison: strip ANSI, digits, whitespace."""
    text = _strip_ansi(text)
    text = _DIGITS_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _banner_hash(text):
    """Hash normalized banner text for grouping."""
    import hashlib
    normalized = _normalize_banner(text)
    if not normalized:
        return ""
    return hashlib.sha256(
        normalized.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


def _normalize_mssp_name(name):
    """Normalize MSSP NAME for comparison."""
    return name.strip().lower()


def _print_json(label, data):
    """Print labeled JSON, colorized through bat or jq when available."""
    raw = json.dumps(data, indent=4, sort_keys=True)
    if _BAT:
        r = subprocess.run(
            [_BAT, "-l", "json", "--style=plain", "--color=always"],
            input=raw, capture_output=True, text=True, check=False,
        )
        if r.returncode == 0:
            raw = r.stdout.rstrip("\n")
    elif _JQ:
        r = subprocess.run(
            [_JQ, "-C", "."],
            input=raw, capture_output=True, text=True, check=False,
        )
        if r.returncode == 0:
            raw = r.stdout.rstrip("\n")
    print(f"{label} {raw}")


def _display_banner(text, maxlines=8):
    """Format banner for compact display."""
    text = _strip_ansi(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > maxlines:
        shown = lines[:maxlines]
        shown.append(f"  ... ({len(lines) - maxlines} more lines)")
        return "\n".join(shown)
    return "\n".join(lines)


def _prompt(message, choices="ynq"):
    """Prompt user for a single-character choice.

    :param message: prompt text
    :param choices: string of valid characters
    :returns: lowercase character, or None on EOF/interrupt
    """
    try:
        answer = input(message).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if answer and answer[0] in choices:
        return answer[0]
    return answer


def _is_ip_address(host):
    """Check whether *host* is a literal IP address (v4 or v6).

    :param host: hostname or IP string
    :returns: True if *host* is a valid IP address
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_hostnames(hostnames, workers=8):
    """Resolve a collection of hostnames to their IP addresses.

    Uses a thread pool with a small worker count to be gentle on DNS.

    :param hostnames: iterable of hostname strings
    :param workers: number of parallel resolver threads
    :returns: dict mapping hostname to set of resolved IP strings
    """
    hostnames = list(hostnames)
    results = {}

    def _resolve(host):
        try:
            infos = socket.getaddrinfo(
                host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return host, {info[4][0] for info in infos}
        except (socket.gaierror, OSError):
            return host, set()

    total = len(hostnames)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, (host, ips) in enumerate(
                pool.map(_resolve, hostnames), 1):
            results[host] = ips
            if done % 100 == 0 or done == total:
                print(f"  resolved {done}/{total} hostnames",
                      file=sys.stderr, end="\r")
    print(file=sys.stderr)
    return results
