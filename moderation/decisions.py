"""Decision cache for moderation sessions."""

import json
import os
from pathlib import Path


def load_decisions(path):
    """Load cached moderation decisions from a JSON file.

    :param path: path to the decisions file
    :returns: dict with ``"cross"`` and ``"dupes"`` keys
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault("cross", {})
    data.setdefault("dupes", {})
    data.setdefault("dns", {})
    data.setdefault("rejected", {"mud": {}, "bbs": {}})
    return data


def save_decisions(path, decisions):
    """Save moderation decisions atomically.

    :param path: path to write the decisions file
    :param decisions: dict with ``"cross"`` and ``"dupes"`` keys
    """
    output = Path(str(path) + ".new")
    with open(output, "w", encoding="utf-8") as f:
        json.dump(decisions, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(output, path)


def record_rejections(decisions, list_name, removals, reason):
    """Record removed entries so fetch_lists.py won't re-add them.

    :param decisions: mutable decisions dict
    :param list_name: ``"mud"`` or ``"bbs"``
    :param removals: set of ``(host, port)`` tuples that were removed
    :param reason: short reason string (e.g. ``"dead"``, ``"duplicate"``)
    """
    rejected = decisions.setdefault(
        "rejected", {"mud": {}, "bbs": {}})
    bucket = rejected.setdefault(list_name, {})
    for host, port in removals:
        bucket[f"{host}:{port}"] = reason


def _group_cache_key(members):
    """Create a stable cache key from a group of records.

    :param members: list of record dicts with ``host`` and ``port`` keys
    :returns: string key (sorted ``host:port`` pairs joined by ``|``)
    """
    parts = sorted(f"{r['host']}:{r['port']}" for r in members)
    return "|".join(parts)
