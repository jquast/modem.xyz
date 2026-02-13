"""GeoIP country lookup with persistent caching via ip-api.com."""

import json
import os
import sys
import time

import requests

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE_FILE = os.path.join(_PROJECT_ROOT, 'geoip_cache.json')
_TTL_DAYS = 30
_TTL_SECONDS = _TTL_DAYS * 86400
_BATCH_URL = 'http://ip-api.com/batch'
_BATCH_SIZE = 100
_BATCH_DELAY = 4  # seconds between batch requests (15 req/min limit)


def _country_flag(code: str) -> str:
    """Convert a 2-letter ISO country code to regional indicator emoji.

    :param code: two-letter uppercase country code (e.g. ``'US'``)
    :returns: flag emoji string, or empty string if code is invalid
    """
    if not code or len(code) != 2:
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


def _load_cache() -> dict:
    """Load the GeoIP cache from disk.

    :returns: dict mapping IP strings to cache entries
    """
    if not os.path.isfile(_CACHE_FILE):
        return {}
    with open(_CACHE_FILE, 'r') as f:
        return json.load(f)


def _save_cache(cache: dict) -> None:
    """Write the GeoIP cache to disk.

    :param cache: dict mapping IP strings to cache entries
    """
    with open(_CACHE_FILE + '.tmp', 'w') as f:
        json.dump(cache, f, indent=1, sort_keys=True)
    os.replace(_CACHE_FILE + '.tmp', _CACHE_FILE)


def _query_batch(ips: list) -> dict:
    """Query ip-api.com batch endpoint for a list of IPs.

    :param ips: list of IP address strings (max 100)
    :returns: dict mapping IP -> (country_code, country_name)
    """
    payload = [{'query': ip, 'fields': 'query,status,country,countryCode'}
               for ip in ips]
    resp = requests.post(_BATCH_URL, json=payload, timeout=30)
    resp.raise_for_status()
    results = {}
    for entry in resp.json():
        ip = entry.get('query', '')
        if entry.get('status') == 'success':
            results[ip] = (entry.get('countryCode', ''),
                           entry.get('country', ''))
        else:
            results[ip] = ('', 'Unknown')
    return results


def lookup_countries(servers: list) -> None:
    """Look up and annotate servers with country information.

    Adds ``_country_code`` and ``_country_name`` keys to each server record.
    Uses a persistent JSON cache with a 30-day TTL per IP.

    :param servers: list of server record dicts (must have ``'ip'`` key)
    """
    unique_ips = {s['ip'] for s in servers if s.get('ip')}
    cache = _load_cache()
    now = time.time()

    fresh = {}
    stale = []
    for ip in sorted(unique_ips):
        entry = cache.get(ip)
        if entry and (now - entry.get('ts', 0)) < _TTL_SECONDS:
            fresh[ip] = entry
        else:
            stale.append(ip)

    print(f"GeoIP: {len(fresh)} cached, {len(stale)} to query",
          file=sys.stderr)

    for i in range(0, len(stale), _BATCH_SIZE):
        batch = stale[i:i + _BATCH_SIZE]
        batch_num = i // _BATCH_SIZE + 1
        total_batches = (len(stale) + _BATCH_SIZE - 1) // _BATCH_SIZE
        print(f"  batch {batch_num}/{total_batches}"
              f" ({len(batch)} IPs) ...", file=sys.stderr)
        results = _query_batch(batch)
        for ip, (code, name) in results.items():
            cache[ip] = {'country': code, 'country_name': name,
                         'ts': now}
        if i + _BATCH_SIZE < len(stale):
            time.sleep(_BATCH_DELAY)

    if stale:
        _save_cache(cache)

    for s in servers:
        ip = s.get('ip', '')
        entry = cache.get(ip, {})
        s['_country_code'] = entry.get('country', '')
        s['_country_name'] = entry.get('country_name', 'Unknown')
