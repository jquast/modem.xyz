"""BBS encoding codecs vendored from x84.

Registers cp437, cp437_art, amiga, and atarist codecs with Python's
codecs module.  Import this package to make these encodings available
via ``codecs.lookup()`` and ``bytes.decode()``.
"""

import codecs
import importlib

_cache = {}
_aliases = {}


def _search_function(encoding):
    """Codec search function registered with codecs.register()."""
    normalized = encoding.lower().replace('-', '_')

    if normalized in _aliases:
        return _aliases[normalized]

    if normalized in _cache:
        return _cache[normalized]

    try:
        mod = importlib.import_module(f'.{normalized}', package=__name__)
    except ImportError:
        _cache[normalized] = None
        return None

    try:
        info = mod.getregentry()
    except AttributeError:
        _cache[normalized] = None
        return None

    _cache[normalized] = info

    if hasattr(mod, 'getaliases'):
        for alias in mod.getaliases():
            _aliases[alias] = info

    return info


codecs.register(_search_function)
