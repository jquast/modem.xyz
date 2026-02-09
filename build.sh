#!/bin/sh
# Generate RST + plots, then build HTML with Sphinx for both sites.
#
# Usage: ./make_docs.sh [--data-dir PATH]
#
# Pass -f to force a clean build.

set -e

FORCE=
for arg in "$@"; do
    if [ "$arg" = "-f" ]; then
        FORCE=1
        shift
    fi
done

if [ -n "$FORCE" ]; then
    rm -rf docs-muds/_build/html docs-bbs/_build/html
fi

python make_mudstats.py "$@" && \
  sphinx-build -d docs-muds/_build/doctrees -b html docs-muds docs-muds/_build/html

python make_bbsstats.py "$@" && \
  sphinx-build -d docs-bbs/_build/doctrees -b html docs-bbs docs-bbs/_build/html
