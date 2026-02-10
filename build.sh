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

# Build libansilove if needed
if [ ! -f libansilove/build/libansilove.so ]; then
    echo "Building libansilove..."
    (cd libansilove && mkdir -p build && cd build && cmake .. && make)
fi

# Build ansi2png if needed
if [ ! -f ansi2png ] || [ ansi2png.c -nt ansi2png ]; then
    echo "Building ansi2png..."
    gcc -o ansi2png ansi2png.c \
        -I./libansilove/include \
        -L./libansilove/build \
        -lansilove
fi

export LD_LIBRARY_PATH="./libansilove/build${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

python make_stats.py --muds "$@" && \
  sphinx-build -d docs-muds/_build/doctrees -b html docs-muds docs-muds/_build/html

python make_stats.py --bbs "$@" && \
  sphinx-build -d docs-bbs/_build/doctrees -b html docs-bbs docs-bbs/_build/html
