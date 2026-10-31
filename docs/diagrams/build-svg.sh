#!/usr/bin/env bash
# Regenerate every SVG from its .drawio source.
#
# Each SVG embeds a full copy of the diagram in its `content` attribute, so it
# is both a rendered image and an editable draw.io file. That is what makes
# this loop work: edit the .drawio, run this script, commit both.
#
# A .svg can also be opened directly in draw.io, edited, and saved. Either
# direction works; the .drawio stays the source of truth for review, because
# a diff of rendered SVG is unreadable.
#
# Requirements: draw.io desktop (`drawio` on PATH) and `xvfb-run`, because the
# export runs a headless Electron window.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/svg"

command -v drawio >/dev/null || {
    echo "drawio not found on PATH; install draw.io desktop" >&2
    exit 1
}

mkdir -p "$out"

shopt -s nullglob
sources=("$here"/*.drawio)
if [ ${#sources[@]} -eq 0 ]; then
    echo "no .drawio files found in $here" >&2
    exit 1
fi

for src in "${sources[@]}"; do
    name="$(basename "$src" .drawio)"
    # `-e` embeds the editable diagram copy. `--size diagram` crops to content
    # rather than the page, so the image has no large empty margin.
    xvfb-run -a drawio \
        --export \
        --format svg \
        --embed-diagram \
        --size diagram \
        --output "$out/$name.svg" \
        "$src" 2>&1 | grep -v 'dbus\|Failed to connect' || true
    echo "built svg/$name.svg"
done
