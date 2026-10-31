#!/usr/bin/env bash
# Regenerate every PNG from its .drawio source.
#
# Each PNG embeds a full copy of the diagram in a `zTXt` chunk (keyword
# `mxGraphModel`), so it is both a viewable image and an editable draw.io file.
# That is what makes this loop work: edit the .drawio, run this script, commit
# both. Open the PNG in draw.io desktop and the diagram comes back editable,
# cell for cell.
#
# PNG is the chosen format over SVG for one concrete reason: draw.io emits SVG
# label text inside `foreignObject` elements, which GitHub's image proxy strips,
# so an SVG embedded in a README there renders shapes with no text. A PNG renders
# correctly everywhere, and it is roughly a quarter of the size.
#
# Requirements: draw.io desktop (`drawio` on PATH) and `xvfb-run`, because the
# export drives a headless Electron window.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/png"

# 2x, so label text stays legible on a high-DPI display and when a diagram is
# zoomed in a README. The widest diagram here is 1900 units, so this tops out
# around 3800 pixels across, which is well within reason for a documentation
# image.
scale="${SCALE:-2}"

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
        --format png \
        --embed-diagram \
        --size diagram \
        --scale "$scale" \
        --output "$out/$name.png" \
        "$src" 2>&1 | grep -v 'dbus\|Failed to connect' || true
    echo "built png/$name.png"
done
