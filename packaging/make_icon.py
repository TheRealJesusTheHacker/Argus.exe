"""Generate ``packaging/argus.ico`` — pure standard library.

Draws the Argus eye (a green ring with a watching center dot on a
dark rounded square, matching the GUI's drawn icon) as PNGs at the
standard Windows icon sizes and packs them into an ICO container.
No Pillow, no image assets: run it anywhere Python runs.

    python packaging/make_icon.py
"""

from __future__ import annotations

import math
import struct
import sys
import zlib
from pathlib import Path

SIZES = (16, 24, 32, 48, 64, 128, 256)
BG = (6, 12, 8)          # green-black panel
RING = (46, 224, 111)    # Sentinel green
DOT = (46, 224, 111)


def _blend(dst: tuple[int, int, int], src: tuple[int, int, int], alpha: float):
    return tuple(round(d + (s - d) * alpha) for d, s in zip(dst, src))


def render(size: int) -> bytes:
    """Render one size as a PNG byte string (RGBA)."""
    pixels = bytearray()
    cx = cy = (size - 1) / 2
    ring_r = size * 0.30
    ring_w = max(1.2, size * 0.075)
    dot_r = size * 0.085
    corner = size * 0.22
    for y in range(size):
        pixels.append(0)  # PNG filter: none
        for x in range(size):
            # rounded-square background with transparent corners
            dx = max(corner - x, 0, x - (size - 1 - corner))
            dy = max(corner - y, 0, y - (size - 1 - corner))
            corner_dist = math.hypot(dx, dy)
            if corner_dist > corner:
                pixels += bytes((0, 0, 0, 0))
                continue
            r, g, b = BG
            dist = math.hypot(x - cx, y - cy)
            ring_alpha = 1.0 - min(1.0, abs(dist - ring_r) / (ring_w / 2))
            if ring_alpha > 0:
                r, g, b = _blend((r, g, b), RING, max(0.0, ring_alpha))
            if dist <= dot_r:
                r, g, b = DOT
            pixels += bytes((r, g, b, 255))
    return _png(size, size, bytes(pixels))


def _png(width: int, height: int, raw: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def build_ico(path: Path) -> None:
    images = [(size, render(size)) for size in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = b""
    offset = 6 + 16 * len(images)
    blobs = b""
    for size, png in images:
        dimension = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII",
            dimension, dimension, 0, 0, 1, 32, len(png), offset,
        )
        blobs += png
        offset += len(png)
    path.write_bytes(header + entries + blobs)


def main() -> int:
    target = Path(__file__).with_name("argus.ico")
    build_ico(target)
    print(f"wrote {target} ({target.stat().st_size:,} bytes, sizes {SIZES})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
