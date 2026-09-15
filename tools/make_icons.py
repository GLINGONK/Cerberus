"""Generate the application icons.

Written as a script rather than committing binaries so the icon is reproducible
and reviewable. Pure stdlib: no Pillow, no external tooling.

Draws a rounded shield with a keyhole, in the application's accent colours.
"""

import math
import pathlib
import struct
import zlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "app" / "src-tauri" / "icons"

BG_TOP = (99, 102, 241)      # indigo
BG_BOTTOM = (14, 165, 233)   # sky
FG = (11, 13, 18)            # near-black keyhole


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


HALF_WIDTH = 0.74      # shield half-width at its widest
SHOULDER = 0.10        # y at which the sides stop being parallel
TOP = -0.86            # y of the shield's top edge
TIP = 0.94             # y of the shield's bottom point
CORNER = 0.20          # top corner radius


def sd_round_box(px, py, hx, hy, r):
    """Signed distance to a rounded box centred on the origin. Negative inside."""
    dx = abs(px) - (hx - r)
    dy = abs(py) - (hy - r)
    outside = math.hypot(max(dx, 0.0), max(dy, 0.0))
    inside = min(max(dx, dy), 0.0)
    return outside + inside - r


def shield_distance(nx, ny):
    """Signed distance to the shield outline. Negative inside.

    Two pieces meeting exactly at the shoulder: above it, straight sides with
    rounded *top* corners only; below it, an elliptical taper to the tip. The
    ellipse is exactly HALF_WIDTH wide at the shoulder, so the seam is invisible.
    Rounding the box's bottom corners too would leave a notch there.
    """
    if ny <= SHOULDER:
        dx = abs(nx) - (HALF_WIDTH - CORNER)
        dy = (TOP + CORNER) - ny
        if dx > 0 and dy > 0:
            return math.hypot(dx, dy) - CORNER
        return max(abs(nx) - HALF_WIDTH, TOP - ny)

    # Lower body: elliptical taper. An ellipse rather than a straight triangle
    # gives the slightly concave flanks that read as a shield, not an arrowhead.
    t = (ny - SHOULDER) / (TIP - SHOULDER)
    if t > 1.0:
        return math.hypot(nx, ny - TIP)
    return abs(nx) - HALF_WIDTH * math.sqrt(max(0.0, 1.0 - t * t))


def coverage(dist, size):
    """Antialiased coverage from a signed distance, over roughly one pixel."""
    aa = 2.0 / size
    return max(0.0, min(1.0, 0.5 - dist / aa))


def rounded_shield(x, y, size):
    nx = (x / size) * 2 - 1
    ny = (y / size) * 2 - 1
    return coverage(shield_distance(nx, ny), size)


def keyhole(x, y, size):
    """Coverage of the keyhole cut-out, 0..1."""
    nx = (x / size) * 2 - 1
    ny = (y / size) * 2 - 1

    # Circular bow.
    bow = math.hypot(nx, ny + 0.16) - 0.21

    # Blade below it, flaring slightly towards the bottom.
    blade_top, blade_bottom = -0.16, 0.36
    t = (ny - blade_top) / (blade_bottom - blade_top)
    half = 0.075 + 0.055 * max(0.0, min(1.0, t))
    blade = sd_round_box(
        nx,
        ny - (blade_top + blade_bottom) / 2,
        half,
        (blade_bottom - blade_top) / 2,
        0.03,
    )

    return coverage(min(bow, blade), size)


def render(size):
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            shield = rounded_shield(x + 0.5, y + 0.5, size)
            if shield <= 0:
                row += bytes((0, 0, 0, 0))
                continue
            base = lerp(BG_TOP, BG_BOTTOM, y / max(size - 1, 1))
            hole = keyhole(x + 0.5, y + 0.5, size)
            colour = lerp(base, FG, hole)
            row += bytes((*colour, round(255 * shield)))
        rows.append(bytes(row))
    return rows


def png_bytes(rows, size):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico_bytes(pngs):
    """Pack PNGs into an ICO. Windows Vista and later accept PNG-compressed entries."""
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries, blobs = b"", b""
    for size, data in pngs:
        entries += struct.pack(
            "<BBBBHHII",
            0 if size >= 256 else size,
            0 if size >= 256 else size,
            0, 0, 1, 32,
            len(data), offset,
        )
        blobs += data
        offset += len(data)
    return header + entries + blobs


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    generated = {}
    for size in (32, 64, 128, 256, 512):
        generated[size] = png_bytes(render(size), size)

    (OUT / "32x32.png").write_bytes(generated[32])
    (OUT / "128x128.png").write_bytes(generated[128])
    (OUT / "128x128@2x.png").write_bytes(generated[256])
    (OUT / "icon.png").write_bytes(generated[512])
    (OUT / "icon.ico").write_bytes(
        ico_bytes([(s, generated[s]) for s in (32, 64, 128, 256)])
    )

    for f in sorted(OUT.iterdir()):
        print(f"{f.name:<18} {f.stat().st_size:>7} bytes")


if __name__ == "__main__":
    main()
