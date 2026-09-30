#!/usr/bin/env python3
"""Genera docs/banner.png: banner del repository (1280x640).

Dipendenze: solo Pillow. Font: Segoe UI Bold / Consolas di Windows,
con fallback su DejaVu se non ci sono.
"""
import math
import os
import sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1280, 640
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "banner.png")

CYAN = (86, 226, 245)
BLUE = (32, 90, 200)
DARK0 = (6, 10, 22)
DARK1 = (14, 26, 54)
DIM = (110, 140, 180)


def font(size, bold=True, mono=False):
    if mono:
        names = ["consolab.ttf", "CascadiaMono.ttf", "DejaVuSansMono-Bold.ttf"]
    else:
        names = ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold else [
            "segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"
        ]
    for n in names:
        for d in (r"C:\Windows\Fonts", "/usr/share/fonts/truetype/dejavu"):
            p = os.path.join(d, n)
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def gradient():
    img = Image.new("RGB", (W, H), DARK0)
    px = img.load()
    cx, cy = W * 0.22, H * 1.15
    maxd = math.hypot(max(cx, W - cx), max(cy, H - cy))
    for y in range(H):
        for x in range(0, W, 2):
            t = min(1.0, math.hypot(x - cx, y - cy) / maxd)
            r = int(DARK1[0] + (DARK0[0] - DARK1[0]) * t)
            g = int(DARK1[1] + (DARK0[1] - DARK1[1]) * t)
            b = int(DARK1[2] + (DARK0[2] - DARK1[2]) * t)
            px[x, y] = (r, g, b)
            if x + 1 < W:
                px[x + 1, y] = (r, g, b)
    return img


def main():
    img = gradient().convert("RGBA")
    # alone luminoso dietro al testo
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse([W * 0.04, H * 0.14, W * 0.84, H * 0.92],
                                fill=CYAN + (30,))
    img = Image.alpha_composite(img, glow.filter(ImageFilter.GaussianBlur(70)))
    d = ImageDraw.Draw(img, "RGBA")

    # radar: cerchi concentrici + sweep + punti
    ox, oy, R = W * 0.86, H * 0.50, 330
    for i, r in enumerate(range(60, R + 60, 54)):
        a = 62 - i * 8
        d.ellipse([ox - r, oy - r, ox + r, oy + r], outline=CYAN + (max(16, a),), width=2)
    for ang in range(0, 360, 30):
        a = math.radians(ang)
        d.line([ox, oy, ox + R * math.cos(a), oy + R * math.sin(a)],
               fill=CYAN + (14,), width=1)
    sweep = []
    for k in range(22):
        a = math.radians(-20 + k * 1.0)
        sweep.append((ox + R * math.cos(a), oy + R * math.sin(a)))
    d.polygon([(ox, oy)] + sweep, fill=CYAN + (11,))
    for k, dist in enumerate([130, 210, 95, 285, 170, 250]):
        a = math.radians(-150 + k * 44)
        x, y = ox + dist * math.cos(a), oy + dist * math.sin(a)
        s = 7 if k % 2 else 5
        d.ellipse([x - s, y - s, x + s, y + s], fill=CYAN + (235,))
        d.ellipse([x - 14, y - 14, x + 14, y + 14], outline=CYAN + (55,), width=1)
    d.ellipse([ox - 5, oy - 5, ox + 5, oy + 5], fill=(255, 255, 255, 220))

    # testo
    f = font(124)
    tw = d.textbbox((0, 0), "BLUESNIFF", font=f)
    x0 = 76
    ty = H // 2 - (tw[3] - tw[1]) // 2 - 40
    sh = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(sh).text((x0 + 4, ty + 6), "BLUESNIFF", font=f, fill=(0, 0, 0, 170))
    img = Image.alpha_composite(img, sh.filter(ImageFilter.GaussianBlur(6)))
    d = ImageDraw.Draw(img, "RGBA")
    d.text((x0, ty), "BLUESNIFF", font=f, fill=(255, 255, 255, 255), stroke_width=2,
           stroke_fill=BLUE + (255,))

    # linea d'accento + sottotitolo
    fs = font(28, bold=False, mono=True)
    sub = "Bluetooth LE scanner  ·  web dashboard  ·  v0.1.0"
    d.rectangle([x0 + 2, ty + 168, x0 + 132, ty + 174], fill=CYAN + (255,))
    d.text((x0 + 2, ty + 196), sub, font=fs, fill=DIM + (255,))
    d.text((x0 + 2, ty + 246), "Rust  ·  nessuna dipendenza  ·  Windows",
           font=font(24, bold=False), fill=(90, 115, 150, 255))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.convert("RGB").save(OUT, "PNG", optimize=True)
    print("scritto", OUT, os.path.getsize(OUT), "byte")


if __name__ == "__main__":
    sys.exit(main())