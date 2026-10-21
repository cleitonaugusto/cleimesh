#!/usr/bin/env python3
"""Generate the README images in docs/assets/, each in a dark and a light
variant (the README picks one with <picture> and prefers-color-scheme).

    python3 scripts/readme_images.py

- banner-{dark,light}.png: Kempelen's Turk (Racknitz, 1789; public domain,
  see docs/assets/source/README.md), the name and the one-line pitch.
- how-it-works-{dark,light}.png: delegation that only narrows, the token that
  becomes the sandbox, the receipt anyone can replay.
- where-it-fits-{dark,light}.png: agent sandboxes contain the agent process;
  CleiMesh decides and proves each tool call.
"""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "docs", "assets")
FONTS = os.path.join(ASSETS, "fonts")
ENGRAVING = os.path.join(ASSETS, "source", "racknitz-1789-turk.jpg")

THEMES = {
    "dark": dict(bg="#0f141b", grid="#18202b", ink="#efe6d2", mute="#9aa4b2", accent="#e0693f",
                 box="#161d27", edge="#3a4656", accent_fill="#2e1a14", engraving="#efe6d2"),
    "light": dict(bg="#f7f4ec", grid="#ebe4d3", ink="#16202e", mute="#5f6670", accent="#b5482a",
                  box="#ffffff", edge="#c4c8ce", accent_fill="#f6e3dc", engraving="#16202e"),
}


def font(weight, size):
    return ImageFont.truetype(os.path.join(FONTS, f"FiraSansCondensed-{weight}.ttf"), size)


def rgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


# ------------------------------------------------------------------ banner

def banner(theme):
    t = THEMES[theme]
    W, H = 2560, 760
    img = Image.new("RGB", (W, H), rgb(t["bg"]))
    d = ImageDraw.Draw(img)
    # a faint mesh, the "Mesh" in the name
    for x in range(0, W, 64):
        d.line([(x, 0), (x, H)], fill=rgb(t["grid"]), width=1)
    for y in range(0, H, 64):
        d.line([(0, y), (W, y)], fill=rgb(t["grid"]), width=1)

    g = ImageOps.autocontrast(Image.open(ENGRAVING).convert("L"), cutoff=2)
    if theme == "light":
        # the engraving's lines in ink, the paper made transparent, fading to the right
        h = H - 60
        g = g.resize((round(g.width * h / g.height), h), Image.LANCZOS)
        alpha = ImageOps.invert(g).point(lambda v: min(255, int(v * 1.25)))
        fade = Image.linear_gradient("L").rotate(90, expand=True).resize(g.size)
        fade = ImageOps.invert(fade).point(lambda v: 255 if v > 90 else int(v * 255 / 90))
        alpha = Image.composite(alpha, Image.new("L", g.size, 0), fade)
        img.paste(Image.new("RGB", g.size, rgb(t["engraving"])), (60, 30), alpha)
        right = 60 + g.width
    else:
        # a printed plate: ink on cream, framed, resting on the dark background
        h = H - 140
        g = g.resize((round(g.width * h / g.height), h), Image.LANCZOS)
        a_ = np.asarray(g, dtype=float)[..., None] / 255
        plate = (a_ * np.array(rgb("#f3ecdc")) + (1 - a_) * np.array(rgb("#1b2330"))).astype("uint8")
        plate = Image.fromarray(plate)
        pad = 18
        card = Image.new("RGB", (g.width + 2 * pad, g.height + 2 * pad), rgb("#f3ecdc"))
        card.paste(plate, (pad, pad))
        cx, cy = 90, (H - card.height) // 2
        shadow = Image.new("L", (W, H), 0)
        ImageDraw.Draw(shadow).rectangle([cx + 14, cy + 22, cx + card.width + 14, cy + card.height + 22], fill=170)
        shadow = shadow.filter(ImageFilter.GaussianBlur(22))
        img.paste(Image.new("RGB", (W, H), (0, 0, 0)), (0, 0), shadow)
        img.paste(card, (cx, cy))
        d = ImageDraw.Draw(img)
        d.rectangle([cx - 1, cy - 1, cx + card.width, cy + card.height], outline=rgb(t["accent"]), width=3)
        right = cx + card.width
    d = ImageDraw.Draw(img)

    x0 = right + 90
    d.text((x0, 150), "CleiMesh", font=font("SemiBold", 210), fill=rgb(t["ink"]))
    d.rectangle([x0 + 6, 405, x0 + 860, 417], fill=rgb(t["accent"]))
    d.text((x0, 450), "Signed permissions for AI agents", font=font("Regular", 66), fill=rgb(t["ink"]))
    d.text((x0, 530), "that the sandbox actually enforces.", font=font("Regular", 66), fill=rgb(t["ink"]))
    d.text((x0 + 4, 640), "D E L E G A T E   ·   C O N T A I N   ·   P R O V E", font=font("Medium", 34),
           fill=rgb(t["accent"]))
    paste_kempi(img, t, theme, center=(W - 330, H // 2), size=500)
    out = os.path.join(ASSETS, f"banner-{theme}.png")
    img.resize((1920, round(H * 1920 / W)), Image.LANCZOS).save(out, optimize=True)
    return out


def kempi_png(size):
    """The mascot rendered from its SVG (ImageMagick), transparent background."""
    import subprocess
    import tempfile
    svg = os.path.join(ASSETS, "mascot", "kempi.svg")
    with tempfile.NamedTemporaryFile(suffix=".png") as out:
        subprocess.run(["convert", "-background", "none", "-density", "384", svg, "-resize", f"{size}x{size}", out.name],
                       check=True)
        return Image.open(out.name).convert("RGBA").copy()


def paste_kempi(img, t, theme, center, size):
    """Kempi on a round badge, so its ink outlines read on the dark theme too."""
    cx, cy = center
    r = size // 2 + 34
    d = ImageDraw.Draw(img)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=rgb("#f3ecdc" if theme == "dark" else "#fffdf7"),
              outline=rgb(t["accent"]), width=8)
    k = kempi_png(size)
    img.paste(k, (cx - size // 2, cy - size // 2 + 6), k)


def social_preview():
    """1280 x 640, the image GitHub shows when the repository link is shared."""
    t = THEMES["dark"]
    W, H = 1280, 640
    img = Image.new("RGB", (W, H), rgb(t["bg"]))
    d = ImageDraw.Draw(img)
    for x in range(0, W, 48):
        d.line([(x, 0), (x, H)], fill=rgb(t["grid"]), width=1)
    for y in range(0, H, 48):
        d.line([(0, y), (W, y)], fill=rgb(t["grid"]), width=1)
    paste_kempi(img, t, "dark", center=(300, H // 2), size=380)
    x0 = 580
    d.text((x0, 150), "CleiMesh", font=font("SemiBold", 140), fill=rgb(t["ink"]))
    d.rectangle([x0 + 4, 322, x0 + 560, 330], fill=rgb(t["accent"]))
    d.text((x0, 360), "Signed permissions for AI agents", font=font("Regular", 44), fill=rgb(t["ink"]))
    d.text((x0, 414), "that the sandbox actually enforces.", font=font("Regular", 44), fill=rgb(t["ink"]))
    d.text((x0 + 2, 500), "D E L E G A T E   ·   C O N T A I N   ·   P R O V E", font=font("Medium", 24),
           fill=rgb(t["accent"]))
    out = os.path.join(ASSETS, "social-preview.png")
    img.save(out, optimize=True)
    return out


# ------------------------------------------------------------------ diagrams

def setup_fonts():
    for f in os.listdir(FONTS):
        if f.endswith(".ttf"):
            font_manager.fontManager.addfont(os.path.join(FONTS, f))
    plt.rcParams.update({"font.family": ["Fira Sans Condensed", "DejaVu Sans"], "svg.fonttype": "path"})


def canvas(w, h, t):
    f, ax = plt.subplots(figsize=(w / 10, h / 10))
    f.subplots_adjust(0, 0, 1, 1)
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.set_aspect("equal")
    ax.axis("off")
    f.patch.set_alpha(0)
    return f, ax


def box(ax, t, x, y, w, h, title, sub=None, kind="plain", size=15):
    face, edge = {"plain": (t["box"], t["edge"]), "accent": (t["accent_fill"], t["accent"]),
                  "ghost": ("none", t["edge"])}[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.6", fc=face, ec=edge,
                                lw=1.6, ls=(0, (5, 3)) if kind == "ghost" else "-", zorder=2))
    color = t["accent"] if kind == "accent" else t["ink"]
    if sub:
        ax.text(x + w / 2, y + h * 0.64, title, ha="center", va="center", fontsize=size, color=color,
                weight="semibold", zorder=3)
        ax.text(x + w / 2, y + h * 0.30, sub, ha="center", va="center", fontsize=size - 4, color=t["mute"],
                zorder=3, linespacing=1.2)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=size, color=color,
                weight="semibold", zorder=3)


def arrow(ax, t, a, b, label=None, color=None, loff=(0, 2.6), size=12, ls="-"):
    c = color or t["ink"]
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=16, color=c, lw=1.6, ls=ls,
                                 shrinkA=0, shrinkB=0, zorder=2.5))
    if label:
        ax.text((a[0] + b[0]) / 2 + loff[0], (a[1] + b[1]) / 2 + loff[1], label, ha="center", va="center",
                fontsize=size, color=c, zorder=4)


def save(f, name):
    out = os.path.join(ASSETS, name + ".png")
    f.savefig(out, dpi=200, transparent=True, bbox_inches="tight", pad_inches=0.15)
    plt.close(f)
    return out


def how_it_works(theme):
    t = THEMES[theme]
    f, ax = canvas(150, 62, t)
    # delegation: each hop can only narrow
    box(ax, t, 2, 40, 20, 13, "You", "sign the root token")
    box(ax, t, 34, 40, 20, 13, "Agent", "read ./project")
    box(ax, t, 66, 40, 20, 13, "Subagent", "read ./project/docs")
    arrow(ax, t, (22, 46.5), (33.6, 46.5), "token", loff=(0, 3.4), size=11)
    arrow(ax, t, (54, 46.5), (65.6, 46.5), "narrower,\noffline", loff=(0, 5.0), size=11)
    ax.text(45, 57, "every hop can only narrow", ha="center", fontsize=13, color=t["mute"], style="italic")
    # the node: chain → sandbox → receipt
    ax.add_patch(FancyBboxPatch((96, 4), 52, 52, boxstyle="round,pad=0,rounding_size=2", fc="none",
                                ec=t["accent"], lw=2.0, zorder=1))
    ax.text(122, 52, "CleiMesh node", ha="center", fontsize=16, color=t["accent"], weight="semibold")
    box(ax, t, 100, 36, 44, 11, "verify the chain", "signatures · only narrows · proof of possession", size=14)
    box(ax, t, 100, 21, 44, 11, "the token becomes the sandbox", "WebAssembly: only ./project/docs exists", "accent",
        size=14)
    box(ax, t, 100, 7, 44, 11, "signed receipt", "hash-chained · no receipt, no run", size=14)
    arrow(ax, t, (122, 36), (122, 32.2))
    arrow(ax, t, (122, 21), (122, 18.2))
    arrow(ax, t, (86, 46.5), (99.6, 42), "call +\nproof", loff=(0, 5.2), size=11)
    # afterwards
    box(ax, t, 34, 7, 54, 11, "Anyone with the log replays the call", "same input, frozen clock and seed → same output",
        "ghost", size=14)
    arrow(ax, t, (100, 12.5), (88.4, 12.5), color=t["mute"], ls=(0, (4, 3)))
    box(ax, t, 2, 7, 26, 11, "~/.ssh, other folders", "do not exist for the tool", "ghost", size=13)
    return save(f, f"how-it-works-{theme}")


def where_it_fits(theme):
    t = THEMES[theme]
    f, ax = canvas(150, 56, t)
    # the agent sandbox around the agent
    ax.add_patch(FancyBboxPatch((2, 4), 66, 46, boxstyle="round,pad=0,rounding_size=2", fc="none",
                                ec=t["edge"], lw=1.8, ls=(0, (6, 4)), zorder=1))
    ax.text(35, 45, "Agent sandbox", ha="center", fontsize=16, color=t["ink"], weight="semibold")
    ax.text(35, 40.5, "OpenShell · Strands Box · sandbox-runtime", ha="center", fontsize=12, color=t["mute"])
    box(ax, t, 8, 20, 26, 13, "Agent", "OpenClaw · Hermes ·\nClaude Code")
    box(ax, t, 40, 24, 24, 9, "its own shell", None, "ghost", size=13)
    box(ax, t, 40, 9, 24, 9, "its network", None, "ghost", size=13)
    arrow(ax, t, (34, 28.5), (39.6, 28.5))
    ax.text(35, 6.5, "contains the agent process, by local policy", ha="center", fontsize=12, color=t["mute"],
            style="italic")
    # CleiMesh, per tool call
    ax.add_patch(FancyBboxPatch((82, 4), 66, 46, boxstyle="round,pad=0,rounding_size=2", fc="none",
                                ec=t["accent"], lw=2.0, zorder=1))
    ax.text(115, 45, "CleiMesh", ha="center", fontsize=16, color=t["accent"], weight="semibold")
    ax.text(115, 40.5, "decides, delegates and proves each tool call", ha="center", fontsize=12, color=t["mute"])
    box(ax, t, 86, 24, 28, 11, "signed token", "narrows per subagent", size=14)
    box(ax, t, 118, 24, 26, 11, "WASM sandbox", "built from the token", "accent", size=14)
    box(ax, t, 100, 9, 34, 10, "signed, replayable receipt", "per subject, for LGPD", size=14)
    arrow(ax, t, (114, 29.5), (117.6, 29.5))
    arrow(ax, t, (131, 24), (125, 19.2))
    arrow(ax, t, (34, 21.5), (85.6, 25.5), "tools that touch\nyour data (MCP)", color=t["accent"], loff=(14.5, -6.2),
          size=11)
    return save(f, f"where-it-fits-{theme}")


if __name__ == "__main__":
    setup_fonts()
    for th in THEMES:
        for fn in (banner, how_it_works, where_it_fits):
            print(fn(th))
    print(social_preview())
