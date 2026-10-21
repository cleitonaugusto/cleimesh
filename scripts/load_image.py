#!/usr/bin/env python3
"""Draws the load test (R12) as a mosaic of its receipts: one square per
signed receipt of a real run, in log order, coloured by what the node
decided. Nothing is simulated in the picture; it is the log.

    LOAD_AGENTS=5000 LOAD_CLIENTS=167 LOAD_KEEP=/tmp/load \\
      cargo test -p cleimesh-p2p --release --test load -- --ignored --nocapture
    python3 scripts/load_image.py /tmp/load     # -> docs/assets/load-{light,dark}.png
"""
import json, math, pathlib, sys
from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = ROOT / "docs/assets/fonts"
W, H = 1600, 900

THEMES = {
    "light": {"bg": "#f3ecdc", "ink": "#16202e", "muted": "#5b7088", "decision": "#c3ccd6", "result": "#a3b1c0",
              "taint": "#b5482a", "replay": "#7a3b69", "widen": "#d9822b", "sandbox": "#c9a227"},
    "dark": {"bg": "#0f1620", "ink": "#f3ecdc", "muted": "#9fb0c3", "decision": "#26313f", "result": "#334356",
             "taint": "#e0623f", "replay": "#b45fa0", "widen": "#f0a050", "sandbox": "#e8c46a"},
}
LEGEND = [
    ("taint", "refused: wrote after reading a mail with an injection"),
    ("replay", "refused: replayed a proof of possession"),
    ("widen", "refused: a delegated token wider than its parent"),
    ("sandbox", "read outside the grant: the sandbox had no such file"),
    ("result", "allowed and ran"),
]


def kind(entry):
    p = entry["params"]
    if entry["action_id"] == "cleimesh.tool_result":
        return "result" if entry.get("success") else "sandbox"
    if p.get("decision") == "denied":
        reason = p.get("denial", "")
        if "untrusted content" in reason:
            return "taint"
        if "replayed" in reason:
            return "replay"
        if "not granted by the parent" in reason:
            return "widen"
        return "taint"
    return "decision"


def font(weight, size):
    return ImageFont.truetype(str(FONTS / f"FiraSansCondensed-{weight}.ttf"), size)


def draw(entries, summary, theme, out):
    t = THEMES[theme]
    img = Image.new("RGB", (W, H), t["bg"])
    d = ImageDraw.Draw(img)

    # The mosaic, right side.
    left, top, right, bottom = 680, 60, W - 60, H - 110
    n = len(entries)
    area = (right - left) * (bottom - top)
    cell = max(2, int(math.sqrt(area / n)))
    cols = (right - left) // cell
    for i, e in enumerate(entries):
        x, y = left + (i % cols) * cell, top + (i // cols) * cell
        d.rectangle([x, y, x + cell - 2, y + cell - 2], fill=t[kind(e)])

    # The numbers, left side.
    x = 60
    d.text((x, 60), f"{summary['agents']:,} AI agents", font=font("Bold", 64), fill=t["ink"])
    d.text((x, 132), "at once, against one node", font=font("Medium", 34), fill=t["muted"])
    d.text((x, 215), f"{summary['escapes']}", font=font("Bold", 150), fill=t["taint"])
    d.text((x + 120, 262), "escapes", font=font("SemiBold", 52), fill=t["ink"])
    d.text((x, 392), f"{summary['receipts']:,} signed receipts,", font=font("SemiBold", 36), fill=t["ink"])
    d.text((x, 434), "all verified", font=font("SemiBold", 36), fill=t["ink"])
    d.text((x, 498), f"{summary['calls']:,} calls in {summary['seconds']:.0f} s on a laptop", font=font("Regular", 28), fill=t["muted"])
    if summary.get("lost"):
        d.text((x, 534), f"{summary['lost']:,} more timed out in the queue; none got through", font=font("Regular", 22), fill=t["muted"])

    y = 600
    for k, label in LEGEND:
        d.rectangle([x, y + 6, x + 18, y + 24], fill=t[k])
        d.text((x + 30, y), label, font=font("Regular", 22), fill=t["ink"])
        y += 36

    d.text((60, H - 70), "Every square is one receipt of a real run, in log order. "
           "Reproduce: LOAD_AGENTS=5000 cargo test -p cleimesh-p2p --release --test load -- --ignored",
           font=font("Regular", 20), fill=t["muted"])
    img.save(out, optimize=True)
    print("wrote", out)


def main():
    run = pathlib.Path(sys.argv[1])
    entries = [json.loads(l) for l in (run / "receipts.jsonl").read_text().splitlines() if l.strip()]
    summary = json.loads((run / "summary.json").read_text())
    for theme in THEMES:
        draw(entries, summary, theme, ROOT / f"docs/assets/load-{theme}.png")


main()
