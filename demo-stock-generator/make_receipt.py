#!/usr/bin/env python3
"""Composes an obviously-absurd fake retail receipt - photographed-on-a-desk
style, ridiculous content - for AI/fraud content-detection demos.

v3 (2026-07-27): the original was a narrow 600px flat-white monospace
thermal-receipt mockup, and even a full-page white-background reformat
(v2, same layout family as make_invoice.py) topped out at "Uncertain"
(~45-69% on OPSWAT's detect_image feature, need 70+ for "Detected").
Root cause: OPSWAT AI Content Inspector's image-classification ensemble
(cnn/multistream/image_xgb/synthid/etc, aggregated into `detect_image`)
scores actual pixel/noise statistics - a flat PIL-rendered canvas with pure
white background has none of the sensor noise / compression texture a real
(or diffusion-generated) photo has, so it scores low almost regardless of
layout. This version renders the receipt text onto a small canvas, then
composites it onto a genuine ComfyUI diffusion photo (blank paper on a
wooden desk) at the paper's location - the same "genuinely diffusion-model
pixel statistics" property that made AI-Generated-ToyCarAccident (pure
diffusion output, no text) score 97% on detect_image. Confirmed by testing:
pure-white-bg version scored 69.51% (just under threshold); this composited
version scored 83.25% and crossed into a full "Detected" verdict.

Separately, `detect_fraud` (a CLIP zero-shot classifier scored against a
fixed 6-category list: Car Accident / Fake Bank Statement / Fake ID / House
Damage / Invoice or Payment Scam / Medical-Healthcare) only fires reliably
once detect_image's own score is high enough for the pipeline to bother
running it - see AI-Generated-MoonInvoice-FraudDemo (full-page corporate
invoice layout, "Bill To" framing) for a sample that trips both features
at once. A "receipt" for an already-COMPLETED purchase doesn't match any
of those 6 fraud categories well regardless of formatting (tested: swapping
"PAID" for "BALANCE DUE - PAY IMMEDIATELY" moved the needle by <5%) - the
category list is about payment demands/claims, not completed transactions.
That's a real, useful thing to know for future samples: match the category
list's actual semantics (a pending claim or payment demand), not just
"make it look official".

Requires ComfyUI running locally (see comfy_gen.py) to generate the desk
background photo; falls back to a small procedural wood-grain gradient (no
real diffusion pixel statistics, won't score nearly as high) if ComfyUI is
unreachable, so the script still produces *something* for offline dev.
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).parent))
import comfy_gen  # noqa: E402

OUT_PATH = "/home/msimone/malwarecage/ai-generated-samples/AI-Generated-UnicornMeadowReceipt-FraudDemo.png"
BG_CACHE = Path("/home/msimone/malwarecage/_generators/.cache-receipt-bg.png")
SCALE = 3


def get_background() -> Image.Image:
    if BG_CACHE.exists():
        return Image.open(BG_CACHE).convert("RGB")

    try:
        comfy_gen.generate(
            ckpt="Juggernaut-XL_v9_RunDiffusionPhoto_v2.safetensors",
            positive=(
                "a single blank white sheet of receipt paper lying flat on a "
                "wooden desk, top-down flat lay photography, minimal, no "
                "folds, no envelope, photorealistic, soft natural light"
            ),
            negative=(
                "envelope, folded, curled, text, writing, numbers, letters, "
                "watermark, blurry, low quality, multiple sheets"
            ),
            width=896,
            height=1152,
            seed=7,
            out_path=str(BG_CACHE),
        )
        return Image.open(BG_CACHE).convert("RGB")
    except Exception as exc:  # noqa: BLE001 - ComfyUI down/unreachable, degrade gracefully
        print(f"[warn] ComfyUI generation failed ({exc}); using flat placeholder background. "
              "detect_image score will be much lower without real diffusion pixel statistics.",
              file=sys.stderr)
        return Image.new("RGB", (896, 1152), (168, 122, 78))


def paper_bbox(bg: Image.Image) -> tuple[int, int, int, int]:
    """Find the light, low-saturation paper rectangle in the desk photo."""
    import numpy as np

    arr = np.array(bg).astype(int)
    r, g, b = arr[..., 0], arr[..., 1], arr[..., 2]
    brightness = (r + g + b) / 3
    sat = arr.max(axis=2) - arr.min(axis=2)
    mask = (brightness > 150) & (sat < 40)
    ys, xs = np.where(mask)

    if xs.size == 0 or ys.size == 0:
        # Fallback: centered rectangle covering ~70% width, ~60% height.
        w, h = bg.size
        return (int(w * 0.15), int(h * 0.2), int(w * 0.85), int(h * 0.8))

    return int(xs.min()), int(ys.min()), int(xs.max()), int(ys.max())


def right_text(d, xy_right, y, text, font, fill="black"):
    w = d.textlength(text, font=font)
    d.text((xy_right - w, y), text, font=font, fill=fill)


def render_content(paper_w: int, paper_h: int) -> Image.Image:
    content = Image.new("RGB", (paper_w, paper_h), (250, 249, 246))
    d = ImageDraw.Draw(content)

    F = "/usr/share/fonts/truetype/dejavu/"
    title_font = ImageFont.truetype(F + "DejaVuSerif-Bold.ttf", 60)
    h2_font = ImageFont.truetype(F + "DejaVuSerif-Bold.ttf", 34)
    body_font = ImageFont.truetype(F + "DejaVuSans.ttf", 26)
    body_bold = ImageFont.truetype(F + "DejaVuSans-Bold.ttf", 26)
    small_font = ImageFont.truetype(F + "DejaVuSans.ttf", 19)

    margin = 45
    right_edge = paper_w - margin
    y = 50

    d.text((margin, y), "QUIK-MART #4092", font=title_font, fill="black")
    y += 78
    d.text((margin, y), "1 Rainbow Rd, Unicorn Meadow", font=small_font, fill=(70, 70, 70))
    y += 28
    d.text((margin, y), "receipts@quikmart.example | Not a real store", font=small_font, fill=(70, 70, 70))
    y += 46

    d.line([(margin, y), (right_edge, y)], fill="black", width=2)
    y += 34
    d.text((margin, y), "RECEIPT", font=h2_font, fill="black")
    y += 46
    right_text(d, right_edge, y, "Txn #: QM-000004092", body_font)
    d.text((margin, y), "Customer: Walk-in", font=body_bold, fill="black")
    y += 36
    d.text((margin, y), "Register 3, Cashier: N. Sparkle", font=body_font, fill="black")
    y += 30
    d.text((margin, y), "Date: 2026-07-27", font=body_font, fill="black")
    y += 46

    d.rectangle([(margin, y), (right_edge, y + 40)], fill="#222222")
    d.text((margin + 10, y + 7), "Item", font=body_bold, fill="white")
    right_text(d, right_edge - 10, y + 7, "Amount", body_bold, fill="white")
    y += 40

    items = [
        ("Unicorn tears (1 gal)", "$999,999.99"),
        ("Dragon scale, sm x3", "$135,000.00"),
        ("Gift card - Narnia", "$250,000.00"),
        ("Bag fee", "$0.05"),
    ]
    for desc, total in items:
        d.text((margin + 8, y + 5), desc, font=body_font, fill="black")
        right_text(d, right_edge - 8, y + 5, total, body_font)
        y += 38
        d.line([(margin, y), (right_edge, y)], fill=(150, 150, 150), width=1)

    y += 20
    d.line([(margin, y), (right_edge, y)], fill="black", width=2)
    y += 18
    d.text((margin, y), "SUBTOTAL:", font=body_bold, fill="black")
    right_text(d, right_edge, y + 2, "$1,385,000.04", body_bold)
    y += 34
    d.text((margin, y), "TAX (whimsy, 8%):", font=body_bold, fill="black")
    right_text(d, right_edge, y + 2, "$110,800.00", body_bold)
    y += 34
    d.text((margin, y), "TOTAL:", font=h2_font, fill="black")
    right_text(d, right_edge, y + 2, "$1,495,800.04", body_bold)
    y += 44
    d.text((margin, y), "PAID - GIFT CARD ****9999", font=body_font, fill="black")
    y += 50

    d.rectangle([(margin, y), (right_edge, y + 100)], outline="black", width=2)
    d.text((margin + 14, y + 10), "RETURN POLICY:", font=body_bold, fill="black")
    d.text((margin + 14, y + 40), "No returns on enchanted or", font=small_font, fill="black")
    d.text((margin + 14, y + 62), "interdimensional items. Thanks!", font=small_font, fill="black")
    y += 122

    d.text((margin, paper_h - 80), "Synthetic demo artifact - AI/fraud-detection", font=small_font, fill=(110, 110, 110))
    d.text((margin, paper_h - 58), "tool testing. Not a real store/transaction.", font=small_font, fill=(110, 110, 110))

    return content


def main() -> None:
    bg = get_background()
    bg_up = bg.resize((bg.width * SCALE, bg.height * SCALE), Image.LANCZOS)

    px0, py0, px1, py1 = paper_bbox(bg)
    box = (px0 * SCALE, py0 * SCALE, px1 * SCALE, py1 * SCALE)
    paper_w, paper_h = box[2] - box[0], box[3] - box[1]

    content = render_content(paper_w, paper_h)

    final = bg_up.copy()
    final.paste(content, (box[0], box[1]))
    final = final.resize((final.width // SCALE, final.height // SCALE), Image.LANCZOS)
    final.save(OUT_PATH)
    print(f"saved -> {OUT_PATH} ({final.size[0]}x{final.size[1]})")


if __name__ == "__main__":
    main()
