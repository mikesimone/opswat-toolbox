#!/usr/bin/env python3
"""Composes an obviously-absurd fake retail receipt, same purpose as the
Moon invoice: legible, printer-style, ridiculous content for AI/fraud
content-detection demos."""
from PIL import Image, ImageDraw, ImageFont

W = 600
F = "/usr/share/fonts/truetype/dejavu/"
mono = ImageFont.truetype(F + "DejaVuSansMono.ttf", 20)
mono_bold = ImageFont.truetype(F + "DejaVuSansMono-Bold.ttf", 22)
mono_small = ImageFont.truetype(F + "DejaVuSansMono.ttf", 16)

lines = []


def line(text="", font=mono, center=False):
    lines.append((text, font, center))


line("QUIK-MART #4092", mono_bold, True)
line("1 Rainbow Rd, Unicorn Meadow", mono_small, True)
line("Not a real store", mono_small, True)
line("-" * 34)
line(f"{'Item':<20}{'Qty':>4}{'Price':>10}")
line("-" * 34)
line(f"{'Unicorn tears (1 gal)':<20}{'1':>4}{'$999999.99':>10}")
line(f"{'Dragon scale, sm':<20}{'3':>4}{'$45000.00':>10}")
line(f"{'Gift card - Narnia':<20}{'1':>4}{'$250000.00':>10}")
line(f"{'Bag fee':<20}{'1':>4}{'$0.05':>10}")
line("-" * 34)
line(f"{'SUBTOTAL':<24}{'$1339045.04':>10}")
line(f"{'TAX (whimsy, 8%)':<24}{'$107123.60':>10}")
line(f"{'TOTAL':<24}{'$1446168.64':>10}", mono_bold)
line("-" * 34)
line("PAID - GIFT CARD ****9999")
line("")
line("THANK YOU FOR SHOPPING!")
line("")
line("*** SYNTHETIC DEMO RECEIPT ***", mono_small, True)
line("Fabricated for AI/fraud-detection", mono_small, True)
line("tool demos. Not a real transaction.", mono_small, True)

line_height = 26
H = 60 + line_height * len(lines) + 40
img = Image.new("RGB", (W, H), "white")
d = ImageDraw.Draw(img)

y = 40
for text, font, center in lines:
    if center:
        w = d.textlength(text, font=font)
        d.text(((W - w) / 2, y), text, font=font, fill="black")
    else:
        d.text((30, y), text, font=font, fill="black")
    y += line_height

img.save("/home/msimone/malwarecage/ai-generated-samples/AI-Generated-UnicornMeadowReceipt-FraudDemo.png")
print("saved")
