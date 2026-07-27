#!/usr/bin/env python3
"""Composes an obviously-absurd fake invoice - clean, legible, professional
layout, ridiculous content - for demoing an AI/fraud-content-detection tool
without producing anything resembling a usable fraud instrument."""
from PIL import Image, ImageDraw, ImageFont

W, H = 1275, 1650  # roughly US Letter at 150dpi
img = Image.new("RGB", (W, H), "white")
d = ImageDraw.Draw(img)


def right_text(xy_right, y, text, font, fill="black"):
    w = d.textlength(text, font=font)
    d.text((xy_right - w, y), text, font=font, fill=fill)


F = "/usr/share/fonts/truetype/dejavu/"
title_font = ImageFont.truetype(F + "DejaVuSerif-Bold.ttf", 54)
h2_font = ImageFont.truetype(F + "DejaVuSerif-Bold.ttf", 30)
body_font = ImageFont.truetype(F + "DejaVuSans.ttf", 24)
body_bold = ImageFont.truetype(F + "DejaVuSans-Bold.ttf", 24)
small_font = ImageFont.truetype(F + "DejaVuSans.ttf", 18)

margin = 90
right_edge = W - margin
y = 80

d.text((margin, y), "LUNACORP ORBITAL LOGISTICS", font=title_font, fill="black")
y += 70
d.text((margin, y), "1 Tranquility Base, Sea of Serenity", font=small_font, fill="gray")
y += 26
d.text((margin, y), "invoicing@lunacorp.example  |  Not a real company", font=small_font, fill="gray")
y += 60

d.line([(margin, y), (right_edge, y)], fill="black", width=2)
y += 40

d.text((margin, y), "INVOICE", font=h2_font, fill="black")
right_text(right_edge, y, "Invoice #: LC-000000001", body_font)
y += 44
d.text((margin, y), "Bill To:  The Moon", font=body_bold, fill="black")
right_text(right_edge, y, "Date: 2026-07-27", body_font)
y += 34
d.text((margin, y), "Attn: The Man in the Moon", font=body_font, fill="black")
y += 34
d.text((margin, y), "c/o Sea of Tranquility, Luna", font=body_font, fill="black")
y += 60

d.rectangle([(margin, y), (right_edge, y + 40)], fill="#222222")
d.text((margin + 10, y + 8), "Description", font=body_bold, fill="white")
right_text(right_edge - 10, y + 8, "Amount", body_bold, fill="white")
y += 40

items = [
    ("Orbital delivery surcharge (Moon zone), qty 1", "$250,000,000,000,000.00"),
    ("Green cheese sample extraction fee, qty 1", "$400,000,000,000,000.00"),
    ("Flag re-planting service, qty 12 @ $25T", "$300,000,000,000,000.00"),
    ("Zero-gravity handling fee, qty 1", "$50,000,000,000,000.00"),
]

for desc, total in items:
    d.text((margin + 10, y + 6), desc, font=body_font, fill="black")
    right_text(right_edge - 10, y + 6, total, body_font)
    y += 42
    d.line([(margin, y), (right_edge, y)], fill="#dddddd", width=1)

y += 30
d.line([(margin, y), (right_edge, y)], fill="black", width=2)
y += 20
d.text((margin, y), "AMOUNT DUE:", font=h2_font, fill="black")
right_text(right_edge, y + 4, "$1,000,000,000,000,000.00", body_bold)
y += 70

d.rectangle([(margin, y), (right_edge, y + 90)], outline="black", width=2)
d.text((margin + 20, y + 15), "PAYMENT TERMS:", font=body_bold, fill="black")
d.text((margin + 20, y + 50), "Due upon receipt. Late payments subject to gravitational penalty.", font=body_font, fill="black")
y += 130

d.text((margin, H - 100), "This invoice is an obviously fictitious demo artifact - synthetic content generated", font=small_font, fill="gray")
d.text((margin, H - 75), "for testing AI/fraud-content-detection tooling. Not a real business. Not a real debt.", font=small_font, fill="gray")

img.save("/home/msimone/malwarecage/ai-generated-samples/AI-Generated-MoonInvoice-FraudDemo.png")
print("saved")
