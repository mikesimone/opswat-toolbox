#!/usr/bin/env python3
"""Simple LSB (least-significant-bit) steganography: hides a benign text
message inside the low bits of an image's pixel data. Purely benign - the
payload is plain text, no executable content - demonstrating the general
"data hidden in an innocuous-looking image" technique."""
import sys
from PIL import Image

MAGIC = b"STEG"  # marker so the extractor knows where the real payload starts/ends


def embed(in_path, out_path, message: bytes):
    img = Image.open(in_path).convert("RGB")
    pixels = bytearray(img.tobytes())

    payload = MAGIC + len(message).to_bytes(4, "big") + message
    bits = "".join(f"{byte:08b}" for byte in payload)

    if len(bits) > len(pixels):
        raise ValueError("message too long for this image")

    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & 0xFE) | int(bit)

    out = Image.frombytes("RGB", img.size, bytes(pixels))
    out.save(out_path)


def extract(path) -> bytes:
    img = Image.open(path).convert("RGB")
    pixels = img.tobytes()

    bit_str = "".join(str(b & 1) for b in pixels[: (4 + 4) * 8])
    header_bytes = bytes(int(bit_str[i:i + 8], 2) for i in range(0, len(bit_str), 8))
    if header_bytes[:4] != MAGIC:
        raise ValueError("no STEG marker found")
    msg_len = int.from_bytes(header_bytes[4:8], "big")

    total_bits_needed = (4 + 4 + msg_len) * 8
    bit_str = "".join(str(b & 1) for b in pixels[:total_bits_needed])
    all_bytes = bytes(int(bit_str[i:i + 8], 2) for i in range(0, len(bit_str), 8))
    return all_bytes[8:8 + msg_len]


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "embed":
        embed(sys.argv[2], sys.argv[3], sys.argv[4].encode())
    elif mode == "extract":
        print(extract(sys.argv[2]).decode())
