#!/usr/bin/env python3
"""Fetches the two parts of demo-stock that can't live in this repo directly:

  1. Real, curated malware samples (specific known-hash MalwareBazaar
     downloads) - opswat-toolbox is a PUBLIC repo, and committing real
     malware to a public repo runs into GitHub's malware/acceptable-use
     policies regardless of the password-protected-zip mitigation. The
     repo's own .gitignore already excludes malwarecage/*.zip for exactly
     this reason - this script re-fetches the SAME curated samples (fixed
     hashes below, not random ones) so everyone gets the identical stock.

  2. The L3i/ICDAR 2023 "Find it again!" receipt-forgery research dataset
     (~674MB zip, ~1GB extracted, ~1,977 files) - not a malware/policy
     issue, just too large to reasonably commit to git (permanently bloats
     every future clone).

Safe to re-run: skips anything already present. Requires MALWAREBAZAAR_API_KEY
in the environment for part 1 (see ~/Environment/hosts/.<hostname> on Six, or
get a free key from bazaar.abuse.ch and export it yourself).
"""
import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

DEMO_STOCK_DIR = Path(__file__).parent.parent / "demo-stock"
STEGANOGRAPHY_DIR = DEMO_STOCK_DIR / "steganography"
FINDIT2_DIR = DEMO_STOCK_DIR / "findit2-benchmark"

MB_API = "https://mb-api.abuse.ch/api/v1/"

# The exact curated set picked 2026-07-27 - see demo-stock/README.md for what
# each one is and why. Original MalwareBazaar SHA256 hashes, not this
# script's output filenames.
CURATED_SAMPLES = [
    ("d6c42166e11a471b6c38d717461f566a183d5e1cd0264f84ec85a1ffedb1db84", "Stego-ZIP-SteganoAmor-Receipt-Lure.zip"),
    ("fd2b36e1b27cd6c92386078e92c5287e770fa55fabd78a4522b910381d453c11", "Stego-PNG-ParallaxRAT-ImgurHosted.zip"),
    ("554401e1eb3654d011c42fb6f2c71e99e6ac8d6194d1087769a4b789db2f3f8c", "Stego-PNG-IcedID-Loader.zip"),
    ("523774fc29fdf6520bb3f0213d474d9909e63bcd44bfbafb57037eb26d19b6e5", "Stego-EXE-DotNet-Steganography.zip"),
    ("54c3c13b6bd236bab7971c6635866b4ca335727e6f96f66491edabae3cbc65cd", "Stego-PDF-EmbeddedXLS-PaymentReceipt-AgentTesla.zip"),
    ("5e303fd9317236b55429aedd5c7aa133f3ea9dd2a50402930c50c5fbcc6e27e6", "Stego-PDF-CVE-2017-11882-SwiftCopy-XLoader.zip"),
]

FINDIT2_URL = "https://l3i-share.univ-lr.fr/2023Finditagain/findit2.zip"


def fetch_malware_samples():
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if not api_key:
        print("MALWAREBAZAAR_API_KEY not set - skipping real malware samples. "
              "Get a free key at bazaar.abuse.ch and export it to run this part.",
              file=sys.stderr)
        return

    STEGANOGRAPHY_DIR.mkdir(exist_ok=True)
    for sha256, filename in CURATED_SAMPLES:
        out_path = STEGANOGRAPHY_DIR / filename
        if out_path.exists():
            print(f"[steganography] already have {filename}, skipping")
            continue

        req = urllib.request.Request(
            MB_API, method="POST",
            data=f"query=get_file&sha256_hash={sha256}".encode(),
            headers={"Auth-Key": api_key},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read()

        if content[:2] != b"PK":
            try:
                detail = json.loads(content).get("query_status", content[:200])
            except ValueError:
                detail = content[:200]
            print(f"[steganography] FAILED for {filename} ({sha256}): {detail}", file=sys.stderr)
            continue

        out_path.write_bytes(content)
        print(f"[steganography] fetched {filename} ({len(content)} bytes)")


def fetch_findit2():
    if FINDIT2_DIR.exists() and any(FINDIT2_DIR.iterdir()):
        print("[findit2-benchmark] already present, skipping")
        return

    tmp_zip = DEMO_STOCK_DIR / "findit2.zip.tmp"
    print(f"[findit2-benchmark] downloading from {FINDIT2_URL} (~674MB, this takes a while)...")
    urllib.request.urlretrieve(FINDIT2_URL, tmp_zip)

    print("[findit2-benchmark] extracting...")
    FINDIT2_DIR.mkdir(exist_ok=True)
    with zipfile.ZipFile(tmp_zip) as z:
        bad = z.testzip()
        if bad is not None:
            raise RuntimeError(f"downloaded zip is corrupt at member {bad}, try again")
        z.extractall(FINDIT2_DIR)

    # Strip macOS resource-fork junk that the source zip carries.
    macosx_dir = FINDIT2_DIR / "__MACOSX"
    if macosx_dir.exists():
        import shutil
        shutil.rmtree(macosx_dir)

    tmp_zip.unlink()
    print("[findit2-benchmark] done")


if __name__ == "__main__":
    fetch_malware_samples()
    fetch_findit2()
