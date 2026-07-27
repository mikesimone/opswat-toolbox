#!/usr/bin/env python3
"""Fetches the two parts of demo-stock that can't live in this repo directly:

  1. Real, curated malware samples (specific known-hash MalwareBazaar
     downloads) - opswat-toolbox is a PUBLIC repo, and committing real
     malware to a public repo runs into GitHub's malware/acceptable-use
     policies regardless of the password-protected-zip mitigation. This
     script re-fetches the SAME curated samples (fixed hashes below, not
     random ones) so everyone gets the identical stock.

  2. The L3i/ICDAR 2023 "Find it again!" receipt-forgery research dataset
     (~674MB zip, ~1GB extracted, ~1,977 files) - not a malware/policy
     issue, just too large to reasonably commit to git (permanently bloats
     every future clone).

Both land in ~/malwarecage by default (override with --dest), matching
opswat-scan-files' own DEFAULT_SCAN_DIR - **not** inside this repo's working
tree. That's deliberate, not just a naming choice: ~/malwarecage is the
directory real malware samples are supposed to be excluded from AV/EDR
scanning on (e.g. Six's Cisco Secure Endpoint path exclusion, see
Infrastructure/sixofone.md in the Environment repo) - a git checkout of
opswat-toolbox has no such exclusion, so downloading real malware into
demo-stock/ itself would sit unprotected. Set up that same exclusion for
wherever --dest points on your own machine before running this.

Safe to re-run: skips anything already present. Requires MALWAREBAZAAR_API_KEY
in the environment for part 1 (see ~/Environment/hosts/.<hostname> on Six, or
get a free key from bazaar.abuse.ch and export it yourself).
"""
import argparse
import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

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


def fetch_malware_samples(dest: Path):
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if not api_key:
        print("MALWAREBAZAAR_API_KEY not set - skipping real malware samples. "
              "Get a free key at bazaar.abuse.ch and export it to run this part.",
              file=sys.stderr)
        return

    steganography_dir = dest / "steganography"
    steganography_dir.mkdir(parents=True, exist_ok=True)
    for sha256, filename in CURATED_SAMPLES:
        out_path = steganography_dir / filename
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


def fetch_findit2(dest: Path):
    findit2_dir = dest / "findit2-benchmark"
    if findit2_dir.exists() and any(findit2_dir.iterdir()):
        print("[findit2-benchmark] already present, skipping")
        return

    tmp_zip = dest / "findit2.zip.tmp"
    dest.mkdir(parents=True, exist_ok=True)
    print(f"[findit2-benchmark] downloading from {FINDIT2_URL} (~674MB, this takes a while)...")
    urllib.request.urlretrieve(FINDIT2_URL, tmp_zip)

    print("[findit2-benchmark] extracting...")
    findit2_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(tmp_zip) as z:
        bad = z.testzip()
        if bad is not None:
            raise RuntimeError(f"downloaded zip is corrupt at member {bad}, try again")
        z.extractall(findit2_dir)

    # Strip macOS resource-fork junk that the source zip carries.
    macosx_dir = findit2_dir / "__MACOSX"
    if macosx_dir.exists():
        import shutil
        shutil.rmtree(macosx_dir)

    tmp_zip.unlink()
    print("[findit2-benchmark] done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--dest",
        default="~/malwarecage",
        help="Where to put the fetched content - must be a directory excluded from your "
        "AV/EDR real-time scanning. Default: ~/malwarecage.",
    )
    args = parser.parse_args()
    dest = Path(args.dest).expanduser()

    fetch_malware_samples(dest)
    fetch_findit2(dest)
