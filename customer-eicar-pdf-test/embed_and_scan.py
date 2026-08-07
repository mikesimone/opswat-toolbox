#!/usr/bin/env python3
r"""
Embed the EICAR antivirus test string into a PDF as a hidden attachment,
then upload it to MetaDefender Core via the API and print the verdict.

Standard library only - nothing to install.

WHAT THIS DOES
--------------
1. Takes a normal, legitimate PDF you already have (e.g. Colorado Tech.pdf).
2. Adds one small hidden attachment to it containing the EICAR test string
   (https://www.eicar.org/) - a public, harmless string every antivirus
   engine is built to flag as if it were malware, specifically so nobody
   ever needs real malware to test detection.
3. The original PDF's pages/content are untouched; the file just gains one
   extra embedded-file attachment named EICAR-TEST-FILE.com.
4. Uploads the new file to your MetaDefender Core instance and prints
   whether it was detected.

WHY NOT JUST DOWNLOAD THE REAL EICAR FILE?
-------------------------------------------
Some networks block eicar.org outright (it looks like malware traffic to a
web filter). This script builds the exact same standard string locally -
no download needed.

WHY NOT AN ALTERNATE DATA STREAM (NTFS ADS)?
----------------------------------------------
An ADS lives in NTFS filesystem metadata, not in the file's actual content
bytes. Any tool that uploads a file (this script, a browser, curl,
Invoke-RestMethod, a scan API) only reads and sends the file's main data
stream, so the ADS content never leaves the disk and never becomes part of
the upload at all. This script instead puts the test string inside the
file's real bytes, in a standard PDF attachment structure, so it travels
with the upload like any other embedded content (the same general
mechanism real malicious PDFs use to smuggle a weaponized attachment
inside what looks like an ordinary document).

USAGE
-----
    python3 embed_and_scan.py "Colorado Tech.pdf"

You'll be prompted for your MetaDefender Core URL and API key if they
aren't already set as environment variables:

    export OPSWAT_LOCAL_URL="http://your-core-host:8008"
    export OPSWAT_LOCAL_API_KEY="your_api_key"

Options:
    --out FILE          Where to save the modified PDF (default: adds
                         "-eicar-test" before the extension).
    --no-upload          Only build the file locally; don't scan it.
    --core-url URL       Same as OPSWAT_LOCAL_URL.
    --api-key KEY        Same as OPSWAT_LOCAL_API_KEY.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ATTACHMENT_NAME = b"EICAR-TEST-FILE.com"


class PdfEditError(Exception):
    pass


def embed_eicar(pdf_bytes: bytes) -> bytes:
    """Append a new PDF revision (an "incremental update", a standard,
    spec-legal way to add content to a PDF without touching a single byte
    of the original) that adds an /EmbeddedFiles attachment carrying the
    EICAR string.
    """
    if not pdf_bytes.startswith(b"%PDF-"):
        raise PdfEditError("Not a PDF (missing %PDF- header).")

    trailer_matches = list(re.finditer(rb"trailer\s*<<(.*?)>>", pdf_bytes, re.S))
    if not trailer_matches:
        raise PdfEditError(
            "Could not find a classic PDF trailer in this file - it may use "
            "compressed cross-reference streams, which this simple script "
            "doesn't parse. Try a different, simpler PDF (e.g. one made "
            "with 'Print to PDF')."
        )
    trailer_body = trailer_matches[-1].group(1)

    size_match = re.search(rb"/Size\s+(\d+)", trailer_body)
    root_match = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R", trailer_body)
    if not size_match or not root_match:
        raise PdfEditError("Trailer is missing /Size or /Root; can't safely edit this PDF.")

    size = int(size_match.group(1))
    root_num = int(root_match.group(1))
    root_gen = int(root_match.group(2))

    startxref_matches = list(re.finditer(rb"startxref\s+(\d+)", pdf_bytes))
    if not startxref_matches:
        raise PdfEditError("Could not find startxref in this file.")
    prev_offset = int(startxref_matches[-1].group(1))

    root_obj_match = re.search(
        rb"(?:^|[\r\n])" + str(root_num).encode() + rb"\s+" + str(root_gen).encode()
        + rb"\s+obj\s*<<(.*?)>>\s*endobj",
        pdf_bytes,
        re.S,
    )
    if not root_obj_match:
        raise PdfEditError(f"Could not locate the Catalog object ({root_num} {root_gen} obj).")
    root_dict_body = root_obj_match.group(1)

    if b"/EmbeddedFiles" in root_dict_body:
        raise PdfEditError("This PDF already has embedded files; pick a different source file.")

    file_obj_num = size
    filespec_obj_num = size + 1
    names_obj_num = size + 2

    new_root_dict = (
        root_dict_body.rstrip()
        + b" /Names << /EmbeddedFiles " + str(names_obj_num).encode() + b" 0 R >>"
    )

    out = bytearray(pdf_bytes)
    if not out.endswith(b"\n"):
        out += b"\n"

    offsets: dict[int, int] = {}

    def append_obj(num: int, gen: int, body: bytes) -> None:
        offsets[num] = len(out)
        out.extend(f"{num} {gen} obj\n".encode())
        out.extend(body)
        out.extend(b"\nendobj\n")

    # Updated Catalog - same object number/generation as the original Root.
    # A later revision of the same object number wins, so this is what
    # every PDF reader will use once it reads the new trailer below.
    append_obj(root_num, root_gen, b"<<" + new_root_dict + b">>")

    # EICAR content as an embedded-file stream. Left uncompressed on
    # purpose: the literal test string sits as a plain, directly-visible
    # byte sequence in the file, the same static signature every AV engine
    # already recognizes, whether it's extracted as an attachment or
    # matched by a flat byte scan of the whole upload.
    ef_stream = (
        b"<< /Type /EmbeddedFile /Length " + str(len(EICAR)).encode() + b" >>\n"
        b"stream\n" + EICAR + b"\nendstream"
    )
    append_obj(file_obj_num, 0, ef_stream)

    filespec = (
        b"<< /Type /Filespec /F (" + ATTACHMENT_NAME + b") /UF (" + ATTACHMENT_NAME + b") "
        b"/EF << /F " + str(file_obj_num).encode() + b" 0 R >> >>"
    )
    append_obj(filespec_obj_num, 0, filespec)

    names_tree = b"<< /Names [(" + ATTACHMENT_NAME + b") " + str(filespec_obj_num).encode() + b" 0 R] >>"
    append_obj(names_obj_num, 0, names_tree)

    new_size = names_obj_num + 1
    xref_offset = len(out)

    xref = bytearray()
    xref += b"xref\n"
    xref += f"{root_num} 1\n".encode()
    xref += f"{offsets[root_num]:010d} {root_gen:05d} n \n".encode()
    xref += f"{file_obj_num} 3\n".encode()
    for n in (file_obj_num, filespec_obj_num, names_obj_num):
        xref += f"{offsets[n]:010d} 00000 n \n".encode()
    out.extend(xref)

    out.extend(b"trailer\n<<")
    out.extend(f" /Size {new_size} /Root {root_num} {root_gen} R /Prev {prev_offset}".encode())
    out.extend(b" >>\nstartxref\n")
    out.extend(str(xref_offset).encode())
    out.extend(b"\n%%EOF")

    return bytes(out)


def prompt_default(text: str, default: str = "") -> str:
    try:
        value = input(text).strip()
    except EOFError:
        value = ""
    return value or default


def http_json(url: str, api_key: str, *, method: str = "GET",
              data: bytes | None = None, extra_headers: dict | None = None) -> dict:
    # Some Core deployments sit behind a WAF/CDN (e.g. Cloudflare) that
    # blocks Python's default "Python-urllib/x.y" User-Agent outright
    # (HTTP 403, Cloudflare error 1010) while letting curl/browser traffic
    # through untouched. A generic browser-looking UA avoids that without
    # needing any third-party HTTP library.
    headers = {
        "apikey": api_key,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}:\n{body}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from None


def upload_and_scan(core_url: str, api_key: str, filename: str, data: bytes,
                     poll_seconds: int = 5, max_wait_seconds: int = 300) -> dict:
    upload_url = core_url.rstrip("/") + "/file"
    body = http_json(
        upload_url, api_key, method="POST", data=data,
        extra_headers={"filename": filename, "Content-Type": "application/octet-stream"},
    )
    data_id = body.get("data_id")
    if not data_id:
        raise RuntimeError(f"Upload did not return a data_id:\n{json.dumps(body, indent=2)}")

    print(f"Uploaded OK. data_id = {data_id}")
    result_url = core_url.rstrip("/") + f"/file/{data_id}"

    deadline = time.time() + max_wait_seconds
    report: dict = {}
    while time.time() < deadline:
        report = http_json(result_url, api_key)
        pct = int((report.get("process_info") or {}).get("progress_percentage", 0) or 0)
        print(f"  scanning... {pct}%")
        if pct >= 100:
            break
        time.sleep(poll_seconds)

    return report


def print_verdict(report: dict) -> bool:
    """Print a plain-language verdict. Returns True if the test string was detected."""
    scan_results = report.get("scan_results") or {}
    verdict = scan_results.get("scan_all_result_a") or "Unknown"
    detected = 0
    total = scan_results.get("total_avs")
    threats: list[str] = []

    for engine in (scan_results.get("scan_details") or {}).values():
        if engine.get("scan_result_i") in (1, 2):  # infected / suspicious
            detected += 1
            threat = engine.get("threat_found")
            if threat and threat not in threats:
                threats.append(threat)

    print()
    print("=" * 60)
    print(f"RESULT: {verdict}")
    if total is not None:
        print(f"Engines that flagged it: {detected}/{total}")
    if threats:
        print("Reported as: " + ", ".join(threats))
    print("=" * 60)

    if detected > 0:
        print("This means MetaDefender Core successfully detected the test file.")
        return True

    print(
        "No engine flagged this file. If you expected a detection, confirm your "
        "Core instance has at least one AV engine licensed/enabled, then contact "
        "support with the JSON output above."
    )
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_pdf", help="Path to the source PDF (e.g. \"Colorado Tech.pdf\")")
    parser.add_argument("--out", default=None, help="Where to save the modified PDF")
    parser.add_argument("--no-upload", action="store_true", help="Only build the file locally; don't scan it")
    parser.add_argument("--core-url", default=None, help="MetaDefender Core base URL, e.g. http://host:8008")
    parser.add_argument("--api-key", default=None, help="MetaDefender Core API key")
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--max-wait-seconds", type=int, default=300)
    args = parser.parse_args()

    in_path = Path(args.input_pdf)
    if not in_path.exists():
        print(f"File not found: {in_path}", file=sys.stderr)
        return 2

    out_path = Path(args.out) if args.out else in_path.with_name(in_path.stem + "-eicar-test" + in_path.suffix)

    print(f"Reading:  {in_path}")
    original = in_path.read_bytes()

    try:
        modified = embed_eicar(original)
    except PdfEditError as exc:
        print(f"\nCould not embed the test string: {exc}", file=sys.stderr)
        return 1

    out_path.write_bytes(modified)
    print(f"Wrote:    {out_path}  ({len(modified):,} bytes, original was {len(original):,})")

    if args.no_upload:
        print("\n--no-upload set; skipping the scan. Upload this file yourself via the MetaDefender Core web UI or API.")
        return 0

    import os
    core_url = args.core_url or os.environ.get("OPSWAT_LOCAL_URL") or prompt_default(
        "MetaDefender Core URL (e.g. http://your-core-host:8008): "
    )
    api_key = args.api_key or os.environ.get("OPSWAT_LOCAL_API_KEY") or prompt_default(
        "MetaDefender Core API key: "
    )

    if not core_url or not api_key:
        print("\nMissing Core URL or API key; ask whoever set up MetaDefender Core for these.", file=sys.stderr)
        return 2

    print(f"\nUploading to {core_url} ...")
    try:
        report = upload_and_scan(
            core_url, api_key, out_path.name, modified,
            poll_seconds=args.poll_seconds, max_wait_seconds=args.max_wait_seconds,
        )
    except RuntimeError as exc:
        print(f"\nUpload/scan failed: {exc}", file=sys.stderr)
        return 1

    detected = print_verdict(report)
    return 0 if detected else 3


if __name__ == "__main__":
    raise SystemExit(main())
