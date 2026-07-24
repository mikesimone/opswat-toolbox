#!/usr/bin/env python3
r"""
Scan a local directory with OPSWAT MetaDefender Cloud API v4.

Default behavior:
  - Prompts whether to send to MetaDefender Cloud or local Core (default local; --target to skip)
  - Interactively downloads N samples from MalwareBazaar into ~/malwarecage
    (delivered as password-protected zips; NOT unzipped locally). --no-download skips this.
  - Recursively scans ~/malwarecage (C:\Users\<you>\malwarecage on Windows)
  - Prompts whether to unzip files locally before uploading (default yes; --unzip/--no-unzip
    to skip the prompt). When unzipped, each extracted file is deleted immediately after its
    own successful upload, and no archive password is sent for it. When left zipped, uploads
    with archive password "infected" and lets MetaDefender unpack it server-side.
  - Deletes each local .zip after a successful upload (use --keep-zips to keep them)
  - Uses rule: multiscan,unarchive,sanitize (MetaDefender unpacks the zips server-side)
  - Polls for completed analysis
  - Prints a concise verdict table
  - Saves full JSON reports to ~/opswat/results/

Usage (PowerShell):
  $env:OPSWAT_API_KEY = 'your_api_key_here'
  python .\Opswat_Scan_Files.py

Usage (bash / *nix):
  export OPSWAT_API_KEY='your_api_key_here'
  python3 Opswat_Scan_Files.py

Local MetaDefender Core:
  # Address defaults to http://127.0.0.1:8008; override via env var or flag.
  $env:OPSWAT_LOCAL_URL = 'http://10.0.0.5:8008'   # PowerShell
  export OPSWAT_LOCAL_URL='http://10.0.0.5:8008'   # bash
  python Opswat_Scan_Files.py --target local --local-url http://10.0.0.5:8008

Optional:
  python Opswat_Scan_Files.py C:\Users\me\samples
  python Opswat_Scan_Files.py --dir ~/samples
  python Opswat_Scan_Files.py --out ~/opswat/demo-results
  python Opswat_Scan_Files.py --rule multiscan,unarchive
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyzipper
import requests


# MetaDefender targets. API_BASE is reassigned in main() based on --target.
# Cloud has a /v4 path prefix; Core (local) does not.
CLOUD_API_BASE = "https://api.metadefender.com/v4"
DEFAULT_LOCAL_API_BASE = "http://127.0.0.1:8008"  # MetaDefender Core fallback
# The local Core address is read from the environment so it can point at a
# remote/other host without editing this file; --local-url still overrides.
LOCAL_API_BASE = os.environ.get("OPSWAT_LOCAL_URL", DEFAULT_LOCAL_API_BASE)
API_BASE = CLOUD_API_BASE

# API keys and the local URL are read from the environment (no secrets stored
# in this file):
#   OPSWAT_API_KEY        -> MetaDefender Cloud (work account)
#   OPSWAT_LOCAL_API_KEY  -> MetaDefender Core (local)
#   OPSWAT_LOCAL_URL      -> MetaDefender Core base URL (default 127.0.0.1:8008)
#   MALWAREBAZAAR_API_KEY -> MalwareBazaar Auth-Key
# Keys can also be passed via --api-key / --mb-api-key, the URL via --local-url.

# Holding directory for samples. On this box this is the Defender-excluded
# ~/malwarecage folder (C:\Users\<you>\malwarecage). Kept as ~ so the same
# script works across hosts; Path.expanduser() resolves it per-platform.
DEFAULT_SCAN_DIR = "~/malwarecage"
DEFAULT_OUTPUT_DIR = "~/opswat/results"
DEFAULT_RULE = "multiscan,unarchive,sanitize"

# --- MalwareBazaar (abuse.ch) -------------------------------------------------
MB_API = "https://mb-api.abuse.ch/api/v1/"

# MalwareBazaar delivers every sample as a ZIP encrypted with this password.
# We deliberately do NOT unzip locally (keeps Defender/Infosec happy) — the zips
# are uploaded as-is and MetaDefender unpacks them server-side via `archivepwd`.
MB_ZIP_PASSWORD = "infected"
DEFAULT_ARCHIVE_PASSWORD = MB_ZIP_PASSWORD

DEFAULT_DOWNLOAD_COUNT = 5


RESULT_LABELS = {
    0: "Clean",
    1: "Infected",
    2: "Suspicious",
    3: "Failed",
    4: "Not scanned",
    5: "Unknown",
    6: "Quarantined",
    7: "Skipped dirty",
    8: "Skipped clean",
    9: "Exceeded archive depth",
    10: "Not extracted",
    11: "Exceeded archive size",
    12: "Exceeded archive file count",
    13: "Password protected",
    14: "Exceeded scan timeout",
    15: "Unsupported",
    16: "Canceled",
    17: "Mismatch",  # filetype/data mismatch (confirmed via STIX export)
    18: "Exceeded file size",
    19: "Partially scanned",
    20: "Potentially unwanted app",
    21: "Potentially vulnerable app",
    22: "Known threat",
    23: "Possible threat",
    24: "No scan results",
    # AI Content Inspector verdict (AI-generated content detection).
    63: "AI Generated",
    # OPSWAT AI / deflection ("Alin") engine verdicts. When enabled, the
    # deflection engine reports its own scan_all_result_i values before (or
    # instead of) the multiscan pipeline.
    67: "AI: Confidently Clean",
    68: "AI: Confidently Malicious",
    69: "AI: Undetermined",
    253: "Not scanned / rate limit exceeded",
    254: "In progress",
    255: "Queued / pending",
}

# scan_all_result_i values that are NOT a final verdict. 254/255 are the
# classic in-progress/queued codes; 69 ("OPSWAT AI Undetermined") is transient
# too — the deflection engine couldn't decide, so MetaDefender routes the file
# to the full scan pipeline and scan_all_result_i is updated once it finishes.
IN_PROGRESS_CODES = frozenset({69, 254, 255})


@dataclass
class SubmittedFile:
    path: Path
    sha256: str
    data_id: str


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def iter_files(root: Path) -> list[Path]:
    if not root.exists():
        raise FileNotFoundError(f"Directory does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    files: list[Path] = []

    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files.append(path)

    return sorted(files)


def unzip_password_protected(zip_path: Path, password: str) -> list[Path]:
    """Extract every member of ``zip_path`` alongside it, return the extracted paths.

    MalwareBazaar delivers samples as WinZip AES-256 encrypted zips, which the
    standard library's ``zipfile`` cannot decrypt at all (it raises "That
    compression method is not supported" before it even gets to the password).
    ``pyzipper.AESZipFile`` handles both AES and classic ZipCrypto transparently.

    Filenames are flattened to their basename (ignoring any directory
    component the zip entry carries) so extracted samples land directly in
    the scan directory next to everything else, and a malicious entry can't
    zip-slip its way outside it.

    All members are read into memory before anything is written to disk.
    MalwareBazaar's "zip" file type means the payload *inside* the archive
    can be named identically to the archive itself (both "<sha256>.zip") --
    writing member-by-member while the archive was still open at that same
    path used to silently overwrite the archive with the extracted bytes,
    which the subsequent "delete the zip" step would then also delete,
    losing the sample entirely. Any name that collides with the archive's
    own path, or with a leftover file from a previous run, gets disambiguated
    instead of clobbered.
    """
    dest_dir = zip_path.parent
    pwd = password.encode("utf-8") if password else None

    with pyzipper.AESZipFile(zip_path) as zf:
        members = [
            (info.filename, zf.read(info, pwd=pwd))
            for info in zf.infolist()
            if not info.is_dir()
        ]

    extracted: list[Path] = []

    for filename, data in members:
        out_path = dest_dir / Path(filename).name

        if out_path == zip_path or out_path.exists():
            stem, suffix = out_path.stem, out_path.suffix
            n = 1
            while out_path == zip_path or out_path.exists():
                out_path = dest_dir / f"{stem}.extracted{n}{suffix}"
                n += 1

        out_path.write_bytes(data)
        extracted.append(out_path)

    return extracted


def run_unzip_phase(
    files: list[Path], archive_password: str | None, keep_zips: bool
) -> tuple[list[Path], set[Path]]:
    """Extract each .zip in ``files`` in place, deleting the zip once extracted.

    Returns the updated file list (zips replaced by their extracted members)
    and the set of extracted paths, so callers know which files no longer
    need an archive password and must be deleted right after upload.
    """
    updated: list[Path] = []
    extracted_paths: set[Path] = set()

    for path in files:
        if path.suffix.lower() != ".zip":
            updated.append(path)
            continue

        try:
            members = unzip_password_protected(path, archive_password or "")
        except (pyzipper.BadZipFile, NotImplementedError, RuntimeError, OSError) as exc:
            print(f"[unzip] failed for {path.name}: {exc}; uploading zip as-is", file=sys.stderr)
            updated.append(path)
            continue

        print(f"[unzip] {path.name} -> {len(members)} file(s)")
        updated.extend(members)
        extracted_paths.update(members)

        if not keep_zips:
            try:
                path.unlink()
                print(f"         deleted local zip: {path.name}")
            except OSError as exc:
                print(f"         [warn] could not delete {path}: {exc}", file=sys.stderr)

    return sorted(updated), extracted_paths


# --- MalwareBazaar download phase --------------------------------------------
def mb_query(session: requests.Session, payload: dict[str, str]) -> requests.Response:
    return request_with_retry(session, "POST", MB_API, data=payload)


def mb_records(response: requests.Response) -> tuple[str, list[dict[str, Any]]]:
    try:
        body = response.json()
    except ValueError:
        return "bad_json", []

    return body.get("query_status", "unknown"), (body.get("data") or [])


def gather_candidates(
    session: requests.Session,
    families: list[str],
    filetypes: list[str],
    pool_limit: int,
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}

    def add(items: list[dict[str, Any]]) -> None:
        for rec in items:
            sha = rec.get("sha256_hash")
            if sha:
                records[sha] = rec

    if families:
        for fam in families:
            status, items = mb_records(
                mb_query(session, {"query": "get_siginfo", "signature": fam, "limit": str(pool_limit)})
            )
            if status == "ok":
                add(items)
            else:
                print(f"[mb] family '{fam}': {status}", file=sys.stderr)
    elif filetypes:
        for ft in filetypes:
            status, items = mb_records(
                mb_query(session, {"query": "get_file_type", "file_type": ft, "limit": str(pool_limit)})
            )
            if status == "ok":
                add(items)
            else:
                print(f"[mb] file_type '{ft}': {status}", file=sys.stderr)
    else:
        status, items = mb_records(mb_query(session, {"query": "get_recent", "selector": "100"}))
        if status == "ok":
            add(items)
        else:
            print(f"[mb] get_recent: {status}", file=sys.stderr)

    pool = list(records.values())

    # If both families and filetypes are given, narrow the family hits to the
    # requested types (MalwareBazaar has no combined query).
    if families and filetypes:
        wanted = {t.lower() for t in filetypes}
        pool = [r for r in pool if str(r.get("file_type", "")).lower() in wanted]

    return pool


def download_sample(session: requests.Session, sha256: str, dest_dir: Path) -> Path:
    response = mb_query(session, {"query": "get_file", "sha256_hash": sha256})
    content = response.content

    # A successful download is a ZIP (starts with the PK magic bytes). Anything
    # else is a JSON error payload.
    if content[:2] == b"PK":
        out = dest_dir / f"{sha256}.zip"
        out.write_bytes(content)
        return out

    try:
        detail = response.json().get("query_status", response.text[:200])
    except ValueError:
        # Collapse HTML/whitespace (e.g. a 502 page) into a short one-liner.
        detail = " ".join(content[:200].decode("utf-8", "replace").split())

    raise RuntimeError(f"download failed for {sha256}: HTTP {response.status_code}: {detail}")


def prompt_default(text: str, default: str) -> str:
    try:
        value = input(text).strip()
    except EOFError:
        value = ""

    return value or default


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def run_download_phase(args: argparse.Namespace, dest_dir: Path, unzip_files: bool) -> None:
    # CLI flags win; otherwise ask interactively.
    if args.count is not None:
        count = args.count
    else:
        raw = prompt_default(
            f"How many files to download from MalwareBazaar? [{DEFAULT_DOWNLOAD_COUNT}]: ",
            str(DEFAULT_DOWNLOAD_COUNT),
        )
        try:
            count = int(raw)
        except ValueError:
            count = DEFAULT_DOWNLOAD_COUNT

    if count <= 0:
        print("[mb] Download count <= 0; skipping download phase.")
        return

    if args.file_types is not None:
        filetypes = split_csv(args.file_types)
    else:
        filetypes = split_csv(
            prompt_default("Specific file types? (comma-separated, e.g. exe,dll,elf) [blank = any]: ", "")
        )

    if args.families is not None:
        families = split_csv(args.families)
    else:
        families = split_csv(
            prompt_default(
                "Specific malware families/signatures? (comma-separated, e.g. AgentTesla,Emotet) [blank = random]: ",
                "",
            )
        )

    api_key = args.mb_api_key or os.environ.get("MALWAREBAZAAR_API_KEY")
    if not api_key:
        print(
            "[mb] No MalwareBazaar Auth-Key found (set MALWAREBAZAAR_API_KEY or pass "
            "--mb-api-key); skipping download.",
            file=sys.stderr,
        )
        return

    session = requests.Session()
    session.headers.update({"Auth-Key": api_key})

    print()
    print("=== MalwareBazaar download ===")
    print(f"Count      : {count}")
    print(f"File types : {', '.join(filetypes) if filetypes else '(any / random)'}")
    print(f"Families   : {', '.join(families) if families else '(any / random)'}")
    print(f"Dest dir   : {dest_dir}")

    dest_dir.mkdir(parents=True, exist_ok=True)

    pool_limit = min(1000, max(count * 5, 100))
    candidates = gather_candidates(session, families, filetypes, pool_limit)

    if not candidates:
        print("[mb] No matching samples found; nothing downloaded.", file=sys.stderr)
        return

    # Shuffle the whole pool and walk it until we hit the requested count, so a
    # few failed/unavailable samples get topped up from the remaining candidates.
    random.shuffle(candidates)
    fate = "will be unzipped locally next" if unzip_files else "stay encrypted, NOT unzipped locally"
    print(
        f"[mb] {len(candidates)} candidate(s); downloading up to {count} "
        f"password-protected zip(s) ({fate})."
    )

    downloaded = 0

    for rec in candidates:
        if downloaded >= count:
            break

        sha = rec["sha256_hash"]
        ft = rec.get("file_type", "?")
        sig = rec.get("signature") or "unknown"

        try:
            out = download_sample(session, sha, dest_dir)
            downloaded += 1
            print(f"  [+] {sha[:12]}  type={ft:<6} family={sig:<18} -> {out.name}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"  [!] {sha[:12]}  {exc}", file=sys.stderr)

    if downloaded < count:
        print(
            f"[mb] Only {downloaded}/{count} downloaded — pool exhausted "
            f"(some failed or were unavailable).",
            file=sys.stderr,
        )

    print(f"[mb] Downloaded {downloaded} sample(s) into {dest_dir}")


def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    max_retries: int = 5,
    timeout: int = 120,
    **kwargs: Any,
) -> requests.Response:
    response: requests.Response | None = None

    for attempt in range(max_retries + 1):
        response = session.request(method, url, timeout=timeout, **kwargs)

        # Retry on rate-limit (429) and transient server errors (5xx, e.g. the
        # 502s MalwareBazaar's front end throws). Everything else returns as-is.
        if response.status_code != 429 and response.status_code < 500:
            return response

        retry_after = response.headers.get("Retry-After")

        if retry_after and retry_after.isdigit():
            sleep_seconds = int(retry_after)
        else:
            sleep_seconds = min(60, 2 ** attempt)

        reason = "rate-limit 429" if response.status_code == 429 else f"server {response.status_code}"
        print(
            f"[retry] {reason}; sleeping {sleep_seconds}s (attempt {attempt + 1}/{max_retries})",
            file=sys.stderr,
        )
        time.sleep(sleep_seconds)

    assert response is not None
    return response


def upload_file(
    session: requests.Session,
    path: Path,
    *,
    rule: str | None,
    private: bool,
    private_processing: bool,
    archive_password: str | None,
    file_password: str | None,
) -> SubmittedFile:
    sha256 = sha256_file(path)

    headers = {
        "filename": path.name,
        "Content-Type": "application/octet-stream",
    }

    if rule:
        headers["rule"] = rule

    if private:
        headers["samplesharing"] = "0"

    if private_processing:
        headers["privateProcessing"] = "1"

    if archive_password:
        headers["archivepwd"] = archive_password

    if file_password:
        headers["filepassword"] = file_password

    with path.open("rb") as f:
        response = request_with_retry(
            session,
            "POST",
            f"{API_BASE}/file",
            headers=headers,
            data=f,
        )

    try:
        body = response.json()
    except ValueError:
        body = {"raw_response": response.text}

    if response.status_code >= 400:
        raise RuntimeError(
            f"Upload failed for {path}: HTTP {response.status_code}: "
            f"{json.dumps(body, indent=2)}"
        )

    data_id = body.get("data_id")

    if not data_id:
        raise RuntimeError(
            f"Upload response for {path} did not include data_id: "
            f"{json.dumps(body, indent=2)}"
        )

    return SubmittedFile(path=path, sha256=sha256, data_id=data_id)


def fetch_result(session: requests.Session, data_id: str) -> dict[str, Any]:
    response = request_with_retry(
        session,
        "GET",
        f"{API_BASE}/file/{data_id}",
    )

    try:
        body = response.json()
    except ValueError:
        body = {"raw_response": response.text}

    if response.status_code >= 400:
        raise RuntimeError(
            f"Result lookup failed for data_id={data_id}: "
            f"HTTP {response.status_code}: {json.dumps(body, indent=2)}"
        )

    return body


def progress_percent(report: dict[str, Any]) -> int:
    process_info = as_dict(report.get("process_info"))

    try:
        return int(process_info.get("progress_percentage", 0) or 0)
    except (TypeError, ValueError):
        return 0


def scan_code(report: dict[str, Any]) -> int | None:
    scan_results = as_dict(report.get("scan_results"))
    value = scan_results.get("scan_all_result_i")

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_complete(report: dict[str, Any]) -> bool:
    # Progress of 100% is always terminal — even if the code is still a
    # transient one, there is nothing further to wait for.
    if progress_percent(report) >= 100:
        return True

    code = scan_code(report)

    if code is not None and code not in IN_PROGRESS_CODES:
        return True

    return False


def flatten_sanitization(details: Any) -> list[tuple[str, str, int]]:
    """Flatten Deep CDR ``sanitization_details.details`` into (action, object, count).

    The structure is recursive: an entry is either a leaf (``object_name`` +
    ``count``) or a container for an embedded file (its own nested ``details``
    list, no ``count``). We keep only the leaves that carry a count.
    """
    leaves: list[tuple[str, str, int]] = []

    if not isinstance(details, list):
        return leaves

    for entry in details:
        if not isinstance(entry, dict):
            continue

        nested = entry.get("details")

        if isinstance(nested, list) and nested:
            leaves.extend(flatten_sanitization(nested))
            continue

        name = entry.get("object_name")
        count = entry.get("count")

        if name and count is not None:
            try:
                leaves.append((entry.get("action") or "modified", str(name), int(count)))
            except (TypeError, ValueError):
                continue

    return leaves


def aggregate_cdr(leaves: list[tuple[str, str, int]]) -> dict[tuple[str, str], int]:
    agg: dict[tuple[str, str], int] = {}

    for action, name, count in leaves:
        agg[(action, name)] = agg.get((action, name), 0) + count

    return agg


def format_cdr(agg: dict[tuple[str, str], int]) -> str | None:
    if not agg:
        return None

    # Group by action (removed first, then sanitized, then anything else).
    action_order = {"removed": 0, "sanitized": 1}
    by_action: dict[str, list[str]] = {}

    for (action, name), count in sorted(agg.items(), key=lambda kv: kv[0][1]):
        by_action.setdefault(action, []).append(f"{count} {name}")

    parts = [
        f"{action} " + ", ".join(items)
        for action, items in sorted(by_action.items(), key=lambda kv: action_order.get(kv[0], 2))
    ]

    return "; ".join(parts)


def dlp_hits(dlp_info: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    for key, info in as_dict(dlp_info.get("hits")).items():
        info = as_dict(info)
        locations: list[str] = []

        for hit in info.get("hits") or []:
            location = as_dict(hit).get("location")
            if location and location not in locations:
                locations.append(location)

        out.append(
            {
                "type": info.get("display_name") or key,
                "count": len(info.get("hits") or []),  # total occurrences
                "locations": locations[:5],  # digest; full detail is in the report JSON
                "locations_total": len(locations),
            }
        )

    return out


def av_summary(scan_results: dict[str, Any]) -> tuple[int, Any, list[str]]:
    """Return (detected_engine_count, total_avs, threat_names) from scan_details."""
    detected = 0
    threats: list[str] = []

    for _, result in as_dict(scan_results.get("scan_details")).items():
        result = as_dict(result)

        if result.get("scan_result_i") in (1, 2):  # infected / suspicious
            detected += 1
            threat = result.get("threat_found")
            if threat and threat not in threats:
                threats.append(threat)

    return detected, scan_results.get("total_avs"), threats


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    file_info = as_dict(report.get("file_info"))
    scan_results = as_dict(report.get("scan_results"))
    process_info = as_dict(report.get("process_info"))
    post_processing = as_dict(process_info.get("post_processing"))
    engine_results = as_dict(report.get("engine_results"))
    ai_verdict = as_dict(as_dict(report.get("aicontentinspector_info")).get("final_verdict"))
    filetype_info = as_dict(report.get("filetype_info"))
    spoofing = as_dict(filetype_info.get("spoofing_info"))
    vulnerability = as_dict(report.get("vulnerability_info"))

    code = scan_code(report)
    # Prefer the authoritative label the API returns; fall back to our numeric
    # map, then to the raw code. This auto-handles new codes (e.g. 63 "AI
    # Generated", the OPSWAT-AI deflection verdicts) without a table update.
    verdict = scan_results.get("scan_all_result_a")
    if not verdict:
        verdict = RESULT_LABELS.get(code, f"code {code}") if code is not None else "Unknown"

    detected, total_avs, threats = av_summary(scan_results)

    cdr_agg = aggregate_cdr(
        flatten_sanitization(as_dict(post_processing.get("sanitization_details")).get("details"))
    )

    ai_result = ai_verdict.get("verdict")
    ai_detected = bool(ai_result) and str(ai_result).strip().lower() not in ("", "not detected", "clean")
    ai_explanation = "; ".join(x for x in (ai_verdict.get("verdict_explanation") or []) if x) or None

    filetype_mismatch = bool(filetype_info.get("is_file_type_mismatch")) or (
        spoofing.get("detection_result") not in (None, "", "Not Mismatched")
    )

    return {
        "display_name": file_info.get("display_name"),
        "sha256": file_info.get("sha256"),
        "file_type": file_info.get("file_type_id"),
        "verdict": verdict,
        "scan_all_result_i": code,
        "process_result": process_info.get("result"),
        "blocked_reason": process_info.get("blocked_reason") or None,
        "av_detected": detected,
        "av_total": total_avs,
        "av_threats": threats,
        "cdr_result": engine_results.get("sanitization_result"),
        "cdr_removals": [
            {"action": action, "object": name, "count": count}
            for (action, name), count in sorted(cdr_agg.items())
        ],
        "cdr_text": format_cdr(cdr_agg),
        "dlp_hits": dlp_hits(as_dict(report.get("dlp_info"))),
        "ai_generated": ai_explanation or ("detected" if ai_detected else None),
        "filetype_mismatch": filetype_mismatch or None,
        "vulnerability_verdict": vulnerability.get("verdict"),
    }


def print_table(rows: list[dict[str, Any]]) -> None:
    headers = ["File", "Verdict", "AV", "CDR", "DLP"]
    widths = [34, 31, 7, 11, 8]

    def cell(value: Any, width: int) -> str:
        text = "" if value is None else str(value)

        if len(text) > width:
            text = text[: width - 1] + "…"

        return text.ljust(width)

    print()
    print(" ".join(cell(h, w) for h, w in zip(headers, widths)))
    print(" ".join("-" * w for w in widths))

    for row in rows:
        av = ""
        if row.get("av_total") is not None:
            av = f"{row.get('av_detected', 0)}/{row.get('av_total')}"

        cdr = ""
        if row.get("cdr_removals") or row.get("cdr_result") == "Success":
            cdr = "Sanitized"
        elif row.get("cdr_result") and row.get("cdr_result") != "Not Run":
            cdr = str(row.get("cdr_result"))

        dlp = ""
        n_dlp = len(row.get("dlp_hits") or [])
        if n_dlp:
            dlp = f"{n_dlp} hit" + ("s" if n_dlp != 1 else "")

        values = [row.get("display_name"), row.get("verdict"), av, cdr, dlp]
        print(" ".join(cell(v, w) for v, w in zip(values, widths)))


def finding_rows(row: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Expand one file's summary into normalized (category, finding, count, note) rows."""
    out: list[tuple[str, str, str, str]] = []

    for removal in row.get("cdr_removals") or []:
        out.append(("CDR", str(removal.get("object")), str(removal.get("count")), str(removal.get("action"))))

    for hit in row.get("dlp_hits") or []:
        note = ""
        locations = list(hit.get("locations") or [])
        if locations:
            note = locations[0]
            extra = hit.get("locations_total", len(locations)) - 1
            if extra > 0:
                note += f" +{extra} more"
        out.append(("DLP", str(hit.get("type")), str(hit.get("count") or ""), note))

    threats = row.get("av_threats") or []
    engines = f"{row.get('av_detected')}/{row.get('av_total')} engines"
    for threat in threats:
        out.append(("AV", str(threat), str(row.get("av_detected") or ""), engines))

    if row.get("ai_generated"):
        out.append(("AI", "AI-generated content", "-", str(row["ai_generated"])))

    if row.get("filetype_mismatch"):
        out.append(("Filetype", "type mismatch / spoofing", "-", "detected"))

    vuln = row.get("vulnerability_verdict")
    if isinstance(vuln, int) and vuln > 0:
        out.append(("Vuln", "vulnerability", "-", f"verdict {vuln}"))

    return out


def print_details(rows: list[dict[str, Any]]) -> None:
    """Normalized findings grid: one row per CDR removal / DLP hit / threat."""
    expanded = [(row.get("display_name"), r) for row in rows for r in finding_rows(row)]

    if not expanded:
        return

    headers = ["File", "Category", "Finding", "Count", "Note"]
    widths = [30, 8, 30, 5, 26]

    def cell(value: Any, width: int) -> str:
        text = "" if value is None else str(value)
        if len(text) > width:
            text = text[: width - 1] + "…"
        return text.ljust(width)

    print()
    print("Findings")
    print(" ".join(cell(h, w) for h, w in zip(headers, widths)))
    print(" ".join("-" * w for w in widths))

    prev_file = None
    for display_name, (category, finding, count, note) in expanded:
        # Blank the repeated filename so each file reads as a visual block.
        file_cell = "" if display_name == prev_file else display_name
        prev_file = display_name
        print(" ".join(cell(v, w) for v, w in zip([file_cell, category, finding, count, note], widths)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload files to OPSWAT MetaDefender Cloud v4 and retrieve scan results."
    )

    parser.add_argument(
        "scan_dir",
        nargs="?",
        default=None,
        help=f"Directory to scan. Default: {DEFAULT_SCAN_DIR}",
    )

    parser.add_argument(
        "--dir",
        dest="scan_dir_flag",
        default=None,
        help=f"Directory to scan. Default: {DEFAULT_SCAN_DIR}",
    )

    parser.add_argument(
        "--out",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for JSON reports. Default: {DEFAULT_OUTPUT_DIR}",
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="MetaDefender apikey. Default depends on --target: cloud uses the OPSWAT_API_KEY "
        "env var; local uses the OPSWAT_LOCAL_API_KEY env var.",
    )

    parser.add_argument(
        "--target",
        choices=["cloud", "local"],
        default=None,
        help="Where to send files: 'cloud' (MetaDefender Cloud) or 'local' (MetaDefender Core). "
        "Omit to be prompted at the start (default local).",
    )

    parser.add_argument(
        "--local-url",
        default=LOCAL_API_BASE,
        help="Base URL for local MetaDefender Core. Overrides the OPSWAT_LOCAL_URL "
        f"env var. Default: {LOCAL_API_BASE}",
    )

    parser.add_argument(
        "--rule",
        default=None,
        help=f"Processing rule. Cloud default: {DEFAULT_RULE}. "
        "Local (Core) sends no rule by default, using Core's configured workflow.",
    )

    parser.add_argument(
        "--private",
        action="store_true",
        help="Set samplesharing: 0.",
    )

    parser.add_argument(
        "--private-processing",
        action="store_true",
        help="Set privateProcessing: 1. Requires eligible account.",
    )

    parser.add_argument(
        "--archive-password",
        default=DEFAULT_ARCHIVE_PASSWORD,
        help=f'Archive password sent to MetaDefender (archivepwd). Default: "{DEFAULT_ARCHIVE_PASSWORD}". '
        "Only sent for files still zipped at upload time; see --unzip.",
    )
    parser.add_argument("--file-password", default=None)

    parser.add_argument(
        "--unzip",
        dest="unzip_files",
        action="store_const",
        const=True,
        default=None,
        help="Extract zip files locally before uploading, deleting each extracted file "
        "immediately after its own successful submission. Omit for an interactive "
        "prompt (default: yes).",
    )
    parser.add_argument(
        "--no-unzip",
        dest="unzip_files",
        action="store_const",
        const=False,
        help="Upload zip files as-is; MetaDefender unpacks them server-side via archivepwd.",
    )

    # --- MalwareBazaar download phase ---
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Skip the MalwareBazaar download phase and just scan the directory.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of samples to download (skips the interactive prompt).",
    )
    parser.add_argument(
        "--file-types",
        default=None,
        help="Comma-separated file types to download, e.g. exe,dll. Omit for interactive; blank = any.",
    )
    parser.add_argument(
        "--families",
        default=None,
        help="Comma-separated malware families/signatures, e.g. AgentTesla,Emotet. Omit for interactive; blank = any.",
    )
    parser.add_argument(
        "--mb-api-key",
        default=None,
        help="MalwareBazaar Auth-Key. Defaults to the MALWAREBAZAAR_API_KEY env var.",
    )
    parser.add_argument(
        "--keep-zips",
        action="store_true",
        help="Keep local .zip samples after upload. Default: delete each zip once uploaded.",
    )
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--max-wait-seconds", type=int, default=900)

    return parser.parse_args()


def main() -> int:
    # Verdict strings and the detail block use non-ASCII glyphs (…, ─). Force
    # UTF-8 output so runs survive a cp1252 console or a redirected stdout.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = parse_args()

    # --- Choose MetaDefender target (Cloud vs local Core) ---
    target = args.target
    if target is None:
        answer = prompt_default(
            "Send to MetaDefender Cloud or Local Core? [cloud/local] (default local): ",
            "local",
        )
        target = "cloud" if answer.strip().lower().startswith("c") else "local"

    global API_BASE
    if target == "local":
        API_BASE = args.local_url
        api_key = args.api_key or os.environ.get("OPSWAT_LOCAL_API_KEY")
        rule = args.rule  # None -> let Core use its configured default workflow
    else:
        API_BASE = CLOUD_API_BASE
        api_key = args.api_key or os.environ.get("OPSWAT_API_KEY")
        rule = args.rule or DEFAULT_RULE

    if not api_key:
        env_name = "OPSWAT_LOCAL_API_KEY" if target == "local" else "OPSWAT_API_KEY"
        print(f"Missing API key. Set {env_name} or pass --api-key.", file=sys.stderr)
        return 2

    if args.unzip_files is None:
        answer = prompt_default(
            "Unzip files before uploading (extract, then delete the zip)? [Y/n]: ",
            "y",
        )
        unzip_files = answer.strip().lower().startswith("y")
    else:
        unzip_files = args.unzip_files

    scan_dir = args.scan_dir_flag or args.scan_dir or DEFAULT_SCAN_DIR

    scan_root = Path(scan_dir).expanduser()
    output_dir = Path(args.out).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_download:
        run_download_phase(args, scan_root, unzip_files)

    files = iter_files(scan_root)

    if not files:
        print(f"No regular files found under {scan_root}")
        return 0

    extracted_paths: set[Path] = set()
    if unzip_files:
        files, extracted_paths = run_unzip_phase(files, args.archive_password, args.keep_zips)

        if not files:
            print(f"No regular files found under {scan_root}")
            return 0

    session = requests.Session()
    session.headers.update({"apikey": api_key})

    submitted: list[SubmittedFile] = []
    summaries: list[dict[str, Any]] = []
    failed: list[Path] = []

    print(f"Target          : {target}  ({API_BASE})")
    print(f"Scan directory  : {scan_root}")
    print(f"Output directory: {output_dir}")
    print(f"Processing rule : {rule or '(Core default workflow)'}")
    print(f"Files found     : {len(files)}")
    print()

    for path in files:
        print(f"[upload] {path}")

        is_zip = path.suffix.lower() == ".zip"

        try:
            submitted_file = upload_file(
                session,
                path,
                rule=rule,
                private=args.private,
                private_processing=args.private_processing,
                # Only files still zipped at upload time need MetaDefender to
                # unpack them server-side; already-extracted files send none.
                archive_password=args.archive_password if is_zip else None,
                file_password=args.file_password,
            )
        except FileNotFoundError:
            # Seen in practice with --unzip: something outside this script
            # (an EDR/AV quarantining the now-plaintext sample) can delete
            # the file out from under us before we get to it. Don't let one
            # vanished file kill the rest of the batch.
            print(
                f"         [warn] {path.name} vanished before upload (likely quarantined by "
                "antivirus/EDR); skipping",
                file=sys.stderr,
            )
            failed.append(path)
            continue
        except (OSError, RuntimeError, requests.RequestException) as exc:
            print(f"         [warn] upload failed for {path.name}: {exc}; skipping", file=sys.stderr)
            failed.append(path)
            continue

        submitted.append(submitted_file)

        print(f"         data_id={submitted_file.data_id}")
        print(f"         sha256={submitted_file.sha256}")

        # Delete the local file once it's safely uploaded (upload_file raises
        # on failure, so we only reach here on success). Files we extracted
        # ourselves are always deleted right away, regardless of
        # --keep-zips -- that flag is about keeping the original archive,
        # not leaving unpacked samples sitting on disk.
        if path in extracted_paths:
            try:
                path.unlink()
                print(f"         deleted extracted file: {path.name}")
            except OSError as exc:
                print(f"         [warn] could not delete {path}: {exc}", file=sys.stderr)
        elif not args.keep_zips and is_zip:
            try:
                path.unlink()
                print(f"         deleted local zip: {path.name}")
            except OSError as exc:
                print(f"         [warn] could not delete {path}: {exc}", file=sys.stderr)

    deadline = time.time() + args.max_wait_seconds

    for item in submitted:
        print(f"[poll] {item.path.name}")

        last_report: dict[str, Any] | None = None

        while time.time() < deadline:
            report = fetch_result(session, item.data_id)
            last_report = report

            pct = progress_percent(report)
            code = scan_code(report)
            label = RESULT_LABELS.get(code, f"code {code}") if code is not None else "pending"

            print(f"       progress={pct}% status={label}")

            if is_complete(report):
                break

            time.sleep(args.poll_seconds)

        if last_report is None:
            raise RuntimeError(f"No result returned for {item.path}")

        safe_name = item.path.name.replace("/", "_")
        report_path = output_dir / f"{safe_name}.{item.sha256[:12]}.json"
        report_path.write_text(
            json.dumps(last_report, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        summary = summarize(last_report)
        summary["local_path"] = str(item.path)
        summary["submitted_sha256"] = item.sha256
        summary["data_id"] = item.data_id
        summary["report_path"] = str(report_path)

        summaries.append(summary)

    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summaries, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print_table(summaries)
    print_details(summaries)

    if failed:
        print()
        print(f"Skipped {len(failed)} file(s) that failed to upload:")
        for path in failed:
            print(f"  - {path.name}")

    print()
    print(f"Full reports: {output_dir.resolve()}")
    print(f"Summary JSON: {summary_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())