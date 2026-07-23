#!/usr/bin/env python3
r"""
Scan a local directory with OPSWAT MetaDefender Cloud API v4.

Default behavior:
  - Prompts whether to send to MetaDefender Cloud or local Core (default local; --target to skip)
  - Interactively downloads N samples from MalwareBazaar into ~/malwarecage
    (delivered as password-protected zips; NOT unzipped locally). --no-download skips this.
  - Recursively scans ~/malwarecage (C:\Users\<you>\malwarecage on Windows)
  - Uploads each file to MetaDefender with archive password "infected"
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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


# MetaDefender targets. API_BASE is reassigned in main() based on --target.
# Cloud has a /v4 path prefix; Core (local) does not.
CLOUD_API_BASE = "https://api.metadefender.com/v4"
LOCAL_API_BASE = "http://127.0.0.1:8008"  # MetaDefender Core on this laptop
API_BASE = CLOUD_API_BASE

# API keys are read from the environment (no secrets stored in this file):
#   OPSWAT_API_KEY        -> MetaDefender Cloud (work account)
#   OPSWAT_LOCAL_API_KEY  -> MetaDefender Core (local, 127.0.0.1:8008)
#   MALWAREBAZAAR_API_KEY -> MalwareBazaar Auth-Key
# Each can also be passed explicitly via --api-key / --mb-api-key.

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
    17: "Encrypted",
    18: "Exceeded file size",
    19: "Partially scanned",
    20: "Potentially unwanted app",
    21: "Potentially vulnerable app",
    22: "Known threat",
    23: "Possible threat",
    24: "No scan results",
    253: "Not scanned / rate limit exceeded",
    254: "In progress",
    255: "Queued / pending",
}


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


def run_download_phase(args: argparse.Namespace, dest_dir: Path) -> None:
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
    print(
        f"[mb] {len(candidates)} candidate(s); downloading up to {count} "
        f"password-protected zip(s) (NOT unzipped locally)."
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
    if progress_percent(report) >= 100:
        return True

    code = scan_code(report)

    if code is not None and code not in (254, 255):
        return True

    return False


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    file_info = as_dict(report.get("file_info"))
    scan_results = as_dict(report.get("scan_results"))
    sanitized = as_dict(report.get("sanitized"))
    sandbox = as_dict(report.get("sandbox"))
    vulnerability = as_dict(report.get("vulnerability"))

    code = scan_code(report)
    verdict = RESULT_LABELS.get(code, f"Unknown code {code}") if code is not None else "Unknown"

    return {
        "display_name": file_info.get("display_name"),
        "sha256": file_info.get("sha256"),
        "file_type": file_info.get("file_type_extension"),
        "verdict": verdict,
        "scan_all_result_i": code,
        "detections": scan_results.get("total_detected_avs"),
        "engines": scan_results.get("total_avs"),
        "threat_name": scan_results.get("threat_name") or report.get("threat_name"),
        "sandbox_verdict": sandbox.get("verdict"),
        "sandbox_threat_level": sandbox.get("threatLevel"),
        "vulnerability_severity": vulnerability.get("severity"),
        "sanitization": sanitized.get("result"),
    }


def print_table(rows: list[dict[str, Any]]) -> None:
    headers = ["File", "Verdict", "AVs", "Type", "Threat", "Sandbox", "CDR"]
    widths = [34, 18, 9, 8, 28, 14, 14]

    def cell(value: Any, width: int) -> str:
        text = "" if value is None else str(value)

        if len(text) > width:
            text = text[: width - 1] + "…"

        return text.ljust(width)

    print()
    print(" ".join(cell(h, w) for h, w in zip(headers, widths)))
    print(" ".join("-" * w for w in widths))

    for row in rows:
        avs = ""

        if row.get("detections") is not None or row.get("engines") is not None:
            avs = f"{row.get('detections', '?')}/{row.get('engines', '?')}"

        values = [
            row.get("display_name"),
            row.get("verdict"),
            avs,
            row.get("file_type"),
            row.get("threat_name"),
            row.get("sandbox_verdict"),
            row.get("sanitization"),
        ]

        print(" ".join(cell(v, w) for v, w in zip(values, widths)))


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
        help=f"Base URL for local MetaDefender Core. Default: {LOCAL_API_BASE}",
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
        help=f'Archive password sent to MetaDefender (archivepwd). Default: "{DEFAULT_ARCHIVE_PASSWORD}".',
    )
    parser.add_argument("--file-password", default=None)

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

    scan_dir = args.scan_dir_flag or args.scan_dir or DEFAULT_SCAN_DIR

    scan_root = Path(scan_dir).expanduser()
    output_dir = Path(args.out).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_download:
        run_download_phase(args, scan_root)

    files = iter_files(scan_root)

    if not files:
        print(f"No regular files found under {scan_root}")
        return 0

    session = requests.Session()
    session.headers.update({"apikey": api_key})

    submitted: list[SubmittedFile] = []
    summaries: list[dict[str, Any]] = []

    print(f"Target          : {target}  ({API_BASE})")
    print(f"Scan directory  : {scan_root}")
    print(f"Output directory: {output_dir}")
    print(f"Processing rule : {rule or '(Core default workflow)'}")
    print(f"Files found     : {len(files)}")
    print()

    for path in files:
        print(f"[upload] {path}")

        submitted_file = upload_file(
            session,
            path,
            rule=rule,
            private=args.private,
            private_processing=args.private_processing,
            archive_password=args.archive_password,
            file_password=args.file_password,
        )

        submitted.append(submitted_file)

        print(f"         data_id={submitted_file.data_id}")
        print(f"         sha256={submitted_file.sha256}")

        # Delete the local zip once it's safely uploaded (upload_file raises on
        # failure, so we only reach here on success). Non-zip files are left alone.
        if not args.keep_zips and path.suffix.lower() == ".zip":
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
    print()
    print(f"Full reports: {output_dir.resolve()}")
    print(f"Summary JSON: {summary_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())