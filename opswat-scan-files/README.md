# OPSWAT Scan Files — Sample Testing Script

## What it does

This script automates end-to-end testing of MetaDefender against real malware samples. It has two phases:

**1. Pull test samples from MalwareBazaar** (optional, on by default)
Queries MalwareBazaar for samples — filterable by malware family (e.g. `Emotet`, `AgentTesla`) or file type (e.g. `exe`, `dll`) — and downloads up to N of them into `~/malwarecage` as password-protected ZIPs (`infected`).

**2. Scan with MetaDefender**
By default, prompts whether to extract each ZIP locally before uploading (`--unzip`/`--no-unzip`, see below); either way, recursively walks the scan directory, uploads each file to either MetaDefender Cloud or a local MetaDefender Core instance, and polls until each scan completes. Left archived, uploads use rule `multiscan,unarchive,sanitize` so MetaDefender unpacks the ZIP server-side. It deletes each local file immediately once successfully uploaded, prints a results table, and saves full JSON reports plus a `summary.json`.

## Why I built this

I wanted a repeatable, one-command way to pull fresh, real-world malicious samples and run them through our MetaDefender setup — for demos, regression-checking detection/sanitization behavior, and validating Cloud vs. Core configs — without manually hunting for samples or handling unencrypted malware on disk.

## Environment setup

Requires Python 3.9+, `requests`, and `pyzipper` (for `--unzip` — MalwareBazaar's zips are AES-256 encrypted, which the standard library's `zipfile` can't decrypt):
```bash
pip install requests pyzipper
# Debian/Ubuntu with an externally-managed Python may need:
pip install --user --break-system-packages requests pyzipper
```

Set whichever of these you need as environment variables (script prompts/errors clearly if a required one is missing):

| Variable | Purpose |
|---|---|
| `OPSWAT_API_KEY` | MetaDefender Cloud API key |
| `OPSWAT_LOCAL_API_KEY` | MetaDefender Core (local) API key |
| `OPSWAT_LOCAL_URL` | MetaDefender Core base URL (optional; default `http://127.0.0.1:8008`) |
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar Auth-Key |

**macOS / Linux** — add to `~/.bashrc` or `~/.zshrc`:
```bash
export OPSWAT_API_KEY="your_cloud_api_key_here"
export OPSWAT_LOCAL_API_KEY="your_local_core_api_key_here"
export OPSWAT_LOCAL_URL="http://127.0.0.1:8008"   # only if Core isn't on localhost
export MALWAREBAZAAR_API_KEY="your_malwarebazaar_authkey_here"
```
Then `source ~/.bashrc` or open a new terminal.

**Windows** — add to `$PROFILE` (PowerShell):
```powershell
$env:OPSWAT_API_KEY = "your_cloud_api_key_here"
$env:OPSWAT_LOCAL_API_KEY = "your_local_core_api_key_here"
$env:OPSWAT_LOCAL_URL = "http://127.0.0.1:8008"   # only if Core isn't on localhost
$env:MALWAREBAZAAR_API_KEY = "your_malwarebazaar_authkey_here"
```
If you don't know your profile path, `notepad $PROFILE` will create/open it. These take effect in new PowerShell sessions only.

Only set the keys for the paths you plan to use (e.g. skip `MALWAREBAZAAR_API_KEY` if you'll always pass `--no-download`).

**If you use `--unzip`, exclude the scan directory from your antivirus/EDR.** With samples extracted to plaintext, an on-access scanner can quarantine a file between extraction and upload (or between upload and cleanup), which the script now survives per-file but which still means lost samples/skipped scans. On sixofone (Cisco Secure Endpoint), the fix was a policy path exclusion for `/home/.*/malwarecage`, then `sudo systemctl restart cisco-amp.service` to pick it up — see `Infrastructure/sixofone.md` in the `Environment` repo. Exclude whatever directory `--dir`/`OPSWAT_LOCAL_URL` scanning points at on your own box.

## Options you'll fill in as it runs

Run with no arguments for a fully interactive prompt, or pass flags to skip any prompt:

| Prompt / Flag | What it controls |
|---|---|
| Cloud or Local Core (`--target`) | Where files get scanned (default: local) |
| `--local-url` | Local Core base URL (overrides `OPSWAT_LOCAL_URL`; default `http://127.0.0.1:8008`) |
| Unzip before uploading (`--unzip` / `--no-unzip`) | Extract zips locally before upload instead of sending them archived (default: yes). Each extracted file is deleted immediately after its own successful upload, and no `archivepwd` is sent for it. Zips left archived still get `archivepwd` and are unpacked by MetaDefender server-side. |
| Download count (`--count`) | How many MalwareBazaar samples to pull (default: 5) |
| File types (`--file-types`) | Comma-separated filter, e.g. `exe,dll` (blank = any) |
| Malware families (`--families`) | Comma-separated filter, e.g. `AgentTesla,Emotet` (blank = random) |
| `--no-download` | Skip MalwareBazaar entirely, just scan an existing folder |
| `--dir` / positional arg | Directory to scan (default: `~/malwarecage`) |
| `--out` | Where JSON reports get saved (default: `~/opswat/results`) |
| `--rule` | Override processing rule (Cloud default: `multiscan,unarchive,sanitize`) |
| `--private` | Sets `samplesharing: 0` |
| `--private-processing` | Sets `privateProcessing: 1` (requires eligible account) |
| `--archive-password` / `--file-password` | Override archive/file passwords sent to MetaDefender |
| `--keep-zips` | Keep local ZIPs after upload instead of deleting them |
| `--poll-seconds` / `--max-wait-seconds` | Polling interval and timeout while waiting on scan results |

## What to expect as output

Console output shows, per file: upload confirmation with `data_id`/`sha256`, then live polling progress (`progress=% status=...`) until the scan completes. At the end, a results table prints:

```
File          Verdict     AVs     Type   Threat          Sandbox   CDR
------------  ----------  ------  -----  --------------  --------  --------
sample.exe    Infected    42/45   exe    Trojan.Generic  malicious sanitized
```

Full per-file JSON reports are saved to `~/opswat/results/<filename>.<sha256_prefix>.json`, and a consolidated `summary.json` (verdicts, detection counts, sandbox/vulnerability/sanitization results for every file) lands in the same folder.
