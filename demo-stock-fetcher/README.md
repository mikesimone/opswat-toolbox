# demo-stock-fetcher

Populates the two parts of [`demo-stock`](../demo-stock/) that can't live in
this repo directly:

1. **Real, curated malware samples** (`demo-stock/steganography/`) - specific
   known-hash MalwareBazaar downloads, not random ones (see
   `CURATED_SAMPLES` in `fetch_demo_stock.py`).
2. **The L3i/ICDAR 2023 "Find it again!" receipt-forgery research dataset**
   (`demo-stock/findit2-benchmark/`) - ~674MB zip, ~1GB / ~1,977 files
   extracted.

## Why a fetch script instead of committing the files

Two different reasons, one per folder:

- **Real malware** - `opswat-toolbox` is a **public** repo, intentionally (so
  coworkers and customers can grab it without being added as collaborators).
  Committing actual malicious files to a public GitHub repo runs into
  GitHub's malware/acceptable-use policies regardless of the
  password-protected-zip mitigation (MalwareBazaar's standard `infected`
  password) - this isn't about whether it's a good idea, it's a
  platform-policy problem. The repo's own root `.gitignore` already excludes
  `malwarecage/`/`*.zip` for exactly this reason. This script re-downloads
  the *same specific curated hashes* directly from MalwareBazaar, so every
  coworker gets the identical stock without any malware bytes ever touching
  git/GitHub itself.
- **The research dataset** - not a policy problem, just size: committing
  ~1GB directly would permanently bloat every future clone of this repo.
  Re-fetched fresh instead.

## Running it

```
export MALWAREBAZAAR_API_KEY=...   # see bazaar.abuse.ch for a free key
python3 fetch_demo_stock.py
```

Safe to re-run - skips anything already present, so a second run after an
interrupted first one just picks up where it left off. The malware part
(6 small files) takes seconds; the research-dataset part (674MB) takes a few
minutes depending on your connection. Verified end-to-end 2026-07-27: all 6
samples fetched with correct byte sizes, findit2-benchmark extracted to
exactly 1,977 files, and a repeat run correctly detected everything already
present and skipped without re-downloading.

## A third dataset that deliberately isn't here

Scam-AI's `gpt4o-receipt` (AI-generated receipts, genuinely good demo
content - real finding is that AI-generated receipts fail on **arithmetic
incoherence**, not visual appearance) is not fetched by this script and
never will be by default: it's CC BY-NC-SA 4.0, gated behind a HuggingFace
click-through that says "non-commercial research purposes only," which a
vendor sales demo isn't. If you specifically want it for internal testing,
download it yourself after accepting HuggingFace's gate - don't add it to
this fetcher without re-checking that reasoning.
