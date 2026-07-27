# demo-stock-fetcher

Populates two things that logically belong to [`demo-stock`](../demo-stock/)
but can't live in this repo, or anywhere in its working tree, at all:

1. **Real, curated malware samples** (`~/malwarecage/steganography/` by
   default) - specific known-hash MalwareBazaar downloads, not random ones
   (see `CURATED_SAMPLES` in `fetch_demo_stock.py`).
2. **The L3i/ICDAR 2023 "Find it again!" receipt-forgery research dataset**
   (`~/malwarecage/findit2-benchmark/` by default) - ~674MB zip, ~1GB /
   ~1,977 files extracted.

## Why a fetch script instead of committing the files - and why it targets `~/malwarecage`, not this repo

Two different reasons, one per folder - but both land outside the repo
entirely, not just gitignored inside it:

- **Real malware** - `opswat-toolbox` is a **public** repo, intentionally (so
  coworkers and customers can grab it without being added as collaborators).
  Committing actual malicious files to a public GitHub repo runs into
  GitHub's malware/acceptable-use policies regardless of the
  password-protected-zip mitigation (MalwareBazaar's standard `infected`
  password) - this isn't about whether it's a good idea, it's a
  platform-policy problem. Separately, and just as important: `~/malwarecage`
  is the directory that's supposed to be excluded from your machine's AV/EDR
  real-time scanning (Six's Cisco Secure Endpoint exclusion is documented in
  `~/Environment/Infrastructure/sixofone.md`). A git checkout of this repo
  has no such exclusion - downloading real malware into `demo-stock/` itself
  (even gitignored, never committed) would still sit unprotected on disk and
  could get quarantined mid-demo. This script re-downloads the *same specific
  curated hashes* directly from MalwareBazaar into `~/malwarecage` instead,
  so every coworker gets the identical stock, protected the same way the
  rest of their MalwareBazaar samples already are, and no malware bytes ever
  touch git/GitHub itself.
- **The research dataset** - not a policy or AV-exclusion problem, just
  size: committing ~1GB directly would permanently bloat every future clone
  of this repo. Re-fetched fresh into `~/malwarecage` alongside the malware
  samples, mostly for consistency (one destination, one exclusion to set up).

## Running it

```
export MALWAREBAZAAR_API_KEY=...   # see bazaar.abuse.ch for a free key
python3 fetch_demo_stock.py                  # -> ~/malwarecage
python3 fetch_demo_stock.py --dest /some/other/excluded/path   # override
```

Set up your AV/EDR exclusion for wherever `--dest` points **before**
running this - default `~/malwarecage` if you haven't already for other
opswat-toolbox work.

Safe to re-run - skips anything already present, so a second run after an
interrupted first one just picks up where it left off. The malware part
(6 small files) takes seconds; the research-dataset part (674MB) takes a few
minutes depending on your connection. Verified end-to-end 2026-07-27: all 6
samples fetched with correct byte sizes, findit2-benchmark extracted to
exactly 1,977 files, and a repeat run correctly detected everything already
present and skipped without re-downloading - including after a path-mismatch
bug where an earlier manual layout had findit2 nested a level deeper than
this script expects; fixed by aligning the manual copy to the same top-level
`~/malwarecage/findit2-benchmark/` layout this script uses.

## A third dataset that deliberately isn't here

Scam-AI's `gpt4o-receipt` (AI-generated receipts, genuinely good demo
content - real finding is that AI-generated receipts fail on **arithmetic
incoherence**, not visual appearance) is not fetched by this script and
never will be by default: it's CC BY-NC-SA 4.0, gated behind a HuggingFace
click-through that says "non-commercial research purposes only," which a
vendor sales demo isn't. If you specifically want it for internal testing,
download it yourself after accepting HuggingFace's gate - don't add it to
this fetcher without re-checking that reasoning.
