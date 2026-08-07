# OPSWAT Toolbox

A personal collection of OPSWAT / MetaDefender tooling. Each tool lives in its own subfolder with its own README and can be used independently.

## Tools

| Tool | What it does |
|---|---|
| **[opswat-scan-files](opswat-scan-files/)** | Automated MetaDefender sample testing — pulls real malware samples from MalwareBazaar and scans them via MetaDefender Cloud or a local Core instance, then reports verdicts. |
| **[customer-eicar-pdf-test](customer-eicar-pdf-test/)** | Zero-install Python/PowerShell scripts for customers to embed the EICAR test string into their own legit PDF and scan it against their Core instance — no real malware, no dependency on reaching eicar.org. |
| **[demo-stock](demo-stock/)** | A fixed, curated set of samples (steganography, benign hidden-content demos, AI-generated fraud-demo images, a real receipt-forgery research dataset) for customer demos — stable, unlike opswat-scan-files' random ephemeral pulls. |
| **[demo-stock-generator](demo-stock-generator/)** | Scripts that built demo-stock's synthetic/benign content — rerun to make more or different variants. |
| **[demo-stock-fetcher](demo-stock-fetcher/)** | Populates the two parts of demo-stock that can't be committed directly (real malware samples, a large research dataset) — see its README for why. |

## Adding a new tool

1. Create a new subfolder (e.g. `some-new-tool/`) with its own `README.md`.
2. Add a row to the table above.
3. Keep any shared ignore patterns in the repo-root `.gitignore`.

## Access

**Public repo, deliberately** — coworkers and customers can grab anything
here without being added as collaborators. Keep that in mind before adding
anything: real malware samples specifically must go through a fetch-script
pattern (see `demo-stock-fetcher`), never committed directly, since a public
GitHub repo hosting live malware runs into platform acceptable-use policy
regardless of password-protection mitigations.
