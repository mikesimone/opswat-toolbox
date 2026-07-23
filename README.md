# OPSWAT Toolbox

A personal collection of OPSWAT / MetaDefender tooling. Each tool lives in its own subfolder with its own README and can be used independently.

## Tools

| Tool | What it does |
|---|---|
| **[opswat-scan-files](opswat-scan-files/)** | Automated MetaDefender sample testing — pulls real malware samples from MalwareBazaar and scans them via MetaDefender Cloud or a local Core instance, then reports verdicts. |

## Adding a new tool

1. Create a new subfolder (e.g. `some-new-tool/`) with its own `README.md`.
2. Add a row to the table above.
3. Keep any shared ignore patterns in the repo-root `.gitignore`.

## Access

Private repo. Collaborators get access to the whole toolbox, so everything here shares the same audience.
