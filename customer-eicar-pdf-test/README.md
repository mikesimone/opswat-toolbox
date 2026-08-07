# customer-eicar-pdf-test

Gives a customer a way to prove MetaDefender Core is detecting things,
using only a legitimate file they already have (e.g. a PDF), with no real
malware and no dependency on reaching eicar.org (some customer networks
block it outright).

**For the customer-facing walkthrough, see [INSTRUCTIONS.md](INSTRUCTIONS.md)**
- send them the whole folder plus that file.

## What it does

`embed_and_scan.py` / `Embed-And-Scan.ps1` take an existing PDF and append
a new PDF revision (a standard, spec-legal "incremental update" - the same
mechanism Acrobat uses every time you save an edit) that adds a hidden
`/Names /EmbeddedFiles` attachment named `EICAR-TEST-FILE.com`, containing
the literal 68-byte EICAR test string. The original PDF's bytes are
completely untouched; the file just gains one new object graph at the end.
The attachment is left uncompressed on purpose, so the test string is a
plain, directly-visible byte sequence - detectable both as an extracted
attachment and by a flat signature scan of the whole upload.

Both scripts then upload the result to MetaDefender Core's `/file` API
(same raw-body-plus-headers pattern as `../opswat-scan-files`), poll
`/file/{data_id}` until `progress_percentage` hits 100, and print a
plain-language verdict.

**Zero third-party dependencies on either side deliberately** - customers
can't install anything, so both scripts are pure standard library /
built-in PowerShell. This is also why they don't reuse
`../opswat-scan-files/Opswat_Scan_Files.py` (needs `requests`/`pyzipper`
via pip) even though the upload/poll logic is conceptually the same.

## Why not ADS?

The first approach considered was hiding the EICAR string in an NTFS
Alternate Data Stream. That doesn't work for this purpose: an ADS lives in
NTFS filesystem *metadata*, not in the file's actual byte content. Any tool
that uploads "the file" (a script, a browser, curl, `Invoke-RestMethod`, a
web console) only reads and sends the file's main `:$DATA` stream, so the
ADS bytes never leave the customer's disk and never become part of the
upload at all. Embedding inside the PDF's actual byte structure, as this
tool does, guarantees the EICAR string is genuinely part of the bytes being
uploaded and scanned.

## Scope / limitations

The PDF editing is a small hand-rolled parser (regex over the trailer /
Catalog object), not a full PDF library - by design, since a full library
would be another thing to install. It handles the common case: a PDF with
a classic (uncompressed) `trailer` / `xref` table and an un-encrypted,
not-already-carrying-attachments Catalog. That covers most PDFs (Word/LibreOffice
exports, scans, "Print to PDF"). It will refuse with a clear error message
rather than produce a corrupt file if the source PDF uses compressed
cross-reference streams (some newer PDF generators) or already has
embedded files.

Verified against `Colorado Tech.pdf` (`qpdf --check` clean, `qpdf
--list-attachments` shows `EICAR-TEST-FILE.com`, attachment content is
byte-for-byte the canonical EICAR string). `Embed-And-Scan.ps1` mirrors the
Python logic construct-for-construct but wasn't execution-tested (no
`pwsh`/`powershell` available on the box this was built on) - smoke-test it
in a real PowerShell session before handing it to a customer.

## Usage (internal)

```bash
python3 embed_and_scan.py "Colorado Tech.pdf" --core-url http://127.0.0.1:8008 --api-key "$OPSWAT_LOCAL_API_KEY"
```

```powershell
.\Embed-And-Scan.ps1 -InputPdf "Colorado Tech.pdf" -CoreUrl "http://127.0.0.1:8008" -ApiKey $env:OPSWAT_LOCAL_API_KEY
```

Add `--no-upload` / `-NoUpload` to just produce the file without scanning.
