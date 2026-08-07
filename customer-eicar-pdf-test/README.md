# Prove your MetaDefender Core detection is working

A quick, safe way to see MetaDefender Core catch a threat — using a PDF you
already have, no real malware, and nothing to install.

## What this does

This tool takes a normal PDF you already have and adds one small, hidden
attachment to it containing the **EICAR test string** — a public, harmless
string that every antivirus engine in the world is built to recognize and
flag exactly as if it were a virus. Security teams have used it this way
for over 20 years, and it cannot harm your computer.

It doesn't rely on downloading anything from eicar.org either, so it still
works on networks that block that site outright.

Your original PDF is never touched — the tool creates a new copy next to
it with the test attachment inside.

## Get started

👉 **[Follow the step-by-step walkthrough](INSTRUCTIONS.md)** — pick the
Windows or Mac/Linux section, copy one command, and go.

Quick preview of what you'll run:

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\Embed-And-Scan.ps1 -InputPdf "YourFile.pdf"
```

```bash
# Mac / Linux
python3 embed_and_scan.py "YourFile.pdf"
```

Either script will ask for your MetaDefender Core URL and API key if you
haven't set them ahead of time — see [INSTRUCTIONS.md](INSTRUCTIONS.md) for
details, including how to skip that prompt next time.

## Is this safe?

Yes. The scripts only ever write the standard, public EICAR test string
(look it up at eicar.org if you'd like to verify it yourself) — never real
malware, and nothing is downloaded from the internet. Your own antivirus
may flag the *output* PDF the moment it's created on disk — that's
expected, and it's actually a good sign.

## Questions or issues?

Send your OPSWAT contact the full console output and we'll help
troubleshoot.

---

Looking for engineering details — how the PDF embedding works, why it
doesn't use an NTFS Alternate Data Stream, or current known limitations?
See [TECHNICAL.md](TECHNICAL.md).
