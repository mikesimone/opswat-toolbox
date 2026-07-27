# demo-stock - permanent samples for OPSWAT/MetaDefender demos

Unlike `opswat-scan-files`' own MalwareBazaar puller (random, ephemeral,
expected to be cleaned up), everything here is a **fixed, curated set**
meant to give customer demos a stable stable of samples instead of whatever
random. Built 2026-07-27.

This folder holds the actual data. Two subfolders are checked into git
directly; two more get created locally by running
[`demo-stock-fetcher`](../demo-stock-fetcher/) once - see that tool's README
for why they aren't just committed, and [`demo-stock-generator`](../demo-stock-generator/)
for how the synthetic content here was made (and how to make more/different
variants).

## Checked into git

### `hidden-content-demo/` - benign, synthetic (safe to open/show freely)

No malicious payload in any of these - safe to actually open in front of a
customer.

| File | What it demonstrates |
|---|---|
| `Stego-PDF-Javascript-HelloWorld.pdf` | A PDF whose `/OpenAction` runs a single `app.alert()` call on open - the simplest possible "this file executes hidden code when you open it" demo. Hand-crafted minimal PDF, validated with `qpdf --check`. |
| `Stego-PDF-EmbeddedAttachment-Benign.pdf` | A PDF carrying a hidden embedded/attached plain-text file, the same general technique the real malicious "embedded XLS" PDFs below use, minus the exploit. Confirmed extractable via `qpdf --list-attachments`. |
| `Stego-PNG-LSB-HiddenText-Benign.png` | An ordinary-looking AI-generated stock photo with a benign text message hidden in the image's least-significant bits (classic LSB steganography). Visually indistinguishable from a normal photo; message round-trip verified via `demo-stock-generator/lsb_embed.py`. |

### `ai-generated-samples/` - synthetic/AI-generated, deliberately absurd content

For demoing an AI-generated-content detection tool. Each image depicts
content so absurd it can't be mistaken for a real fraud attempt, while still
being realistic enough in *rendering* to meaningfully test detection.

| File | What it is |
|---|---|
| `AI-Generated-ToyCarAccident-InsuranceClaimDemo.png` | Genuine diffusion-model output (ComfyUI, `Juggernaut-XL_v9_RunDiffusionPhoto_v2`): two Hot Wheels-scale diecast toy cars, photographed like a real accident-claim photo - obviously toys, not real vehicles. |
| `AI-Generated-MoonInvoice-FraudDemo.png` | Composed, not diffusion (SDXL can't render legible line-item text - see `demo-stock-generator`'s README). A professional-looking invoice billed to "The Moon" for $1,000,000,000,000,000.00. |
| `AI-Generated-UnicornMeadowReceipt-FraudDemo.png` | Same reasoning, receipt format - "Unicorn tears," "Dragon scale," paid via a "Narnia" gift card. |

## Populated by `demo-stock-fetcher` (not committed to git)

Run `python3 ../demo-stock-fetcher/fetch_demo_stock.py` once (needs
`MALWAREBAZAAR_API_KEY` in the environment) to create these two folders.
Safe to re-run - skips anything already present.

### `steganography/` - real, malicious samples (from MalwareBazaar)

Delivered as password-protected zips (password `infected`, MalwareBazaar's
standard convention) - **do not unzip locally on a machine without an
endpoint-security exclusion for wherever you put this** (Six's exclusion is
documented in `~/Environment/Infrastructure/sixofone.md` if you need a
reference for setting up your own). Let MetaDefender unpack server-side
instead.

| File | Original MalwareBazaar SHA256 | What it is |
|---|---|---|
| `Stego-ZIP-SteganoAmor-Receipt-Lure.zip` | `d6c42166e11a471b6c38d717461f566a183d5e1cd0264f84ec85a1ffedb1db84` | SteganoAmor campaign - a fake "E_receipt" lure zip containing a VBS that pulls a payload hidden in a steganographic image. Good thematic fit for a receipt-lure demo. |
| `Stego-PNG-ParallaxRAT-ImgurHosted.zip` | `fd2b36e1b27cd6c92386078e92c5287e770fa55fabd78a4522b910381d453c11` | A PNG hosted on imgur, carrying a hidden Parallax RAT payload in its pixel data. |
| `Stego-PNG-IcedID-Loader.zip` | `554401e1eb3654d011c42fb6f2c71e99e6ac8d6194d1087769a4b789db2f3f8c` | A PNG used by an IcedID loader to smuggle its payload. |
| `Stego-EXE-DotNet-Steganography.zip` | `523774fc29fdf6520bb3f0213d474d9909e63bcd44bfbafb57037eb26d19b6e5` | A .NET executable with an embedded steganographic payload. |
| `Stego-PDF-EmbeddedXLS-PaymentReceipt-AgentTesla.zip` | `54c3c13b6bd236bab7971c6635866b4ca335727e6f96f66491edabae3cbc65cd` | A PDF literally named "Payment Receipt INV21-0162.pdf" with an embedded XLS exploiting CVE-2017-11882, delivering AgentTesla. Great "this looked legit" pitch. |
| `Stego-PDF-CVE-2017-11882-SwiftCopy-XLoader.zip` | `5e303fd9317236b55429aedd5c7aa133f3ea9dd2a50402930c50c5fbcc6e27e6` | A PDF ("SWIFT COPY.pdf") with the same embedded-exploit technique, delivering XLoader. |

Picked via MalwareBazaar's `steganography` and `embedded` tags, cross-checked
against `file_type=pdf`. Want a different sample from the same pool? Query
`get_taginfo`/`get_file_type` against those tags directly.

### `findit2-benchmark/` - real receipt-forgery research data

The L3i/ICDAR 2023 "Find it again!" dataset: 988 scanned receipts, 163 with
realistic fraudulent modifications, plus `train.txt`/`test.txt`/`val.txt`
ground truth with **pixel-region forgery annotations** (exact bounding box,
forgery type e.g. "CPI" copy-paste-insert, entity type e.g. Product/
Total-payment/Metadata for every modified field) - genuinely good demo
material on its own merits.

No explicit license stated on the source page - that's *not* the same as
cleared for commercial use. Treat as internal-validation-safe; email the
authors before using it as actual customer-facing collateral.

## Not in this repo at all

A third, separate dataset (Scam-AI's `gpt4o-receipt` - AI-generated receipts
with a genuinely interesting "arithmetic incoherence is the real tell, not
visual appearance" finding) is **explicitly not included here** - it's
licensed CC BY-NC-SA 4.0 with a click-through gate that says "non-commercial
research purposes only," which a vendor sales demo isn't. It stays local to
whoever downloaded it, for internal testing/validation only. Ask about it
separately if you want details - don't go looking for it in this repo.
