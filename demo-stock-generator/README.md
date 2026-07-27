# demo-stock-generator

The scripts that made the synthetic/benign content in
[`demo-stock`](../demo-stock/) - kept here as their own tool so they're easy
to find, rerun, or adapt for a new variant. All tested and working as of
2026-07-27.

Run under `/opt/ComfyUI/venv/bin/python` on Six (has Pillow already), or any
Python 3 with Pillow installed for the ones that don't call ComfyUI:

```
/opt/ComfyUI/venv/bin/python make_receipt.py
```

| Script | Produces | Notes |
|---|---|---|
| `make_invoice.py` | `demo-stock/ai-generated-samples/AI-Generated-MoonInvoice-FraudDemo.png` | Pure PIL composition - **no diffusion model involved**, see below for why. Right-aligned numeric columns via `textlength()` to avoid an overlap bug an earlier column-position version hit with very large dollar figures. |
| `make_receipt.py` | `demo-stock/ai-generated-samples/AI-Generated-UnicornMeadowReceipt-FraudDemo.png` | Same idea, thermal-receipt style (monospace font, narrow width). |
| `make_js_pdf.py` | `demo-stock/hidden-content-demo/Stego-PDF-Javascript-HelloWorld.pdf` | Hand-crafts a minimal valid PDF byte-for-byte (no PDF library was available in the venv at the time) - `/OpenAction` -> a JavaScript action object -> a single `app.alert()` call. Validate any output with `qpdf --check`. |
| `make_embedded_pdf.py` | `demo-stock/hidden-content-demo/Stego-PDF-EmbeddedAttachment-Benign.pdf` | Same hand-crafted-PDF approach, but with a `/Names /EmbeddedFiles` entry carrying a benign attached `.txt` file instead of a JS action. Validate with `qpdf --list-attachments`. |
| `lsb_embed.py` | `demo-stock/hidden-content-demo/Stego-PNG-LSB-HiddenText-Benign.png` | Generic least-significant-bit embed/extract for any image - `embed`/`extract` subcommands. Used against a ComfyUI-generated stock-photo carrier. |
| `comfy_gen.py` | (a dependency, not a file itself) | Minimal ComfyUI `/prompt` API client - submit a basic SDXL txt2img workflow, poll `/history`, fetch the result via `/view`. Used to generate the toy-car photo and the LSB carrier photo. Needs a running ComfyUI (`http://127.0.0.1:8188` on Six) with an SDXL checkpoint. |

## Why some outputs aren't diffusion output

SDXL-family models (including `Juggernaut-XL_v9_RunDiffusionPhoto_v2`, this
box's go-to photoreal checkpoint) cannot reliably render coherent small
text - an early attempt at generating the Moon invoice via ComfyUI produced a
correctly-structured invoice *layout* with completely garbled line-item
numbers, useless for a demo that depends on the customer actually reading
"$1,000,000,000,000,000." The invoice and receipt were built directly with
PIL instead - what makes them obviously fake is the content, not the
generation technique.
