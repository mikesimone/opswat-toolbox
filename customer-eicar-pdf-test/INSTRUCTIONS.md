# How to test MetaDefender detection with your own PDF

This test proves your MetaDefender Core is actually catching bad files,
without needing a real virus and without visiting any "malware test" website
that your network might block.

It works by taking a normal PDF you already have and adding one small,
hidden attachment inside it containing the **EICAR test string** - a public,
harmless string that every antivirus product in the world is built to
recognize and flag exactly as if it were a virus. Security teams have used
it for this exact purpose for over 20 years. It cannot harm your computer.

You do **not** need to install anything. Pick the section below for your
operating system.

---

## Windows (PowerShell)

1. Copy the whole `customer-eicar-pdf-test` folder to your computer.
2. Put a copy of the PDF you want to test in that same folder (or note its
   full path).
3. Get two things from whoever manages your MetaDefender Core:
   - The **Core URL** (looks like `http://something:8008`)
   - Your **API key**
4. Right-click in the folder → "Open in Terminal" (or open PowerShell and
   `cd` into the folder).
5. Run this command, replacing the file name with your PDF's actual name:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Embed-And-Scan.ps1 -InputPdf "Colorado Tech.pdf"
   ```

   (The `-ExecutionPolicy Bypass` part is just there so Windows doesn't
   block the script from running one time - it doesn't install or change
   anything permanently.)

6. It will ask for your Core URL and API key if you didn't set them ahead
   of time (see "Optional: skip the prompts" below). Paste them in and
   press Enter.
7. Watch the output. You'll see it build the file, upload it, and then
   print scanning progress. At the end you'll see something like:

   ```
   ============================================================
   RESULT: Infected
   Engines that flagged it: 12/40
   Reported as: EICAR-Test-File, EICAR_Test_File
   ============================================================
   This means MetaDefender Core successfully detected the test file.
   ```

   **That "RESULT: Infected" line is what you want to see.** It means
   detection is working.

### If it says "No engine flagged this file"

Something's off with the Core setup itself (e.g. no AV engines
licensed/enabled) - it's not a problem with the test file. Send us the full
console output and we'll help troubleshoot.

### Optional: skip the prompts

If you'll run this more than once, set these once per PowerShell window
before running the script, and it won't ask again:

```powershell
$env:OPSWAT_LOCAL_URL = "http://your-core-host:8008"
$env:OPSWAT_LOCAL_API_KEY = "your_api_key_here"
```

---

## Mac / Linux (Python)

1. Copy the whole `customer-eicar-pdf-test` folder to your computer.
2. Put a copy of the PDF you want to test in that same folder (or note its
   full path).
3. Get two things from whoever manages your MetaDefender Core:
   - The **Core URL** (looks like `http://something:8008`)
   - Your **API key**
4. Open a Terminal and `cd` into the folder.
5. Check you have Python 3 already (most Macs and all Linux systems do):

   ```bash
   python3 --version
   ```

   If that fails, you have an older Mac - use `python` instead of `python3`
   in the next step.

6. Run:

   ```bash
   python3 embed_and_scan.py "Colorado Tech.pdf"
   ```

7. It will ask for your Core URL and API key if you didn't set them ahead
   of time (see below). Paste them in and press Enter.
8. Watch the output, same as the Windows steps above - you want to see
   `RESULT: Infected` at the end.

### Optional: skip the prompts

```bash
export OPSWAT_LOCAL_URL="http://your-core-host:8008"
export OPSWAT_LOCAL_API_KEY="your_api_key_here"
```

---

## What if I don't want the script to upload anything itself?

Add `--no-upload` (Python) or `-NoUpload` (PowerShell) and it will just
build the modified PDF next to your original one and stop. Then you can
drag-and-drop that file into the MetaDefender Core web console yourself.

```bash
python3 embed_and_scan.py "Colorado Tech.pdf" --no-upload
```

```powershell
.\Embed-And-Scan.ps1 -InputPdf "Colorado Tech.pdf" -NoUpload
```

The new file is saved right next to your original, named
`<your file>-eicar-test.pdf`. Your original file is never changed.

## Is this safe to run on a work laptop / send to IT?

Yes. The script only ever writes the standard, public EICAR test string
(look it up at eicar.org if you want to verify it yourself) - never real
malware, never anything downloaded from the internet. Your antivirus may
itself flag the *output* PDF the moment it's created on disk - that's
expected and is actually a good sign.
