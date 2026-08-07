<#
.SYNOPSIS
    Embeds the EICAR antivirus test string into a PDF as a hidden attachment
    and writes the result to the local folder.

.DESCRIPTION
    Uses only built-in PowerShell (.NET) - nothing to install, no modules.

    WHAT THIS DOES
    1. Takes a normal, legitimate PDF you already have (e.g. Colorado Tech.pdf).
    2. Adds one small hidden attachment to it containing the EICAR test
       string (https://www.eicar.org/) - a public, harmless string every
       antivirus engine is built to flag as if it were malware, specifically
       so nobody ever needs real malware to test detection.
    3. The original PDF's pages/content are untouched; the file just gains
       one extra embedded-file attachment named EICAR-TEST-FILE.com.
    4. Writes the new file locally. Upload it yourself wherever you want to
       trigger a detection (e.g. the MetaDefender Core web UI or API).

    WHY NOT JUST DOWNLOAD THE REAL EICAR FILE?
    Some networks block eicar.org outright (it looks like malware traffic to
    a web filter). This script builds the exact same standard string locally
    - no download needed.

    WHY NOT AN ALTERNATE DATA STREAM (NTFS ADS)?
    An ADS lives in NTFS filesystem metadata, not in the file's actual
    content bytes. Any tool that uploads a file (a browser, curl,
    Invoke-RestMethod, a scan API) only reads and sends the file's main
    data stream, so the ADS content never leaves the disk and never
    becomes part of the upload at all. This script instead puts the test
    string inside the file's real bytes, in a standard PDF attachment
    structure, so it travels with the upload like any other embedded
    content.

.PARAMETER InputPdf
    Path to the source PDF, e.g. "Colorado Tech.pdf"

.PARAMETER OutPdf
    Where to save the modified PDF. Default: adds "-eicar-test" before the
    extension.

.EXAMPLE
    .\Embed-And-Scan.ps1 -InputPdf "Colorado Tech.pdf"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPdf,

    [string]$OutPdf
)

$ErrorActionPreference = "Stop"

# ISO-8859-1 (Latin1) maps each byte to exactly one character and back, so a
# PDF's raw bytes can round-trip through .NET regex/string operations
# without corrupting any byte value - important since PDFs mix ASCII
# structure with arbitrary binary stream data.
$Latin1 = [System.Text.Encoding]::GetEncoding("ISO-8859-1")

$EicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$AttachmentName = "EICAR-TEST-FILE.com"

function Add-EicarAttachment {
    param([byte[]]$PdfBytes)

    $text = $Latin1.GetString($PdfBytes)

    if (-not $text.StartsWith("%PDF-")) {
        throw "Not a PDF (missing %PDF- header)."
    }

    $trailerMatches = [regex]::Matches($text, 'trailer\s*<<(.*?)>>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($trailerMatches.Count -eq 0) {
        throw "Could not find a classic PDF trailer in this file - it may use compressed cross-reference streams, which this simple script doesn't parse. Try a different, simpler PDF (e.g. one made with 'Print to PDF')."
    }
    $trailerBody = $trailerMatches[$trailerMatches.Count - 1].Groups[1].Value

    $sizeMatch = [regex]::Match($trailerBody, '/Size\s+(\d+)')
    $rootMatch = [regex]::Match($trailerBody, '/Root\s+(\d+)\s+(\d+)\s+R')
    if (-not $sizeMatch.Success -or -not $rootMatch.Success) {
        throw "Trailer is missing /Size or /Root; can't safely edit this PDF."
    }

    $size = [int]$sizeMatch.Groups[1].Value
    $rootNum = [int]$rootMatch.Groups[1].Value
    $rootGen = [int]$rootMatch.Groups[2].Value

    $startxrefMatches = [regex]::Matches($text, 'startxref\s+(\d+)')
    if ($startxrefMatches.Count -eq 0) {
        throw "Could not find startxref in this file."
    }
    $prevOffset = [int64]$startxrefMatches[$startxrefMatches.Count - 1].Groups[1].Value

    $rootObjPattern = "(?:^|[\r\n])$rootNum\s+$rootGen\s+obj\s*<<(.*?)>>\s*endobj"
    $rootObjMatch = [regex]::Match($text, $rootObjPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $rootObjMatch.Success) {
        throw "Could not locate the Catalog object ($rootNum $rootGen obj)."
    }
    $rootDictBody = $rootObjMatch.Groups[1].Value

    if ($rootDictBody -match '/EmbeddedFiles') {
        throw "This PDF already has embedded files; pick a different source file."
    }

    $fileObjNum = $size
    $filespecObjNum = $size + 1
    $namesObjNum = $size + 2

    $newRootDict = $rootDictBody.TrimEnd() + " /Names << /EmbeddedFiles $namesObjNum 0 R >>"

    $ms = New-Object System.IO.MemoryStream
    $ms.Write($PdfBytes, 0, $PdfBytes.Length)
    if ($PdfBytes[$PdfBytes.Length - 1] -ne 10) {
        $ms.WriteByte(10)
    }

    $offsets = @{}

    function Write-Text([System.IO.MemoryStream]$Stream, [string]$Str) {
        $bytes = $Latin1.GetBytes($Str)
        $Stream.Write($bytes, 0, $bytes.Length)
    }

    function Add-Object {
        param([int]$Num, [int]$Gen, [string]$Body)
        $offsets[$Num] = $ms.Length
        Write-Text $ms "$Num $Gen obj`n"
        Write-Text $ms $Body
        Write-Text $ms "`nendobj`n"
    }

    # Updated Catalog - same object number/generation as the original Root.
    # A later revision of the same object number wins, so this is what
    # every PDF reader will use once it reads the new trailer below.
    Add-Object -Num $rootNum -Gen $rootGen -Body "<<$newRootDict>>"

    # EICAR content as an embedded-file stream. Left uncompressed on
    # purpose: the literal test string sits as a plain, directly-visible
    # byte sequence in the file, the same static signature every AV engine
    # already recognizes, whether it's extracted as an attachment or
    # matched by a flat byte scan of the whole upload.
    $efStream = "<< /Type /EmbeddedFile /Length $($EicarString.Length) >>`nstream`n$EicarString`nendstream"
    Add-Object -Num $fileObjNum -Gen 0 -Body $efStream

    $filespec = "<< /Type /Filespec /F ($AttachmentName) /UF ($AttachmentName) /EF << /F $fileObjNum 0 R >> >>"
    Add-Object -Num $filespecObjNum -Gen 0 -Body $filespec

    $namesTree = "<< /Names [($AttachmentName) $filespecObjNum 0 R] >>"
    Add-Object -Num $namesObjNum -Gen 0 -Body $namesTree

    $newSize = $namesObjNum + 1
    $xrefOffset = $ms.Length

    $xrefText = New-Object System.Text.StringBuilder
    [void]$xrefText.Append("xref`n")
    [void]$xrefText.Append("$rootNum 1`n")
    [void]$xrefText.Append(("{0:D10} {1:D5} n `n" -f $offsets[$rootNum], $rootGen))
    [void]$xrefText.Append("$fileObjNum 3`n")
    foreach ($n in @($fileObjNum, $filespecObjNum, $namesObjNum)) {
        [void]$xrefText.Append(("{0:D10} 00000 n `n" -f $offsets[$n]))
    }
    [void]$xrefText.Append("trailer`n<< /Size $newSize /Root $rootNum $rootGen R /Prev $prevOffset >>`nstartxref`n$xrefOffset`n%%EOF")

    Write-Text $ms $xrefText.ToString()

    return $ms.ToArray()
}

# --- Main ---

if (-not (Test-Path -LiteralPath $InputPdf)) {
    Write-Error "File not found: $InputPdf"
    exit 2
}

if (-not $OutPdf) {
    $dir = Split-Path -Parent (Resolve-Path -LiteralPath $InputPdf)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPdf)
    $ext = [System.IO.Path]::GetExtension($InputPdf)
    $OutPdf = Join-Path $dir "$base-eicar-test$ext"
}

Write-Host "Reading:  $InputPdf"
$original = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InputPdf))

try {
    $modified = Add-EicarAttachment -PdfBytes $original
}
catch {
    Write-Error "Could not embed the test string: $($_.Exception.Message)"
    exit 1
}

[System.IO.File]::WriteAllBytes($OutPdf, $modified)
Write-Host "Wrote:    $OutPdf  ($($modified.Length) bytes, original was $($original.Length))"
Write-Host ""
Write-Host "Upload this file yourself (e.g. via the MetaDefender Core web UI or API) to trigger a detection."
exit 0
