#!/usr/bin/env python3
"""Hand-crafts a PDF with a benign embedded/attached file - the same general
technique (content hidden inside a PDF container) used by the real
malicious PDFs downloaded into ../steganography/ (which embed XLS files
that trigger CVE-2017-11882), but here the embedded payload is just a plain
text file with no exploit."""

embedded_text = (
    b"This is a plain text file embedded inside a PDF container.\n"
    b"No macro, no exploit, no executable content - just a demonstration\n"
    b"that a PDF can carry an arbitrary hidden attachment a casual viewer\n"
    b"would never notice, the same technique real malware uses to smuggle\n"
    b"a weaponized Office file inside what looks like an ordinary PDF.\n"
)

content_stream = b"""BT
/F1 18 Tf
72 700 Td
(This PDF has a hidden file attachment embedded inside it.) Tj
0 -24 Td
(See the /EmbeddedFiles entry in the document's Name tree.) Tj
0 -24 Td
(Benign payload: a plain .txt file, no macro or exploit.) Tj
ET
"""

objects = []


def obj(n, body):
    objects.append((n, body))


obj(1, b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 7 0 R >> >>")
obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 6 0 R >> >> /Contents 5 0 R >>")
obj(5, b"<< /Length " + str(len(content_stream)).encode() + b" >>\nstream\n" +
       content_stream + b"endstream")
obj(6, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
obj(7, b"<< /Names [(hidden-attachment.txt) 8 0 R] >>")
obj(8, b"<< /Type /Filespec /F (hidden-attachment.txt) /EF << /F 9 0 R >> >>")
obj(9, b"<< /Type /EmbeddedFile /Length " + str(len(embedded_text)).encode() +
       b" >>\nstream\n" + embedded_text + b"endstream")

out = bytearray()
out += b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n"

offsets = {}
for n, body in objects:
    offsets[n] = len(out)
    out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"

xref_offset = len(out)
max_n = max(n for n, _ in objects)
count = max_n + 1
out += f"xref\n0 {count}\n".encode()
out += b"0000000000 65535 f \n"
for n in range(1, count):
    if n in offsets:
        out += f"{offsets[n]:010d} 00000 n \n".encode()
    else:
        out += b"0000000000 00000 f \n"

out += b"trailer\n"
out += f"<< /Size {count} /Root 1 0 R >>\n".encode()
out += b"startxref\n"
out += f"{xref_offset}\n".encode()
out += b"%%EOF"

path = "/home/msimone/malwarecage/hidden-content-demo/Stego-PDF-EmbeddedAttachment-Benign.pdf"
with open(path, "wb") as f:
    f.write(out)
print(f"wrote {len(out)} bytes -> {path}")
