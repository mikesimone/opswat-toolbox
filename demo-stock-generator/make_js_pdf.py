#!/usr/bin/env python3
"""Hand-crafts a minimal, valid PDF whose /OpenAction runs a benign
JavaScript alert() on open - the classic "hidden executable content in a
PDF" demo, entirely benign (no exploit, no payload beyond the alert)."""

content_stream = b"""BT
/F1 18 Tf
72 700 Td
(This PDF contains hidden JavaScript.) Tj
0 -24 Td
(It runs automatically via /OpenAction when opened in a JS-capable reader.) Tj
0 -24 Td
(Benign demo payload: a single app.alert\\(\\) call - see the OpenAction object.) Tj
ET
"""

js_code = (
    b"app.alert('Hello, World! This PDF just executed hidden JavaScript "
    b"on open. A JPG or PDF viewer that lets this run unsandboxed is "
    b"exactly the kind of hidden-content risk Deep CDR is built to strip.');"
)

objects = []


def obj(n, body):
    objects.append((n, body))


obj(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 6 0 R >> >> /Contents 5 0 R >>")
obj(4, b"<< /S /JavaScript /JS (" + js_code + b") >>")
obj(5, b"<< /Length " + str(len(content_stream)).encode() + b" >>\nstream\n" +
       content_stream + b"endstream")
obj(6, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

out = bytearray()
out += b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"  # standard binary-marker comment

offsets = {}
for n, body in objects:
    offsets[n] = len(out)
    out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"

xref_offset = len(out)
count = len(objects) + 1
out += f"xref\n0 {count}\n".encode()
out += b"0000000000 65535 f \n"
for n, _ in objects:
    out += f"{offsets[n]:010d} 00000 n \n".encode()

out += b"trailer\n"
out += f"<< /Size {count} /Root 1 0 R >>\n".encode()
out += b"startxref\n"
out += f"{xref_offset}\n".encode()
out += b"%%EOF"

path = "/home/msimone/malwarecage/hidden-content-demo/Stego-PDF-Javascript-HelloWorld.pdf"
with open(path, "wb") as f:
    f.write(out)
print(f"wrote {len(out)} bytes -> {path}")
