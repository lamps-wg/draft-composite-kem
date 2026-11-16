#!/usr/bin/env python3
"""Split testvectors.json into one PEM file per end-entity certificate (x5c).
Each PEM contains the EE cert followed by the top-level "cacert" cert.
Also writes testvectors_combined.pem: all EE certs, then one copy of cacert.

Usage: python3 testvectors_to_pem.py [testvectors.json] [outdir]
Defaults: testvectors.json -> ./testvectors_pem
"""
import base64
import json
import sys
import textwrap
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "testvectors.json")
outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "testvectors_pem")


def to_pem(b64_der):
    b64 = base64.b64encode(base64.b64decode(b64_der)).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(b64, 64)) + "\n-----END CERTIFICATE-----\n"


with open(src) as f:
    data = json.load(f)

outdir.mkdir(parents=True, exist_ok=True)
ca_pem = to_pem(data["cacert"])

combined = []
for tc in data["tests"]:
    ee_pem = to_pem(tc["x5c"])
    (outdir / f"{tc['tcId']}.pem").write_text(ee_pem + ca_pem)
    combined.append(ee_pem)

# all EE certs, then a single copy of the CA cert at the end
(outdir / "testvectors_combined.pem").write_text("".join(combined) + ca_pem)

print(f"Wrote {len(data['tests'])} certificates to {outdir}/")
