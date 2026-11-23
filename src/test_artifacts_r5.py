#!/usr/bin/env python3

import os
import re
import sys
import tempfile
import zipfile
from glob import glob

from pyasn1.type import univ

import generate_test_vectors
from generate_test_vectors import REVERSE_OID_TABLE

_USAGE_STR = "Usage: test_artifacts_r5.py [provider] [artifact zip filename]"

def read_bytes(filename: str) -> bytes:
    if not os.path.isfile(filename):
        raise RuntimeError(f"File expected, but does not exist: {filename}")

    with open(filename, "rb") as f:
        return f.read()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        exit(_USAGE_STR)

    prov = sys.argv[1]

    infile = sys.argv[2]
    if infile is None:
        exit("Artifact zip filename is required.\n" + _USAGE_STR)

    print(f"\n\nTesting {prov} / {infile} against {generate_test_vectors.VERSION_IMPLEMENTED}")

    os.makedirs("output/certs/compatMatrices/artifacts_certs_r5", exist_ok=True)

    outfilename = f"output/certs/compatMatrices/artifacts_certs_r5/{prov}_composite-ref-impl.csv"
    append = os.path.isfile(outfilename)
    compatMatrixFile = open(outfilename, 'a')
    if not append:
        # if we're adding on top of the composite-sigs-ref-impl, then don't add the CSV header
        compatMatrixFile.write("key_algorithm_oid,type,test_result\n")

    zipf = zipfile.ZipFile(infile)
    tmpdir = tempfile.mkdtemp()
    zipf.extractall(tmpdir)

    # Extract the artifacts zip
    # do a recursive search to be robust to extra layers of folders in the zip
    # R5 format, see http://github.com/IETF-Hackathon/pqc-certificates?tab=readme-ov-file#zip-format-r5

    # The certs: <friendlyname>-<oid>_ee.der
    for filename in sorted(glob(tmpdir+'/**/*_ee.der', recursive=True)):
        try:
            OID_str = re.search(r'.*-(([0-9]+\.?)*)_ee\.der$', filename).group(1)
        except AttributeError:
            print(f"Could not parse this file name, skipping. {filename}")
            continue

        print(f"\nProcessing cert {filename}")
        try:
            result = generate_test_vectors.verifyCert(read_bytes(filename))
        except LookupError as e:
            print(e)
            continue
        except Exception as e:
            print(f"\tCert failed: {e!r}")
            result = False
        print(f"\tCert result: {result}")
        compatMatrixFile.write(OID_str+",cert,"+("Y" if result else "N")+"\n")

    # The private keys: <friendlyname>-<oid>_[<type>_]priv.der, tested against
    # <friendlyname>-<oid>_ee.der, _ciphertext.bin and _ss.bin
    consistent = {}
    for filename in sorted(glob(tmpdir+'/**/*_priv.der', recursive=True)):
        try:
            filenameprefix, OID_str, keyType = re.search(r'(.*-(([0-9]+\.?)*))_(([a-z]+)_)?priv\.der$', filename).group(1, 2, 5)
        except AttributeError:
            print(f"Could not parse this file name, skipping. {filename}")
            continue
        keyType = keyType or "priv"

        algorithm_name = REVERSE_OID_TABLE.get(univ.ObjectIdentifier(OID_str))
        if algorithm_name is None:
            print(f"DEBUG: OID does not represent a composite (at least not of this version of the draft): {OID_str}")
            continue
        # Section 4 defines one private key form for a composite, the seed form,
        # so any other (e.g. _expandedkey_priv.der) is expected to fail to load
        # and is reported as N. Pure ML-KEM also has expanded forms, which this
        # implementation does not read, so those are skipped.
        if keyType in ("expandedkey", "both") and \
           not isinstance(generate_test_vectors.getNewInstanceByName(algorithm_name), generate_test_vectors.CompositeKEM):
            print(f"skipping multiformat private key... filename={filename}")
            continue

        print(f"\nProcessing private key {filename}")
        try:
            priv_der = read_bytes(filename)
            cert_bytes = read_bytes(f"{filenameprefix}_ee.der")
            ciphertext_bytes = read_bytes(f"{filenameprefix}_ciphertext.bin")
            shared_secret_bytes = read_bytes(f"{filenameprefix}_ss.bin")
        except Exception as e:
            print(f"Failed to read artifacts for OID {OID_str}: {e}")
            continue

        try:
            priv, cons = generate_test_vectors.checkPrivateKey(priv_der, cert_bytes, ciphertext_bytes, shared_secret_bytes)
        except LookupError as e:
            print(e)
            continue
        print(f"\tPrivate key passed: {priv}, consistent with the cert: {cons}")

        compatMatrixFile.write(OID_str+","+keyType+","+("Y" if priv else "N")+"\n")
        consistent[OID_str] = consistent.get(OID_str, True) and cons

    for OID_str, cons in consistent.items():
        compatMatrixFile.write(OID_str+",consistent,"+("Y" if cons else "N")+"\n")
