#!/usr/bin/env python3

import os
import re
import sys
import tempfile
import zipfile
from glob import glob

from pyasn1.type import univ
from pyasn1.type.univ import ObjectIdentifier

import generate_test_vectors
from src.generate_test_vectors import REVERSE_OID_TABLE

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

    compatMatrixFile = open(f"output/certs/compatMatrices/artifacts_certs_r5/{prov}_composite-ref-impl.csv", 'w')
    compatMatrixFile.write("key_algorithm_oid,type,test_result\n")

    zipf = zipfile.ZipFile(infile)
    tmpdir = tempfile.mkdtemp()
    zipf.extractall(tmpdir)

    # Extract the artifacts zip
    # do a recursive search to be robust to extra layers of folders in the zip
    for filename in glob(tmpdir+'/**/*_priv.der', recursive=True):

        # support only single format private keys (<friendlyname>-<oid>_priv.der)
        if "_seed_priv.der" in filename or \
           "_expandedkey_priv.der" in filename or \
           "_both_priv.der" in filename:
            print(f"skipping multiformat private key... filename={filename}")
            continue

        try:
            OID_str = re.search(r'(.*)-(([0-9]+\.?)*)_.*', filename).groups()[1]
        except:
            print(f"Could not parse this file name, skipping. {filename}")
            continue

        # check if the OID in the file name is a supported composite
        OID: ObjectIdentifier = univ.ObjectIdentifier(OID_str)
        algorithm_name = REVERSE_OID_TABLE.get(OID)

        if algorithm_name is None:
            print(f"DEBUG: OID does not represent a composite (at least not of this version of the draft): {OID}")
            continue

        print(f"\nProcessing {algorithm_name} from {filename}")

        # read artifacts
        try:
            # R5 format, see http://github.com/IETF-Hackathon/pqc-certificates?tab=readme-ov-file#zip-format-r5
            priv_bytes = read_bytes(filename=filename) # TODO Windows paths
            cert_bytes = read_bytes(f"{filename.strip("_priv.der")}_ee.der")
            ciphertext_bytes = read_bytes(f"{filename.strip("_priv.der")}_ciphertext.bin")
            shared_secret_bytes = read_bytes(f"{filename.strip("_priv.der")}_ss.bin")
        except Exception as e:
            print(f"Failed to read artifacts for OID {OID_str}: {e}")
            continue

        # the actual validation
        try:
            validation_result = generate_test_vectors.validatePrivateKey(priv_bytes, cert_bytes, ciphertext_bytes, shared_secret_bytes) # TODO
        except Exception as e:
            print(f"Exception during validation: {e}")
            continue

        # report result
        print(f"\tPrivate key validation result: {str(validation_result)}")
        if validation_result:
            compatMatrixFile.write(OID_str+",cert,Y\n")
        else:
            compatMatrixFile.write(OID_str+",cert,N\n")
