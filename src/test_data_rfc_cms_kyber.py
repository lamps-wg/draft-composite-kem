#!/usr/bin/env python

# Used to generate test data for test_rfcTBD.py.
#
# Written by Russ Housley for test_cms_kyber on 12 December 2024.

import os
import base64
import binascii
import textwrap
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5083
from pyasn1_alt_modules import rfc9629
from pyasn1.type import univ, char, tag, constraint
from pyasn1_alt_modules import pem
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

import rfc_cms_kyber

pem_text = """\
MIID8gYLKoZIhvcNAQkQARegggPhMIID3QIBADGCA4ikggOEBgsqhkiG9w0BCRAN
AzCCA3MCAQCAFFmXiMN67UAO5AXRsqM2arF9gkpRMAsGCWCGSAFlAwQEAQSCAwDz
6kG2NhIUhlAHMA3HCeC8G9o0Ey8HMa//d2N7a7e92ba+Xrwfp9NKfiwH3r26CvqG
Aj5LgU/hbzNkFGw1AfgXDQTcpHEjfPB2R/x6OxiuV6KPxOjqHbjDvyRoclHHrGfG
i4uBkgPSAXrBlzXop9n7F4sxae2grAJIWX8sl/Vs6BRcKmuAIXbriZTQnEoojgyr
ncDz3owBMBdLvA7STNEJ9vt3WaGV07/3qjSCHsxynDwWpiHYwf3Q++/VlZNrPnzZ
B/ulQtAWweHxgTpvX0k8WnCKSl9S5qGIMK2Tc4KBMSqb02pkSMDV/YEKCwPyFgIO
hEleCys+umJmUAbGm0cmH0Kev0sHAnYvg02uebvK2xFW6uboTy0Txj8okoy5sP6h
mRekF6qgrEEa3/CjkSAxW9iv986h64UUU0cWZeEaEl0eYR6LOf3e16ZPSYDC8Xo7
VjAZvYuf8QuLlqDCw73Rp+PT+fkFqfY4dxGXwZYMU/UOuQqi2IsT86W8gmsQPhEv
7EvSScX8TJSDsrQOVrGoHc5OymRmuepkn17ORYyrR8iKEDVJEDCGesJbgcCoi2VT
LFdDYOzMn1T6gSsmyg3KGWLqdn8csG/mPjKblyBmlYbM8KT4ICqQx1nBngGUfMIV
+v4wY9s0vcLSTBI5QCbgPRrIzz0B97sZdcp29uXA4Qlz2riuRpn38up1G90BGxvo
lukVQ8djNhhGgC60UJwA3bRn+O2xo/cSBkMSLJIIqA5QSY+zcPu90MqvN1JFkbO6
YJQbtuFvQ9hAmHJNrWRaXRGLJuH8gxUhG2bhOn5jjtgmVdKHx8gFDxHs13IQMHAU
//u5JHvJOnC8HLWPIbMTXa0giC7H22Gf7GMdYVG0pNr37wEJkfd7D4OKM5S0fXH3
4moC701Bgypt0D+inpqd+Vdyzylg5KkkoLcQqiE1tAPYc2FCSJNhZe/xA4/WOkoO
HS6/FvFcNaIxkwmNDl9BM4J+Zv4zxqcrqjSUuRM9r/IepBU22+EltUGXug15v+Mw
DQYLKoZIhvcNAQkQAxwCASAwCwYJYIZIAWUDBAEtBCgSWjJGbANW6249qJezunw8
TekPnqeXQxQsCApolNdBREvHJzVFD8fxMDoGCSqGSIb3DQEHATAeBglghkgBZQME
AS4wEQQM09P1v4RTaKUfxd6/AgEQgA0W/2sAf/+wpWYbxab8BBAcFxeZJbrC7Ifl
jQHB7vah"""

recipient_kid = univ.OctetString(hexValue='599788c37aed400ee405d1b2a3366ab17d824a51')

asn1Spec = rfc5652.ContentInfo()
substrate = pem.readBase64fromText(pem_text)
asn1Object, rest = der_decode(substrate, asn1Spec=asn1Spec)
assert not rest
assert asn1Object.prettyPrint()
assert substrate == der_encode(asn1Object)
assert rfc5083.id_ct_authEnvelopedData == asn1Object['contentType']

aed, rest = der_decode(asn1Object['content'], asn1Spec=rfc5083.AuthEnvelopedData())
assert not rest
assert aed.prettyPrint()
assert asn1Object['content'] == der_encode(aed)
assert 0 == aed['version']

ori = aed['recipientInfos'][0]['ori']
assert rfc9629.id_ori_kem == ori['oriType']
kemri, rest = der_decode(ori['oriValue'], asn1Spec=rfc9629.KEMRecipientInfo())
assert not rest
assert kemri.prettyPrint()
assert ori['oriValue'] == der_encode(kemri)
assert 0 == kemri['version']

assert kemri['rid']['subjectKeyIdentifier'] == recipient_kid
assert kemri['kem']['algorithm'] == rfc_cms_kyber.id_alg_ml_kem_512
assert kemri['kdf']['algorithm'] == rfc_cms_kyber.id_alg_hkdf_with_sha256

print ('')
print ('pem_text = """\\')
print(pem_text)
print ('"""')
