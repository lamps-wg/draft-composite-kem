#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# ML-KEM Algorithm with CMS KEMRecipientInfo
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfcTBD.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc3565
from pyasn1_alt_modules import rfc8619


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Imports from RFC 3565

id_aes128_wrap = rfc3565.id_aes128_wrap

id_aes256_wrap = rfc3565.id_aes256_wrap


# Imports from RFC 8619

id_alg_hkdf_with_sha256 = rfc8619.id_alg_hkdf_with_sha256


# Object Identifiers

nistAlgorithms = univ.ObjectIdentifier('2.16.840.1.101.3.4')

aes = kems = nistAlgorithms + (1, )

kems = nistAlgorithms + (4, )

id_alg_ml_kem_512 = kems + (1, )

id_alg_ml_kem_768 = kems + (2, )

id_alg_ml_kem_1024 = kems + (3, )


# ML-KEM Key Encapsulation Mechanism Algorithms

kema_ml_kem_512 = AlgorithmIdentifier()
kema_ml_kem_512['algorithm'] = id_alg_ml_kem_512
# kema_ml_kem_512['parameters'] are absent

kema_ml_kem_768 = AlgorithmIdentifier()
kema_ml_kem_768['algorithm'] = id_alg_ml_kem_768
# kema_ml_kem_768['parameters'] are absent

kema_ml_kem_1024 = AlgorithmIdentifier()
kema_ml_kem_1024['algorithm'] = id_alg_ml_kem_1024
# kema_ml_kem_1024['parameters'] are absent


# Public Key for use only with the ML-KEM Algorithm 

pk_ml_kem_512 = SubjectPublicKeyInfo()
pk_ml_kem_512['algorithm']['algorithm'] = id_alg_ml_kem_512
# pk_ml_kem_512['algorithm']['parameters'] are absent
# pk_ml_kem_512['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)

pk_ml_kem_768 = SubjectPublicKeyInfo()
pk_ml_kem_768['algorithm']['algorithm'] = id_alg_ml_kem_768
# pk_ml_kem_768['algorithm']['parameters'] are absent
# pk_ml_kem_768['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)

pk_ml_kem_1024 = SubjectPublicKeyInfo()
pk_ml_kem_1024['algorithm']['algorithm'] = id_alg_ml_kem_1024
# pk_ml_kem_1024['algorithm']['parameters'] are absent
# pk_ml_kem_1024['subjectPublicKey'] = univ.BitString.fromOctetString(public_key)


# Key Derivation Functions

kda_hkdf_with_sha256 = AlgorithmIdentifier()
kda_hkdf_with_sha256['algorithm'] = id_alg_hkdf_with_sha256
# kda_hkdf_with_sha256['parameters'] are absent


# Key Wrap Algorithms

kwa_aes128_wrap = AlgorithmIdentifier()
kwa_aes128_wrap['algorithm'] = id_aes128_wrap
# kwa_aes128_wrap['parameters'] are absent

kwa_aes256_wrap = AlgorithmIdentifier()
kwa_aes256_wrap['algorithm'] = id_aes256_wrap
# kwa_aes256_wrap['parameters'] are absent


# No need to update the Algorithm Identifier map or the S/MIME
# Capabilities map because the parameters are always absent.
