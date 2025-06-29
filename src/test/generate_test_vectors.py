#!/usr/bin/env python3

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, x448, padding
import secrets
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization


import datetime
import base64
import json
import textwrap

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5208
from pyasn1_alt_modules import rfc5280
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode



OID_TABLE = {
  "id-RSAES-OAEP-2048": univ.ObjectIdentifier((1,2,840,113549,1,1,7)),
  "id-RSAES-OAEP-3072": univ.ObjectIdentifier((1,2,840,113549,1,1,7)),
  "id-RSAES-OAEP-4096": univ.ObjectIdentifier((1,2,840,113549,1,1,7)),
  "ECDH-P256": univ.ObjectIdentifier((1,2,840,10045,2,1)),
  "ECDH-P384": univ.ObjectIdentifier((1,2,840,10045,2,1)),
  "ECDH-brainpoolP384r1": univ.ObjectIdentifier((1,2,840,10045,2,1)),
  "id-X25519": univ.ObjectIdentifier((1,3,101,110)),
  "id-X448": univ.ObjectIdentifier((1,3,101,111)),
  "id-alg-ml-kem-768": univ.ObjectIdentifier((2,16,840,1,101,3,4,4,2)),
  "id-alg-ml-kem-1024": univ.ObjectIdentifier((2,16,840,1,101,3,4,4,3)),
  "id-MLKEM768-RSA2048-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,50)),
  "id-MLKEM768-RSA3072-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,51)),
  "id-MLKEM768-RSA4096-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,52)),
  "id-MLKEM768-X25519-SHA3-256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,53)),
  "id-MLKEM768-ECDH-P256-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,54)),
  "id-MLKEM768-ECDH-P384-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,55)),
  "id-MLKEM768-ECDH-brainpoolP256r1-HKDF-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,56)),
  "id-MLKEM1024-ECDH-P384-HKDF-SHA384": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,57)),
  "id-MLKEM1024-ECDH-brainpoolP384r1-HKDF-SHA384": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,58)),
  "id-MLKEM1024-X448-SHA3-256": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,59)),
  "id-MLKEM1024-ECDH-P521-HKDF-SHA384": univ.ObjectIdentifier((2,16,840,1,114027,80,5,2,60)),
}


class KEM:
  pk = None
  sk = None
  id = None
  oid = None

  # returns nothing
  def keyGen(self):
    pass
    
  # returns (ct, ss)
  def encap(self):
    if self.pk == None:
      raise Exception("Cannot Encap for a KEM with no PK.")
    pass

  # returns (ss)
  def decap(self, ct):
    if self.sk == None:
      raise Exception("Cannot Decap for a KEM with no SK.")
    pass

  def public_key_bytes(self):
    raise Exception("Not implemented")

  def private_key_bytes(self):
    raise Exception("Not implemented")



class ECDHP256KEM(KEM):
  id = "ECDH-P256"
  oid = univ.ObjectIdentifier((1,2,840,10045))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.SECP256R1())
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = ec.generate_private_key(ec.SECP256R1())
    ss = esk.exchange(ec.ECDH(), self.pk)
    ct = esk.public_key().public_bytes(
                  encoding=serialization.Encoding.X962,
                  format=serialization.PublicFormat.UncompressedPoint
                ) 
    return (ct, ss)

  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct)
    return self.sk.exchange(ec.ECDH(), ct)
  

  def public_key_bytes(self):
    return self.pk.public_bytes(
                      encoding=serialization.Encoding.X962,
                      format=serialization.PublicFormat.UncompressedPoint
                    )

  def private_key_bytes(self):    
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )

  
# skip some copy&paste'ing by inheriting from P256
class ECDHP521KEM(ECDHP256KEM):
  id = "ECDH-P521"
  oid = univ.ObjectIdentifier((1,2,840,10045))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.SECP521R1())
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = ec.generate_private_key(ec.SECP521R1())
    ss = esk.exchange(ec.ECDH(), self.pk)
    ct = esk.public_key().public_bytes(
              encoding=serialization.Encoding.X962,
              format=serialization.PublicFormat.UncompressedPoint
            ) 
    return (ct, ss)
  
  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), ct)
    return self.sk.exchange(ec.ECDH(), ct)
  

# skip some copy&paste'ing by inheriting from P256
class ECDHP384KEM(ECDHP256KEM):
  id = "ECDH-P384"
  oid = univ.ObjectIdentifier((1,2,840,10045))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.SECP384R1())
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = ec.generate_private_key(ec.SECP384R1())
    ss = esk.exchange(ec.ECDH(), self.pk)
    ct = esk.public_key().public_bytes(
              encoding=serialization.Encoding.X962,
              format=serialization.PublicFormat.UncompressedPoint
            ) 
    return (ct, ss)
  
  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), ct)
    return self.sk.exchange(ec.ECDH(), ct)
  


  
# skip some copy&paste'ing by inheriting from P256
class ECDHBP256KEM(ECDHP256KEM):
  id = "ECDH-brainpoolP256r1"
  oid = univ.ObjectIdentifier((1,2,840,10045))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.BrainpoolP256R1())
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = ec.generate_private_key(ec.BrainpoolP256R1())
    ss = esk.exchange(ec.ECDH(), self.pk)
    ct = esk.public_key().public_bytes(
              encoding=serialization.Encoding.X962,
              format=serialization.PublicFormat.UncompressedPoint
            ) 
    return (ct, ss)
  
  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP256R1(), ct)
    return self.sk.exchange(ec.ECDH(), ct)
  

  
# skip some copy&paste'ing by inheriting from P256
class ECDHBP384KEM(ECDHP256KEM):
  id = "ECDH-brainpoolP384r1"
  oid = univ.ObjectIdentifier((1,2,840,10045))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.BrainpoolP384R1())
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = ec.generate_private_key(ec.BrainpoolP384R1())
    ss = esk.exchange(ec.ECDH(), self.pk)
    ct = esk.public_key().public_bytes(
              encoding=serialization.Encoding.X962,
              format=serialization.PublicFormat.UncompressedPoint
            ) 
    return (ct, ss)
  
  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP384R1(), ct)
    return self.sk.exchange(ec.ECDH(), ct)


class X25519KEM(KEM):
  id = "id-X25519"
  oid = univ.ObjectIdentifier((1,3,101,110))

  def keyGen(self):
    self.sk = x25519.X25519PrivateKey.generate()
    self.pk = self.sk.public_key()
    
  def encap(self):    
    esk = x25519.X25519PrivateKey.generate()
    ss = esk.exchange(self.pk)
    ct = esk.public_key().public_bytes(
                  encoding=serialization.Encoding.Raw,
                  format=serialization.PublicFormat.Raw
                ) 
    return (ct, ss)

  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = x25519.X25519PublicKey.from_public_bytes(ct)
    return self.sk.exchange(ct)
  

  def public_key_bytes(self):
    return self.pk.public_bytes(
                      encoding=serialization.Encoding.Raw,
                      format=serialization.PublicFormat.Raw
                    )


  def private_key_bytes(self):
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )

  

class X448KEM(X25519KEM):
  id = "id-X448"
  oid = univ.ObjectIdentifier((1,3,101,111))

  def keyGen(self):
    self.sk = x448.X448PrivateKey.generate()
    self.pk = self.sk.public_key()

  def encap(self):    
    esk = x448.X448PrivateKey.generate()
    ss = esk.exchange(self.pk)
    ct = esk.public_key().public_bytes(
              encoding=serialization.Encoding.Raw,
              format=serialization.PublicFormat.Raw
            ) 
    return (ct, ss)

  def decap(self, ct):
    if isinstance(ct, bytes):
      ct = x448.X448PublicKey.from_public_bytes(ct)
    return self.sk.exchange(ct)



class RSA2048OAEPKEM(KEM):
  id = "id-RSAES-OAEP-2048"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1))

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
      )
    self.pk = self.sk.public_key()

  # returns (ct, ss)
  def encap(self):    
    ss = secrets.token_bytes(32)
    ct = self.pk.encrypt(
        ss,
        padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
        )
      )
    return (ct, ss)
  

  # returns (ss)
  def decap(self, ct):    
    ss = self.sk.decrypt(
        ct,
        padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
        )
      )
    return ss
    

  def public_key_bytes(self):
    return self.pk.public_bytes(
                      encoding=serialization.Encoding.DER,
                      format=serialization.PublicFormat.PKCS1
                    )


  def private_key_bytes(self):
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )


# save some copy&paste by inheriting
class RSA3072OAEPKEM(RSA2048OAEPKEM):
  id = "id-RSAES-OAEP-3072"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1))

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
      )
    self.pk = self.sk.public_key()


# save some copy&paste by inheriting
class RSA4096OAEPKEM(RSA2048OAEPKEM):
  id = "id-RSAES-OAEP-4096"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1))

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
      )
    self.pk = self.sk.public_key()


class MLKEM768(KEM):
  id = "id-alg-ml-kem-768"
  oid = univ.ObjectIdentifier((2,16,840,1,101,3,4,4,2))

  # returns nothing
  def keyGen(self):
    self.sk = secrets.token_bytes(64)
    self.pk, _ = ML_KEM_768.key_derive(self.sk)
    
  # returns (ct, ss)
  def encap(self):
    (ss, ct) = ML_KEM_768.encaps(self.pk)
    return (ct, ss)

  # returns (ss)
  def decap(self, ct):
    _, dk = ML_KEM_768.key_derive(self.sk)
    return ML_KEM_768.decaps(dk, ct)

  def public_key_bytes(self):
    return self.pk

  def private_key_bytes(self):
    return self.sk
  


class MLKEM1024(KEM):
  id = "id-alg-ml-kem-1024"
  oid = univ.ObjectIdentifier((2,16,840,1,101,3,4,4,3))

  # returns nothing
  def keyGen(self):
    self.sk = secrets.token_bytes(64)
    self.pk, _ = ML_KEM_1024.key_derive(self.sk)
    
  # returns (ct, ss)
  def encap(self):
    (ss, ct) = ML_KEM_1024.encaps(self.pk)
    return (ct, ss)

  # returns (ss)
  def decap(self, ct):
    _, dk = ML_KEM_1024.key_derive(self.sk)
    return ML_KEM_1024.decaps(dk, ct)

  def public_key_bytes(self):
    return self.pk

  def private_key_bytes(self):
    return self.sk
  



### Composites ###

class CompositeKEM(KEM):
  mlkem = None
  tradkem = None
  kdf = "None"
  domSep = ""

  def __init__(self):
    super().__init__()
    self.domSep = DOMAIN_TABLE[self.id][0]  # the first component is the domain,
                                            # the second is a boolean controlling whether
                                            # this renders in the domsep table in the draft.

  def keyGen(self):
    self.mlkem.keyGen()
    self.tradkem.keyGen()

    self.pk = self.public_key_bytes()
    self.sk = self.public_key_bytes()


  
  def serializePublicKey(self):
    """
    (pk1, pk2) -> pk
    """
    mlkemPK = self.mlkem.public_key_bytes()
    tradPK  = self.tradkem.public_key_bytes()
    return mlkemPK + tradPK
  
  def deserializePublicKey(self, keyBytes):
    """
    pk -> (pk1, pk2)
    """
    assert isinstance(keyBytes, bytes)

    if isinstance(self.mlkem, MLKEM768):
      return keyBytes[:1184], keyBytes[1184:]
    elif isinstance(self.mlkem, MLKEM1024):
      return keyBytes[:1568], keyBytes[1568:]
  

  def serializePrivateKey(self):
    """
    (mlkemSK, tradSK) -> sk
    """
    mlkemSK = self.mlkem.private_key_bytes()
    tradSK  = self.tradkem.private_key_bytes()
    return mlkemSK + tradSK
  
  def deserializePrivateKey(self, keyBytes):
    """
    sk -> (mlkemSK, tradSK)
    """
    assert isinstance(keyBytes, bytes)
    return keyBytes[:64], keyBytes[64:]
  
  def public_key_bytes(self):
    return self.serializePublicKey()

  def private_key_bytes(self):
    return self.serializePrivateKey()
  
  def serializeCiphertext(self, ct1, ct2):
    assert isinstance(ct1, bytes)
    assert isinstance(ct2, bytes)
    return ct1 + ct2
  

  def deserializeCiphertext(self, ct):
    assert isinstance(ct, bytes)

    if isinstance(self.mlkem, MLKEM768):
      return ct[:1088], ct[1088:]
    elif isinstance(self.mlkem, MLKEM1024):
      return ct[:1568], ct[1568:]



  # returns (ct, ss)
  def encap(self):
    if self.mlkem == None or self.tradkem == None:
      raise Exception("Cannot Encap for a KEM with no PK.")
    
    (ct1, ss1) = self.mlkem.encap()
    (ct2, ss2) = self.tradkem.encap()

    ct = self.serializeCiphertext(ct1, ct2)

    ss = kemCombiner(self, ss1, ss2, ct2, self.tradkem.public_key_bytes())

    return (ct, ss)


  # returns (ss)
  def decap(self, ct):
    if self.mlkem == None or self.tradkem == None:
      raise Exception("Cannot Decap for a KEM with no SK.")
    
    (mlkemCT, tradCT) = self.deserializeCiphertext(ct)

    mlkemSS = self.mlkem.decap(mlkemCT)
    tradSS = self.tradkem.decap(tradCT)

    ss = kemCombiner(self, mlkemSS, tradSS, tradCT, self.tradkem.public_key_bytes())

    return ss



class MLKEM768_RSA2048_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-RSA2048-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = RSA2048OAEPKEM()
  kdf = "HKDF-SHA256"


class MLKEM768_RSA3072_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-RSA3072-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = RSA3072OAEPKEM()
  kdf = "HKDF-SHA256"


class MLKEM768_RSA4096_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-RSA4096-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = RSA4096OAEPKEM()
  kdf = "HKDF-SHA256"


class MLKEM768_X25519_SHA3_256(CompositeKEM):
  id = "id-MLKEM768-X25519-SHA3-256"
  mlkem = MLKEM768()
  tradkem = X25519KEM()
  kdf = "SHA3-256"


class MLKEM768_ECDH_P256_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-ECDH-P256-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = ECDHP256KEM()
  kdf = "HKDF-SHA256"


class MLKEM768_ECDH_P384_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-ECDH-P384-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = ECDHP384KEM()
  kdf = "HKDF-SHA256"


class MLKEM768_ECDH_brainpoolP256r1_HKDF_SHA256(CompositeKEM):
  id = "id-MLKEM768-ECDH-brainpoolP256r1-HKDF-SHA256"
  mlkem = MLKEM768()
  tradkem = ECDHBP256KEM()
  kdf = "HKDF-SHA256"


class MLKEM1024_ECDH_P384_HKDF_SHA384(CompositeKEM):
  id = "id-MLKEM1024-ECDH-P384-HKDF-SHA384"
  mlkem = MLKEM1024()
  tradkem = ECDHP384KEM()
  kdf = "HKDF-SHA384"


class MLKEM1024_ECDH_brainpoolP384r1_HKDF_SHA384(CompositeKEM):
  id = "id-MLKEM1024-ECDH-brainpoolP384r1-HKDF-SHA384"
  mlkem = MLKEM1024()
  tradkem = ECDHBP384KEM()
  kdf = "HKDF-SHA384"


class MLKEM1024_X448_SHA3_256(CompositeKEM):
  id = "id-MLKEM1024-X448-SHA3-256"
  mlkem = MLKEM1024()
  tradkem = X448KEM()
  kdf = "SHA3-256"

  
class MLKEM1024_ECDH_P521_HKDF_SHA384(CompositeKEM):
  id = "id-MLKEM1024-ECDH-P521-HKDF-SHA384"
  mlkem = MLKEM1024()
  tradkem = ECDHP521KEM()
  kdf = "HKDF-SHA384"

  

### KEM Combiner ###

"""
      if KDF is "SHA3-256"
        ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Domain)

      else if KDF is "HKDF"
        ss = HKDF-Extract(salt="", IKM=mlkemSS || tradSS || tradCT || tradPK || Domain)
          # Note: salt is the empty string (0 octets), which will internally be mapped
          # to the zero vector `0x00..00` of the correct input size for the underlying
          # hash function as per [RFC 5869].
"""
def kemCombiner(kem, mlkemSS, tradSS, tradCT, tradPK, output=False, file_handle=None):
  ss = None

  if kem.kdf == "HKDF-SHA256":
    # ss = HKDF-Extract(salt="", IKM=mlkemSS || tradSS || tradCT || tradPK || Domain)
    # Using HMAC interface because python cryptography does not expose HKDF-Extract() by itself
    emptyStr = "".encode('ascii')
    h = hmac.HMAC(key=emptyStr, algorithm=hashes.SHA256())
    h.update(mlkemSS)
    h.update(tradSS)
    h.update(tradCT)
    h.update(tradPK)
    h.update(kem.domSep)
    ss = h.finalize()
    
  elif kem.kdf == "HKDF-SHA384":
    # ss = HKDF-Extract(salt="", IKM=mlkemSS || tradSS || tradCT || tradPK || Domain)
    # Using HMAC interface because python cryptography does not expose HKDF-Extract() by itself
    emptyStr = "".encode('ascii')
    h = hmac.HMAC(key=emptyStr, algorithm=hashes.SHA384())
    h.update(mlkemSS)
    h.update(tradSS)
    h.update(tradCT)
    h.update(tradPK)
    h.update(kem.domSep)
    ss = h.finalize()
    ss = ss[:32]  # truncate to 32 bytes

  elif kem.kdf == "SHA3-256":
    # SHA3-256(..)
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(mlkemSS)
    digest.update(tradSS)
    digest.update(tradCT)
    digest.update(tradPK)
    digest.update(kem.domSep)
    ss = digest.finalize()
  
  else:
    raise Exception("KEM combiner \""+str(kem.kdf)+"\" not recognized.")
    
    if (output):
      if file_handle is None:
         print("No data written to the file")

      else:              
         file_handle.write("\nmlkemSS: " + mlkemSS.hex())
         file_handle.write("\ntradSS: " + tradSS.hex())
         file_handle.write("\ntradCT: " + tradCT.hex())
         file_handle.write("\ntradPK: " + tradPK.hex())
         file_handle.write("\nDomain: " + kem.domSep.hex())
         file_handle.write("\nss: " + ss.hex())

    return Mp  

  return ss







### Generate CA Cert and KEM Cert ###

caName = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IETF'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'LAMPS'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Composite ML-KEM CA')
    ]
  )

# Since we're gonna sign with PQ algs that python cryptography doesn't
# know about, we need to do this manually
# input: a cert that already carries a signature that needs to be replaced
def caSign(cert, caSK):
  certDer = cert.public_bytes(encoding=serialization.Encoding.DER)
  cert_pyasn1, _ = decode(certDer, rfc5280.Certificate())

  # Manually set the algID to ML-DSA-65 and re-sign it
  sigAlgID = rfc5280.AlgorithmIdentifier()
  sigAlgID['algorithm'] = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18))
  cert_pyasn1['tbsCertificate']['signature'] = sigAlgID
  tbs_bytes = encode(cert_pyasn1['tbsCertificate'])
  cert_pyasn1['signatureAlgorithm'] = sigAlgID
  cert_pyasn1['signature'] = univ.BitString(hexValue=ML_DSA_65.sign(caSK, tbs_bytes).hex())

  return x509.load_der_x509_certificate(encode(cert_pyasn1))


# RFC 9500 section 2.1
# needed to create a X509 with a keytype that python recognizes,
# then we can manually replace it.
_RSA_DUMMY_KEY = serialization.load_pem_private_key("""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----
""".encode(), password=None)



def createCA():
  caPK, caSK = ML_DSA_65.keygen()

  x509_builder = x509.CertificateBuilder()
  x509_builder = x509_builder.subject_name( caName )

  x509_builder = x509_builder.issuer_name( caName )

  one_day = datetime.timedelta(1, 0, 0)
  x509_builder = x509_builder.not_valid_before(datetime.datetime.today() - one_day)
  x509_builder = x509_builder.not_valid_after(datetime.datetime.today() + (one_day * 3652))
  x509_builder = x509_builder.serial_number(x509.random_serial_number())
  x509_builder = x509_builder.public_key(_RSA_DUMMY_KEY.public_key())

  x509_builder = x509_builder.add_extension( x509.KeyUsage(
                                digital_signature=False,
                                content_commitment=False,
                                key_encipherment=False,
                                data_encipherment=False,
                                key_agreement=False,
                                key_cert_sign=True,
                                crl_sign=False,
                                encipher_only=False,
                                decipher_only=False ), critical=True)
  
  x509_builder = x509_builder.add_extension( x509.BasicConstraints(ca=True, path_length=2), critical=True)

  caCert = x509_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())

  
  # Replace the RSA public key with ML-DSA

  # Extract the Certificate
  caCert_der = caCert.public_bytes(encoding=serialization.Encoding.DER)
  caCert_pyasn1, _ = decode(caCert_der, rfc5280.Certificate())

  spki = rfc5280.SubjectPublicKeyInfo()
  algid = rfc5280.AlgorithmIdentifier()
  algid['algorithm'] = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18))
  spki['algorithm'] = algid
  spki['subjectPublicKey'] = univ.BitString(hexValue=caPK.hex())
  caCert_pyasn1['tbsCertificate']['subjectPublicKeyInfo'] = spki

  caCert = x509.load_der_x509_certificate(encode(caCert_pyasn1))

  caCert = caSign(caCert, caSK)

  return (caCert, caSK)




def signKemCert(caSK, kem):
  x509_builder = x509.CertificateBuilder()
  x509_builder = x509_builder.subject_name(x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IETF'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'LAMPS'),
        x509.NameAttribute(NameOID.COMMON_NAME, kem.id)
    ]
  ))

  x509_builder = x509_builder.issuer_name( caName )

  one_day = datetime.timedelta(1, 0, 0)
  x509_builder = x509_builder.not_valid_before(datetime.datetime.today() - one_day)
  x509_builder = x509_builder.not_valid_after(datetime.datetime.today() + (one_day * 3652))
  x509_builder = x509_builder.serial_number(x509.random_serial_number())
  x509_builder = x509_builder.public_key(_RSA_DUMMY_KEY.public_key())

  x509_builder = x509_builder.add_extension( x509.KeyUsage(
                                digital_signature=False,
                                content_commitment=False,
                                key_encipherment=True,
                                data_encipherment=False,
                                key_agreement=False,
                                key_cert_sign=False,
                                crl_sign=False,
                                encipher_only=False,
                                decipher_only=False ), critical=True)
  
  # x509_builder = x509_builder.add_extension( x509.BasicConstraints(ca=True, path_length=None), critical=True)

  kemCert = x509_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())


  # Ok, now swap out the public key for one that python won't recognize, and re-sign it

  # Extract the Certificate
  kemCert_der = kemCert.public_bytes(encoding=serialization.Encoding.DER)
  kemCert_pyasn1, _ = decode(kemCert_der, rfc5280.Certificate())

  spki = rfc5280.SubjectPublicKeyInfo()
  algid = rfc5280.AlgorithmIdentifier()
  algid['algorithm'] = OID_TABLE[kem.id]
  spki['algorithm'] = algid
  spki['subjectPublicKey'] = univ.BitString(hexValue=kem.public_key_bytes().hex())

  kemCert_pyasn1['tbsCertificate']['subjectPublicKeyInfo'] = spki

  kemCert = x509.load_der_x509_certificate(encode(kemCert_pyasn1))

  kemCert = caSign(kemCert, caSK)


  return kemCert




# Setup the test vector output
testVectorOutput = {}

# Create the CA that will sign all KEM certs
(caCert, caSK) = createCA()
testVectorOutput['cacert'] = base64.b64encode(caCert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
testVectorOutput['tests'] = []

SIZE_TABLE = {}

DOMAIN_TABLE = {}



def genDomainTable():
  """
  This is a bit weird; we have to generate it first because
  this table is used by the composite.sign() to construct Mprime,
  but also not every supported option should be rendered into
  the domain separators table in the draft, hence carrying a boolean.
  By default, everything is False to be included in the table unless
  turned on by doSig(.., includeInDomainTable=True)."""

  for alg in OID_TABLE:
    domain = base64.b16encode(encode(OID_TABLE[alg]))
    DOMAIN_TABLE[alg] = (domain, False)

# run this statically
genDomainTable()



def doKEM(kem, caSK, includeInTestVectors=True, includeInDomainTable=True, includeInSizeTable=True):
  kem.keyGen()
  (ct, ss) = kem.encap()
  _ss = kem.decap(ct)
  assert ss == _ss

  jsonResult = formatResults(kem, caSK, ct, ss)

  if includeInTestVectors:
    testVectorOutput['tests'].append(jsonResult)

  if includeInDomainTable:
    DOMAIN_TABLE[kem.id] = (DOMAIN_TABLE[kem.id][0], True)

  if includeInSizeTable:
    sizeRow = {}
    sizeRow['pk'] = len(kem.public_key_bytes())
    sizeRow['sk'] = len(kem.private_key_bytes())
    sizeRow['ct'] = len(ct)
    sizeRow['ss'] = len(ss)
    SIZE_TABLE[kem.id] = sizeRow


def writeTestVectors():
  with open('testvectors.json', 'w') as f:
    f.write(json.dumps(testVectorOutput, indent=2))
  
  with open('testvectors_wrapped.json', 'w') as f:
    f.write('\n'.join(textwrap.wrap(''.join(json.dumps(testVectorOutput, indent="")), 
                                  width=68,
                                  replace_whitespace=False,
                                  drop_whitespace=False)))


def formatResults(kem, caSK, ct, ss ):

  jsonTest = {}
  jsonTest['tcId'] = kem.id
  jsonTest['ek'] = base64.b64encode(kem.public_key_bytes()).decode('ascii')

  kemCert = signKemCert(caSK, kem)
  jsonTest['x5c'] = base64.b64encode(kemCert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
  jsonTest['dk'] = base64.b64encode(kem.private_key_bytes()).decode('ascii')

  # Construct PKCS#8
  pki = rfc5208.PrivateKeyInfo()
  pki['version'] = 0
  algId = rfc5208.AlgorithmIdentifier()
  algId['algorithm'] = OID_TABLE[kem.id]
  pki['privateKeyAlgorithm'] = algId
  pki['privateKey'] = univ.OctetString(kem.private_key_bytes())
  jsonTest['dk_pkcs8'] = base64.b64encode(encode(pki)).decode('ascii')

  jsonTest['c'] = base64.b64encode(ct).decode('ascii')
  jsonTest['k'] = base64.b64encode(ss).decode('ascii')

  return jsonTest


def writeDumpasn1Cfg():
  """
  Creates a dumpasn1.cfg file based on the OID mapping table in this script.
  """

  with open('dumpasn1.cfg', 'w') as f:
    f.write("# dumpasn1 Object Identifier configuration file.\n")
    f.write("# Generated by the Composite KEM reference implementation\n")
    f.write("# available at: https://github.com/lamps-wg/draft-composite-kem\n")
    f.write("\n")

    for oid in OID_TABLE:
      f.write("OID = "+ str(OID_TABLE[oid]).replace('.', ' ')+"\n")
      f.write("Comment = "+ oid+"\n")
      f.write("Description = "+ oid+"\n")
      f.write("\n")


def writeSizeTable():
  # In this style:
  # | Algorithm   | Public key  | Private key |  Ciphertext  |  SS  |
  # | ----------- | ----------- | ----------- |  ----------- |  --  |
  # | ML-KEM-768  |    1184     |     64      |     1088     |  32  |
  # | ML-KEM-1024 |    1568     |     64      |     1568     |  32  |


  with open('sizeTable.md', 'w') as f:
    f.write('| Algorithm                                     |  Public key  |  Private key |  Ciphertext  |  SS  |\n')
    f.write('| --------------------------------------------- | ------------ | ------------ |  ----------- |  --  |\n')

    for alg in SIZE_TABLE:
      row = SIZE_TABLE[alg]
      f.write('| '+ alg.ljust(46, ' ') +'|'+
                 str(row['pk']).center(14, ' ') +'|'+
                 str(row['sk']).center(14, ' ') +'|'+
                 str(row['ct']).center(14, ' ') +'|'+
                 str(row['ss']).center(6, ' ') +'|\n')
  

def writeDomainTable():
  """
  Writes the table of domain separators to go into the draft.
  """

  with open('domSepTable.md', 'w') as f:
    f.write('| Composite Signature Algorithm                 | Domain Separator (in Hex encoding)|\n')
    f.write('| ---------------------------------------       | ----------------------------------|\n')

    for alg in DOMAIN_TABLE:
      if DOMAIN_TABLE[alg][1]:  # boolean controlling rendering in this table.
        f.write('| ' + alg.ljust(45, ' ') + " | " + str(DOMAIN_TABLE[alg][0].decode('ascii')) + " |\n")


def doKEMCombiner(kem, file_handle=None, ctx=b''):
  r = secrets.token_bytes(32)
  Mp = sig.computeMp(_mf, ctx, r,True,file_handle)


def main():

  # Single algs - remove these, just for testing
  # doKEM(X25519KEM(), caSK,      includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doKEM(ECDHP256KEM(), caSK,    includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doKEM(ECDHP384KEM(), caSK,    includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doKEM(RSA2048OAEPKEM(), caSK, includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doKEM(RSA3072OAEPKEM(), caSK, includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doKEM(RSA4096OAEPKEM(), caSK, includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  doKEM(MLKEM768(), caSK,  includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  doKEM(MLKEM1024(), caSK, includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )


  
  # Composites
  doKEM(MLKEM768_RSA2048_HKDF_SHA256(), caSK)
  doKEM(MLKEM768_RSA3072_HKDF_SHA256(), caSK)
  doKEM(MLKEM768_RSA4096_HKDF_SHA256(), caSK)
  doKEM(MLKEM768_X25519_SHA3_256(), caSK)
  doKEM(MLKEM768_ECDH_P256_HKDF_SHA256(), caSK )
  doKEM(MLKEM768_ECDH_P384_HKDF_SHA256(), caSK )
  doKEM(MLKEM768_ECDH_brainpoolP256r1_HKDF_SHA256(), caSK )
  doKEM(MLKEM1024_ECDH_P384_HKDF_SHA384(), caSK )
  doKEM(MLKEM1024_ECDH_brainpoolP384r1_HKDF_SHA384(), caSK )
  doKEM(MLKEM1024_X448_SHA3_256(), caSK )
  doKEM(MLKEM1024_ECDH_P521_HKDF_SHA384(), caSK )


  writeTestVectors()
  writeDumpasn1Cfg()
  writeSizeTable()
  writeDomainTable()


if __name__ == "__main__":
  main()