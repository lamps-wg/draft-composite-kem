---
title: Composite ML-KEM for use in X.509 Public Key Infrastructure and CMS
abbrev: Composite ML-KEM
docname: draft-ietf-lamps-pq-composite-kem-latest

# <!-- stand_alone: true -->
ipr: trust200902
area: Security
stream: IETF
wg: LAMPS
keyword:
 - X.509
 - CMS
 - Post-Quantum
 - KEM
cat: std

venue:
  group: LAMPS
  type: Working Group
  mail: spams@ietf.org
  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: lamps-wg/draft-composite-kem
  latest: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html

coding: utf-8
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
  -
    ins: M. Pala
    name: Massimiliano Pala
    org: OpenCA Labs
    city: New York City, New York
    country: United States of America
    email: director@openca.org
  -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany
  -
    ins: S. Fluhrer
    name: Scott Fluhrer
    org: Cisco Systems
    email: sfluhrer@cisco.com


normative:
  RFC2119:
  RFC4055:
  RFC5280:
  RFC5480:
  RFC5652:
  RFC5958:
  RFC6234:
  RFC8017:
  RFC8174:
  RFC8410:
  RFC8411:
  RFC8619:
  RFC9629:
  I-D.draft-ietf-lamps-cms-sha3-hash-04:
  I-D.draft-ietf-lamps-kyber-certificates-06:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  SP.800-56Ar3:
    title: "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography"
    date: April 2018
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
  SP.800-56Cr2:
    title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
    date: August 2020
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
  SP.800-57pt1r5:
    title: "Recommendation for Key Management: Part 1 – General"
    date: May 2020
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
  SP.800-185:
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
    date: December 2016
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
  FIPS.180-4:
    title: "FIPS Publication 180-4: Secure Hash Standard"
    date: August 2015
    author:
      org: National Institute of Standards and Technology (NIST)
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
  FIPS.202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    author:
      org: National Institute of Standards and Technology (NIST)
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  FIPS.203:
    title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
    date: August 13, 2024
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf


informative:
  RFC2986:
  RFC4210:
  RFC4211:
  RFC4262:
  RFC5083:
  RFC5639:
  RFC5914:
  RFC5990:
  RFC6090:
  RFC7292:
  RFC7296:
  RFC8446:
  RFC8551:
  I-D.draft-ietf-tls-hybrid-design-04:
  I-D.draft-ietf-pquip-pqt-hybrid-terminology-04:
  I-D.draft-ietf-lamps-cms-kyber-05:
  X-Wing:
    title: "X-Wing The Hybrid KEM You’ve Been Looking For"
    date: 2024-01-09
    author:
      -
        ins: M. Barbosa
        name: Manuel Barbosa
      -
        ins: D. Connolly
        name: Deirdre Connolly
      -
        ins: J. Duarte
        name: João Diogo Duarte
      -
        ins: A. Kaiser
        name: Aaron Kaiser
      -
        ins: P. Schwabe
        name: Peter Schwabe
      -
        ins: K. Varner
        name: Karolin Varner
      -
        ins: B. Westerbaan
        name: Bas Westerbaan
    target: https://eprint.iacr.org/2024/039.pdf
  BSI2021:
    title: "Quantum-safe cryptography - fundamentals, current developments and recommendations"
    target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Brochure/quantum-safe-cryptography.pdf
    author:
      - org: "Federal Office for Information Security (BSI)"
    date: October 2021
  ANSSI2024:
    title: "Position Paper on Quantum Key Distribution"
    target: https://cyber.gouv.fr/sites/default/files/document/Quantum_Key_Distribution_Position_Paper.pdf
    author:
      - org: "French Cybersecurity Agency (ANSSI)"
      - org: "Federal Office for Information Security (BSI)"
      - org: "Netherlands National Communications Security Agency (NLNCSA)"
      - org: "Swedish National Communications Security Authority, Swedish Armed Forces"
  SP800-131Ar2:
    title: "Transitioning the Use of Cryptographic Algorithms and Key Lengths"
    target: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-131ar2.pdf
    author:
      - ins: E. Barker
        name: Elaine Barke
      - ins: A. Roginksy
        name: Allan Reginsky
    org: National Institute of Standards and Technology (NIST)
  GHP18:
    title: KEM Combiners
    author:
      name: Federico Giacon
      name: Felix Heuer
      name: Bertram Poettering
    date: 2018
    target: https://eprint.iacr.org/2018/024
  Aviram22:
    title: "Practical (Post-Quantum) Key Combiners from One-Wayness and Applications to TLS"
    author:
      name: Nimrod Aviram
      name: Benjamin Dowling
      name: Ilan Komargodski
      name: Kenneth G. Paterson
      name: Eyal Ronen
      name: Eylon Yogev
    target: https://eprint.iacr.org/2022/065
  CNSA2.0:
    title: "Commercial National Security Algorithm Suite 2.0"
    org: National Security Agency
    target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  FIPS-140-3-IG:
    title: Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation Program
    target: https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
    author:
      org: National Institute of Standards and Technology (NIST)
    date: July 26, 2024


--- abstract

This document defines combinations of ML-KEM [FIPS.203] in hybrid with traditional algorithms RSA-OAEP, ECDH, X25519, and X448. These combinations are tailored to meet security best practices and regulatory requirements. Composite ML-KEM is applicable in any application that uses X.509, PKIX, and CMS data structures and protocols that accept ML-KEM, but where the operator wants extra protection against breaks or catastrophic bugs in ML-KEM. For use within CMS, this document is intended to be coupled with the CMS KEMRecipientInfo mechanism in {{RFC9629}}.

<!-- End of Abstract -->


--- middle

# Changes in version -06

Interop-affecting changes:

* Remove the ASN.1 SEQUENCE wrapping around the ASN.1 structures to make it easier to access via other protocols.
* Add a ML-KEM-768 + ECDH-P256 variant


Editorial changes:

* Added an Implementation Consideration section explaining why private keys need to contain the public keys.
* Added a security consideration about key reuse.
* Added security considerations about SHA3-vs-HKDF-SHA2 and a warning against generifying this construction to other combinations of ciphers.
* Enhanced the section about how to get this FIPS-certified.
* ASN.1 module fixes (thanks Russ and Carl).
  * Renamed the module from Composite-KEM-2023 -> Composite-MLKEM-2024
  * Simplified the ASN.1 module to make it more compiler-friendly (thanks Carl!) -- should not affect wire encodings.


Still to do in a future version:

- `[ ]` Wait for NIST SP 800-227 to make sure KEM combiner aligns, and update the section explaining how to get this FIPS-certified.
- `[ ]` We need PEM samples … hackathon? OQS friends? David @ BC? The right format for samples is probably to follow the hackathon ... a Dilithium or ECDSA trust anchor certificate, a composite KEM end entity certificate, and a CMS EnvelopedData sample encrypted for that composite KEM certificate.
- `[ ]` Open question: do we need to include the ECDH, X25519, X448, and RSA public keys in the KDF? X-Wing does, but previous versions of this spec do not. In general existing ECC and RSA hardware decrypter implementations might not know their own public key.
- `[ ]` Other outstanding github issues: https://github.com/lamps-wg/draft-composite-kem/issues


# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA-OAEP, ECDH and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021].

In addition, [BSI2021] specifically references this specification as a concrete example of hybrid X.509 certificates.

A more recent example is [ANSSI2024], a document co-authored by French Cybersecurity Agency (ANSSI),
Federal Office for Information Security (BSI), Netherlands National Communications Security Agency (NLNCSA), and
Swedish National Communications Security Authority, Swedish Armed Forces which makes the following statement:

> “In light of the urgent need to stop relying only on quantum-vulnerable public-key cryptography for key establishment, the clear priority should therefore be the migration to post-quantum cryptography in hybrid solutions”

This specification represents the straightforward implementation of the hybrid solutions called for by European cyber security agencies.

PQ/T Hybrid cryptography can, in general, provide solutions to two migration problems:

- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Ease-of-migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.

This document defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key encapsulation mechanism (KEM) key and ciphertext such that they can be treated as a single atomic algorithm at the protocol level. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite ML-KEM algorithms are provided based on ML-KEM, RSA-OAEP and ECDH. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.

Composite ML-KEM is intended for general applicability anywhere that key establishment or enveloped content encryption is used within PKIX or CMS structures.




## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This document is consistent with all terminology from {{I-D.ietf-pquip-pqt-hybrid-terminology}}.
In addition, the following terms are used in this document:

**ALGORITHM**:
          The usage of the term "algorithm" within this
          document generally refers to any function which
          has a registered Object Identifier (OID) for
          use within an ASN.1 AlgorithmIdentifier. This
          loosely, but not precisely, aligns with the
          definitions of "cryptographic algorithm" and
          "cryptographic scheme" given in {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

**COMBINER:**
  A combiner specifies how multiple shared secrets are combined into
  a single shared secret.

**DER:**
  Distinguished Encoding Rules as defined in [X.690].

**KEM:**
   A key encapsulation mechanism as defined in {{sec-kems}}.

**PKI:**
  Public Key Infrastructure, as defined in {{RFC5280}}.

**SHARED SECRET KEY:**
  A value established between two communicating parties for use as
  cryptographic key material suitable for direct use by symmetric
  cryptographic algorithms. This document is concerned with shared
  secrets established via public key cryptographic operations.

## Composite Design Philosophy

{{I-D.ietf-pquip-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys, as defined here, follow this definition and should be regarded as a single key that performs a single cryptographic operation such as key generation, signing, verifying, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, ciphertext and signature can be carried in existing fields in protocols such as PKCS#10 {{RFC2986}}, CMP {{RFC4210}}, X.509 {{RFC5280}}, CMS {{RFC5652}}, and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts an analogous single-algorithm cryptographic scheme without requiring any modification of the protocol to handle multiple algorithms.



# Overview of the Composite ML-KEM Scheme {#sec-kems}

We borrow here the definition of a key encapsulation mechanism (KEM) from {{I-D.ietf-tls-hybrid-design}}, in which a KEM is a cryptographic primitive that consists of three algorithms:

   *  `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
      which generates a public key `pk` and a secret key `sk`.\

   *  `Encap(pk) -> (ss, ct)`: A probabilistic encapsulation algorithm,
      which takes as input a public key `pk` and outputs a ciphertext `ct`
      and shared secret ss. Note: this document uses `Encap()` to conform to {{?RFC9180}},
      but [FIPS.203] uses `Encaps()`.

   *  `Decap(sk, ct) -> ss`: A decapsulation algorithm, which takes as
      input a secret key `sk` and ciphertext `ct` and outputs a shared
      secret `ss`, or in some cases a distinguished error value.
      Note: this document uses `Decap()` to conform to {{RFC9180}},
      but [FIPS.203] uses `Decaps()`.

We also borrow the following algorithms from {{RFC9180}}, which deal with encoding and decoding of KEM public key values.

   *  `SerializePublicKey(pk) -> bytes`: Produce a fixed-length byte string encoding the public key pk.

   *  `DeserializePublicKey(bytes) -> pk`: Parse a fixed-length byte string to recover a public key pk. This function can fail if the input byte string is malformed.

We define the following algorithms which are used to serialize and deseralize the CompositeCiphertextValue

   *  `SerializeCiphertextValue(CompositeCiphertextValue) -> bytes`: Produce a fixed-length byte string encoding the CompositeCiphertextValue.

   *  `DeserializeCipherTextValue(bytes) -> pk`: Parse a fixed-length byte string to recover a CompositeCiphertextValue. This function can fail if the input byte string is malformed.

The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}).

The KEM interface was chosen as the interface for a composite key establishment because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs as described in {{sec-RSAOAEPKEM}} and {{sec-DHKEM}} below.

This specification uses the Post-Quantum KEM ML-KEM as specified in [FIPS.203] and {{I-D.ietf-lamps-kyber-certificates}}. For Traditional KEMs, this document uses the RSA-OAEP algorithm defined in [RFC8017], the Elliptic Curve Diffie-Hellman key agreement schemes ECDH defined in section 5.7.1.2 of [SP.800-56Ar3], and X25519 / X448 which are defined in [RFC8410]. A combiner function is used to combine the two component shared secrets into a single shared secret.


## Promotion of RSA-OAEP into a KEM {#sec-RSAOAEPKEM}

The RSA Optimal Asymmetric Encryption Padding (OAEP), as defined in section 7.1 of [RFC8017] is a public key encryption algorithm used to transport key material from a sender to a receiver. It is promoted into a KEM by having the sender generate a random 256 bit secret and encrypt it.

Note that, at least at the time of writing, the algorithm `RSAOAEPKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it cannot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.

~~~
RSAOAEPKEM.Encap(pkR):
  shared_secret = SecureRandom(ss_len)
  enc = RSAES-OAEP-ENCRYPT(pkR, shared_secret)

  return shared_secret, enc
~~~

Note that the OAEP label `L` is left to its default value, which is the empty string as per [RFC8017]. The shared secret output by the overall Composite ML-KEM already binds a composite domain separator, so there is no need to also utilize the component domain separators.

The value of `ss_len` as well as the RSA-OAEP parameters used within this specification can be found in {{sect-rsaoaep-params}}.

 `Decap(sk, ct) -> ss` is accomplished in the analogous way.

~~~
RSAOAEPKEM.Decap(skR, enc):
  shared_secret = RSAES-OAEP-DECRYPT(skR, enc)

  return shared_secret
~~~


## Promotion of ECDH into a KEM {#sec-DHKEM}

An elliptic curve Diffie-Hellman key agreement is promoted into a KEM `Encap(pk) -> (ss, ct)` using a simplified version of the DHKEM definition from [RFC9180]; simplified to remove the context-binding labels since the shared secret output by the overall Composite ML-KEM already binds a composite domain separator, so there is no need to also utilize labels within DHKEM.

Note that, at least at the time of writing, the algorithm `DHKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it cannot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.

~~~
DHKEM.Encap(pkR):
  skE, pkE = GenerateKeyPair()
  shared_secret = DH(skE, pkR)
  enc = SerializePublicKey(pkE)

  return shared_secret, enc
~~~

`Decap(sk, ct) -> ss` is accomplished in the analogous way.

~~~
DHKEM.Decap(skR, enc):
  pkE = DeserializePublicKey(enc)
  shared_secret = DH(skR, pkE)

  return shared_secret
~~~

This construction applies for all variants of elliptic curve Diffie-Hellman used in this specification: ECDH, X25519, and X448.

The simplifications from the DHKEM definition in [RFC9180] is that since the ciphertext and receiver's public key are included explicitly in the Composite ML-KEM combiner, there is no need to construct the `kem_context` object, and since a domain separator is included explicitly in the Composite ML-KEM combiner there is no need to perform the labeled steps of `ExtractAndExpand()`.

# Composite ML-KEM Functions {#sec-composite-mlkem}

This section describes the composite ML-KEM functions needed to instantiate the KEM API in {{sec-kems}}.

## Key Generation

To generate a new keypair for Composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms for the Composite keypair in no particular order. Multi-process or multi-threaded applications might choose to execute the key generation functions in parallel for better key generation performance.

The following process is used to generate composite keypair values:

~~~
KeyGen() -> (pk, sk)

Explicit Inputs:
     None

Implicit Input:
  ML-KEM     A placeholder for the specific ML-KEM algorithm and
             parameter set to use, for example, could be "ML-KEM-65".

  Trad       A placeholder for the specific traditional algorithm and
             parameter set to use, for example "RSA-OAEP"
             or "X25519".

Output:
  (pk, sk)  The composite keypair.

Key Generation Process:

  1. Generate component keys

    (mlkemPK, mlkemSK) = ML-KEM.KeyGen()
    (tradPK, tradSK)   = Trad.KeyGen()

  2. Check for component key gen failure
    if NOT (mlkemPK, mlkemSK) or NOT (tradPK, tradSK):
      output "Key generation error"

  3. Output the composite public and private keys

    pk = (mlkemPK, tradPK)
    sk = (mlkemSK, tradSK)
    return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite KeyGen(pk, sk)"}


In order to ensure fresh keys, the key generation functions MUST be executed for both component algorithms. Compliant parties MUST NOT use or import component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use.

Note that in step 2 above, both component key generation processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

## Encapsulation

The `Encap(pk)` of a Composite ML-KEM algorithm is designed to behave exactly the same as `ML-KEM.Encaps(ek)` defined in Algorithm 20 in Section 7.2 of [FIPS.203]. Specifically, `Composite-ML-KEM.Encap(pk)` produces a 256-bit shared secret key that can be used directly with any symmetric-key cryptographic algorithm. In this way, Composite ML-KEM can be used as a direct drop-in replacement anywhere that ML-KEM is used.

~~~
Composite-ML-KEM.Encap(pk) -> (ss, ct)

Explicit Input:

  pk          Composite public key consisting of encryption public keys
              for each component.

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example "RSA-OAEP"
           or "X25519".

  KDF      The KDF specified for the given Composite ML-KEM algorithm.
           See algorithm specifications below.

  Domain   Domain separator value for binding the ciphertext to the
           Composite OID. See section on Domain Separators below.

Output:

  ss      The shared secret key, a 256-bit key suitable for use with
          symmetric cryptographic algorithms.

  ct      The ciphertext, a byte string.

Encap Process:

  1. Separate the public keys.

      (mlkemPK, tradPK) = pk

  2.  Perform the respective component Encap operations according to
      their algorithm specifications.

      (mlkemCT, mlkemSS) = MLKEM.Encaps(mlkemPK)
      (tradCT, tradSS) = TradKEM.Encap(tradPK)

  3. If either ML-KEM.Encaps() or TradKEM.Encap() return an error,
     then this process must return an error.

      if NOT (mlkemCT, mlkemSS) or NOT (tradCT, tradSS):
        output "Encapsulation error"

  4. Encode the ciphertext

     ct = mlkemCT || tradCT

  5. Combine the KEM secrets and additional context to yield the composite shared secret

     ss = KDF(mlkemSS || tradSS || tradCT || tradPK || Domain)

  6. Output composite shared secret key and ciphertext

     return (ss, ct)
~~~
{: #alg-composite-mlkem-encap title="Composite-ML-KEM.Encap(pk)"}

The specific values for `KDF` are defined per Composite ML-KEM algorithm in {{tab-kem-algs}} and the specific values for `Domain` are defined per Composite ML-KEM algorithm in {{sec-alg-ids}}.

## Decapsulation {#sect-composite-decaps}

The `Decap(sk, ct) -> ss` of a Composite ML-KEM algorithm is designed to behave exactly the same as `ML-KEM.Decaps(dk, c)` defined in Algorithm 21 in Section 7.3 of [FIPS.203]. Specifically, `Composite-ML-KEM.Decap(sk, ct)` produces a 256-bit shared secret key that can be used directly with any symmetric-key cryptographic algorithm. In this way, Composite ML-KEM can be used as a direct drop-in replacement anywhere that ML-KEM is used.

~~~
Composite-ML-KEM.Decap(sk, ct) -> ss

Explicit Input:

  sk    Composite private key consisting of decryption private keys for
        each component.

  ct      The ciphertext, a byte string.

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific traditional algorithm and
           parameter set to use, for example "RSA-OAEP"
           or "X25519".

  KDF      The KDF specified for the given Composite ML-KEM algorithm.
           See algorithm specifications below.

  Domain   Domain separator value for binding the ciphertext to the
           Composite OID. See section on Domain Separators below.

Output:

  ss      The shared secret key, a 256-bit key suitable for use with
          symmetric cryptographic algorithms.

Decap Process:

  1. Separate the private keys

      (mlkemSK, tradSK) = sk

  2. Parse the ciphertext

      (mlkemCT, tradCT) = ct

  3.  Perform the respective component Encap operations according to
      their algorithm specifications.

      mlkemSS = MLKEM.Decaps(mlkemSK, mlkemCT)
      tradSS  = TradKEM.Decap(tradSK, tradCT)

  4. If either ML-KEM.Decaps() or TradKEM.Decap() return an error,
     then this process must return an error.

      if NOT mlkemSS or NOT tradSS:
        output "Encapsulation error"

  5. Combine the KEM secrets and additional context to yield the composite shared secret

      ss = KDF(mlkemSS || tradSS || tradCT || tradPK || Domain)

  6. Output composite shared secret key

     return ss
~~~
{: #alg-composite-mlkem-decap title="Composite-ML-KEM.Decap(sk, ct)"}

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output and error handling as the process sketched above.

In order to properly achieve its security properties, the KEM combiner requires that all inputs are fixed-length. Since each Composite ML-KEM algorithm fully specifies its component algorithms, including key sizes, all inputs should be fixed-length in non-error scenarios, however some implementations may need to perform additional checking to handle certain error conditions. In particular, the KEM combiner step should not be performed if either of the component decapsulations returned an error condition indicating malformed inputs. For timing-invariance reasons, it is RECOMMENDED to perform both decapsulation operations and check for errors afterwards to to prevent an attacker from using a timing channel to tell which component failed decapsulation. Also, RSA-based composites MUST ensure that the modulus size (ie the size of tradCT and tradPK) matches that specified for the given Composite ML-KEM algorithm in {{tab-kem-algs}}; depending on the cryptographic library used, this check may be done by the library or may require an explicit check as part of the `CompositeKEM.Decap()` routine.

## SerializePublicKey and DeserializePublicKey {#sec-serialize-deserialize}

The KEM public key serialization routine simply concatenates the fixed-length public keys of the constituent KEMs, as defined below.

~~~
Composite-ML-KEM.SerializePublicKey(pk) -> bytes

Explicit Input:

  pk    Composite ML-KEM public key

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific traditional algorithm and
           parameter set to use, for example "RSA-OAEP"
           or "X25519".

Output:

  bytes   The encoded public key

Serialization Process:

  1. Separate the public keys

     (mlkemPK, tradPK) = pk

  2. Serialize each of the constituent public keys

     mlkemEncodedPK = ML-KEM.SerializePublicKey(mlkemPK)
     tradEncodedPK = Trad.SerializePublicKey(tradPK)

  3. Combine and output the encoded public key

     bytes = mlkemEncodedPK || tradEncodedPK
     output bytes
~~~
{: #alg-composite-serialize title="Composite SerializePublicKey(pk)"}

Deserialization reverses this process, raising an error in the event that the input is malformed.

~~~
Composite-ML-KEM.DeserializePublicKey(bytes) -> pk

Explicit Input:

  bytes   An encoded public key

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific traditional algorithm and
           parameter set to use, for example "RSA-OAEP"
           or "X25519".

Output:

  pk     The composite ML-KEM public key

Deserialization Process:

  1. Validate the length of the the input byte string

     if bytes is not the correct length:
      output "Deserialization error"

  2. Parse each constituent encoded public key

     (mlkemEncodedPK, tradEncodedPK) = bytes

  3. Deserialize the constituent public keys

     mlkemPK = ML-KEM.DeserializePublicKey(mlkemEncodedPK)
     tradPK = Trad.DeserializePublicKey(tradEncodedPK)

  4. If either ML-KEM.DeserializePublicKey() or
     Trad.DeserializePublicKey() return an error,
     then this process must return an error.

      if NOT mlkemPK or NOT tradPK:
        output "Deserialization error"

  5. Output the composite ML-KEM public key

     output (mlkemPK, tradPK)
~~~
{: #alg-composite-deserialize title="Composite DeserializePublicKey(bytes)"}

## SerializePrivateKey and DeserializePrivateKey

The same serialization and deserialization process as described in {{sec-serialize-deserialize}}
should be used to serialize and deserialize the private keys.  The only difference is that pk is
the private key, and the output is the concatenation of the mlkem and traditional private keys for
serialization, or the mlkem and traditional private keys for deserialization.

## SerializeCiphertextValue and DeSerializeCiphertextValue

The serialization routine for the CompositeCiphertextValue simply concatenates the fixed-length
ML-KEM cipherText value with the cipherText value from the traditional algorithm, as defined below:

~~~
Composite-ML-DSA.SerializeCiphertextValue(CompositeCiphertextValue) -> bytes

Explicit Input:

  CompositeCiphertextValue    The Composite CipherText Value obtained from Composite-ML-KEM.Encap(pk)

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific traditional algorithm and
           parameter set to use, for example "RSAOAEP" or "ECDH".

Output:

  bytes   The encoded CompositeCiphertextValue

Serialization Process:

  1. Separate the cipher texts

     (mldkemct, tradkemct) = CompositeCiphertextValue

  2. Serialize each of the constituent cipher texts

     mlkemEncodedCt = ML-KEM.SerializeCiphertext(mlkemct)
     tradkemEncodedCT = Trad.SerializeCiphertext(tradkemct)

  3. Combine and output the encoded composite ciphertext

     bytes = mlkemEncodedCt || tradkemEncodedCT
     output bytes
~~~
{: #alg-composite-serialize-ct title="Composite SerializeCiphertextValue(CompositeCiphertextValue)"}


Deserialization reverses this process, raising an error in the event that the input is malformed.

~~~
Composite-ML-KEM.DeserializeCiphertextValue(bytes) -> CompositeCiphertextValue

Explicit Input:

  bytes   An encoded CompositeCiphertextValue

Implicit inputs:

  ML-KEM   A placeholder for the specific ML-KEM algorithm and
           parameter set to use, for example, could be "ML-KEM-768".

  Trad     A placeholder for the specific traditional algorithm and
           parameter set to use, for example "RSAOAEP" or "ECDH".

Output:

  CompositeCiphertextValue  The CompositeCiphertextValue

Deserialization Process:

  1. Validate the length of the the input byte string

     if bytes is not the correct length:
      output "Deserialization error"

  2. Parse each constituent encoded cipher text.
       The length of the mlkemEncodedCt is known based on the size of
       the ML-KEM component cipher text length specified by the Object ID

     (mlkemEncodedCt, tradkemEncodedCt) = bytes

  3. Deserialize the constituent cipher text values

     mlkemCt = ML-KEM.DeserializeCiphertext(mlkemEncodedCt)
     tradkemCt = Trad.DeserializeCiphertext(tradkemEncodedCt)

  4. If either ML-KEM.DeserializeCiphertext() or
     Trad.DeserializeCiphertext() return an error,
     then this process must return an error.

      if NOT mlkemCt or NOT tradkemCt:
        output "Deserialization error"

  5. Output the CompositeCiphertextValue

     output (mlkemCt, tradkemCt)

~~~
{: #alg-composite-deserialize-ct title="Composite DeserializeCiphertextValue(bytes)"}

## ML-KEM public key, private key and cipher text sizes for serialization and deserialization

As noted above in the public key, private key and CompositeCiphertextValue
serialization and deserialization methods, ML-KEM uses fixed-length values for
all of these components.  This means the length encoding of the first component is
known and does NOT need to be encoded into the serialization and deserialization process
which simplifies the encoding.  If future composite combinations make use of
algorithms where the first component uses variable length keys or cipher texts, then
that specification will need to ensure the length is encoded in a
fixed-length prefix so the components can be correctly deserialized.

The following table shows the fixed length values in bytes for the public, private and cipher text
sizes for ML-KEM which can be used to deserialzie the components.

| Algorithm   | Public key  | Private key |  Ciphertext  |
| ----------- | ----------- | ----------- |  ----------- |
| ML-KEM-768  |    1184     |     64      |     1952     |
| ML-KEM-1024 |    1568     |     64      |     2592     |
{: #tab-mlkem-sizes title="ML-KEM Key and Ciphertext Sizes"}


# Composite Key Structures {#sec-composite-keys}

In order to form composite public keys and ciphertext values, we define ASN.1-based composite encodings such that these structures can be used as a drop-in replacement for existing public key and ciphertext fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652].

## CompositeKEMPublicKey {#sec-composite-pub-keys}

The wire encoding of a Composite ML-KEM public key is:

~~~ ASN.1
CompositeKEMPublicKey ::= BIT STRING
~~~
{: artwork-name="CompositeKEMPublicKey-asn.1-structures"}

Since RSA and ECDH component public keys are themselves in a DER encoding, the following show the internal structure of the various public key types used in this specification:

When a CompositeKEMPublicKey is used with an RSA public key, the BIT STRING itself is generated by the concatenation of a raw ML-KEM key according to {{I-D.ietf-lamps-kyber-certificates}} and an RSAPublicKey (which is a DER encoded RSAPublicKey).

When a CompositeKEMPublicKey is used with an EC public key, the BIT STRING itself is generated by the concatenation of a raw ML-KEM key according to {{I-D.ietf-lamps-kyber-certificates}} and an ECDHPublicKey (which is a DER encoded ECPoint).

When a CompositeKEMPublicKey is used with an Edwards public key, the BIT STRING itself is generated by the concatenation of a raw ML-KEM key according to {{I-D.ietf-lamps-kyber-certificates}} and a raw Edwards public key according to [RFC8410].

Some applications may need to reconstruct the `SubjectPublicKeyInfo` objects corresponding to each component public key. {{tab-kem-algs}} in {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

When the CompositeKEMPublicKey must be provided in octet string or bit string format, the data structure is encoded as specified in {{sec-encoding-rules}}.

In order to maintain security properties of the composite, applications that use composite keys MUST always perform fresh key generations of both component keys and MUST NOT reuse existing key material. See {{sec-cons-key-reuse}} for a discussion.

The following ASN.1 Information Object Class is defined to allow for compact definitions of each composite algorithm, leading to a smaller overall ASN.1 module.

~~~ ASN.1
  pk-CompositeKEM {OBJECT IDENTIFIER:id, PublicKeyType}
    PUBLIC-KEY ::= {
      IDENTIFIER id
      KEY PublicKeyType
      PARAMS ARE absent
      CERT-KEY-USAGE { keyEncipherment }
    }
~~~
{: artwork-name="CompositeKeyObject-asn.1-structures"}


As an example, the public key type `pk-MLKEM768-ECDH-P384` can be defined compactly as:

~~~
pk-MLKEM768-ECDH-P384 PUBLIC-KEY ::=
  pk-CompositeKEM {
    id-MLKEM768-ECDH-P384,
    EcCompositeKemPublicKey }
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


## CompositeKEMPrivateKey {#sec-priv-key}

When a Composite ML-KEM private key is to be exported from a cryptographic module, it uses an analogous definition to the public keys:

~~~ ASN.1
CompositeKEMPrivateKey ::= OCTET STRING
~~~
{: artwork-name="CompositeKEMPrivateKey-asn.1-structures"}

Each element of the `CompositeKEMPrivateKey` Sequence is an `OCTET STRING` according to the encoding of the underlying algorithm specification and will decode into the respective private key structures in an analogous way to the public key structures defined in {{sec-composite-pub-keys}}. This document does not provide helper classes for private keys.  The PrivateKey for each component algorithm MUST be in the same order as defined in {{sec-composite-pub-keys}}.

Use cases that require an interoperable encoding for composite private keys will often need to place a `CompositeKEMPrivateKey` inside a `OneAsymmetricKey` structure defined in [RFC5958], such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211]. The definition of `OneAsymmetricKey` is copied here for convenience:

~~~ ASN.1
 OneAsymmetricKey ::= SEQUENCE {
       version                   Version,
       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
       privateKey                PrivateKey,
       attributes            [0] Attributes OPTIONAL,
       ...,
       [[2: publicKey        [1] PublicKey OPTIONAL ]],
       ...
     }

  ...
  PrivateKey ::= OCTET STRING
                        -- Content varies based on type of key.  The
                        -- algorithm identifier dictates the format of
                        -- the key.
~~~
{: artwork-name="RFC5958-OneAsymmetricKey-asn.1-structure"}

When a `CompositeKEMPrivateKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}} and its parameters field MUST be absent.  The privateKey field SHALL contain the `CompositeKEMPrivateKey`, and the `publicKey` field remains OPTIONAL.  If the `publicKey` field is present, it MUST be a `CompositeKEMPublicKey`.

Some applications may need to reconstruct the `OneAsymmetricKey` objects corresponding to each component private key. {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

Component keys of a CompositeKEMPrivateKey MUST NOT be used in any other type of key or as a standalone key. For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.


## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that the composite public key and composite private key data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

In the interests of simplicity and avoiding compatibility issues, implementations that parse these structures MAY accept both BER and DER.

## Key Usage Bits

When any of the Composite ML-KEM `AlgorithmIdentifier` appears in the `SubjectPublicKeyInfo` field of an X.509 certificate [RFC5280], the key usage certificate extension MUST only contain

~~~
keyEncipherment
~~~

Composite ML-KEM keys MUST NOT be used in a "dual usage" mode because even if the
traditional component key supports both signing and encryption,
the post-quantum algorithms do not and therefore the overall composite algorithm does not.


# Composite ML-KEM Structures

## kema-CompositeKEM {#sec-kema-CompositeKEM}

The ASN.1 algorithm object for a Composite ML-KEM is:

~~~
kema-CompositeKEM {
  OBJECT IDENTIFIER:id,
    PUBLIC-KEY:publicKeyType }
    KEM-ALGORITHM ::= {
         IDENTIFIER id
         VALUE CompositeCiphertextValue
         PARAMS ARE absent
         PUBLIC-KEYS { publicKeyType }
        }
~~~

## CompositeCiphertextValue {#sec-CompositeCiphertextValue}

The `CompositeCipherTextValue` is the DER encoding of a SEQUENCE of the ciphertexts from the
underlying component algorithms.  It is represented in ASN.1 as follows:

~~~
CompositeCiphertextValue ::= OCTET STRING
~~~

The order of the component ciphertexts is the same as the order defined in {{sec-composite-pub-keys}}.

# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of Composite ML-KEM algorithms and lists the OID, two component algorithms, and the KDF to be used within combiner function. Domain separator values are defined below in {{sec-domsep-values}}.

EDNOTE: these are prototyping OIDs to be replaced by IANA.

&lt;CompKEM&gt;.1 is equal to 2.16.840.1.114027.80.5.2.1

## Composite-ML-KEM Algorithm Identifiers

| Composite ML-KEM Algorithm         | OID                  | First Algorithm | Second Algorithm     | KDF      |
|---------                           | -----------------    | ----------      | ----------           | -------- |
| id-MLKEM768-RSA2048                | &lt;CompKEM&gt;.30   | MLKEM768        | RSA-OAEP 2048        | HKDF-SHA256 |
| id-MLKEM768-RSA3072                | &lt;CompKEM&gt;.31   | MLKEM768        | RSA-OAEP 3072        | HKDF-SHA256 |
| id-MLKEM768-RSA4096                | &lt;CompKEM&gt;.32   | MLKEM768        | RSA-OAEP 4096        | HKDF-SHA256 |
| id-MLKEM768-X25519                 | &lt;CompKEM&gt;.33   | MLKEM768        | X25519               | SHA3-256 |
| id-MLKEM768-ECDH-P256              | &lt;CompKEM&gt;.34   | MLKEM768        | ECDH-P256            | HKDF-SHA256 |
| id-MLKEM768-ECDH-P384              | &lt;CompKEM&gt;.35   | MLKEM768        | ECDH-P384            | HKDF-SHA256 |
| id-MLKEM768-ECDH-brainpoolP256r1   | &lt;CompKEM&gt;.36   | MLKEM768        | ECDH-brainpoolp256r1 | HKDF-SHA256 |
| id-MLKEM1024-ECDH-P384             | &lt;CompKEM&gt;.37   | MLKEM1024       | ECDH-P384            | HKDF-SHA384/256 |
| id-MLKEM1024-ECDH-brainpoolP384r1  | &lt;CompKEM&gt;.38   | MLKEM1024       | ECDH-brainpoolP384r1 | SHA3-256 |
| id-MLKEM1024-X448                  | &lt;CompKEM&gt;.39   | MLKEM1024       | X448                 | SHA3-256 |
{: #tab-kem-algs title="Composite ML-KEM key types"}

For the use of HKDF [RFC5869]: a salt is not provided; ie the default salt (all zeroes of length HashLen) will be used. For HKDF-SHA256 the output of 256 bit output is used directly; for HKDF-SHA384/256, HKDF is invoked with SHA384 and then the output is truncated to 256 bits, meaning that only the first 256 bits of output are used.

Full specifications for the referenced algorithms can be found in {{appdx_components}}.


## Domain Separators {#sec-domsep-values}

The KEM combiner used in this document requires a domain separator `Domain` input.  The following table shows the HEX-encoded domain separator for each Composite ML-KEM AlgorithmID; to use it, the value should be HEX-decoded and used in binary form. The domain separator is simply the DER encoding of the composite algorithm OID.

| Composite ML-KEM Algorithm| Domain Separator (in Hex encoding)|
| -----------               | ----------- |
| id-MLKEM768-RSA2048       | 060B6086480186FA6B5005021E |
| id-MLKEM768-RSA3072       | 060B6086480186FA6B5005021F |
| id-MLKEM768-RSA4096       | 060B6086480186FA6B50050220 |
| id-MLKEM768-X25519        | 060B6086480186FA6B50050221 |
| id-MLKEM768-ECDH-P256     | 060B6086480186FA6B50050222 |
| id-MLKEM768-ECDH-P384     | 060B6086480186FA6B50050223 |
| id-MLKEM768-ECDH-brainpoolP256r1 | 060B6086480186FA6B50050224 |
| id-MLKEM1024-ECDH-P384    | 060B6086480186FA6B50050225 |
| id-MLKEM1024-ECDH-brainpoolP384r1 | 060B6086480186FA6B50050226 |
| id-MLKEM1024-X448         | 060B6086480186FA6B50050227 |
{: #tab-kem-domains title="Composite ML-KEM fixedInfo Domain Separators"}

EDNOTE: these domain separators are based on the prototyping OIDs assigned on the Entrust arc. We will need to ask for IANA early allocation of these OIDs so that we can re-compute the domain separators over the final OIDs.


## Rationale for choices

* Pair equivalent levels.
* NIST-P-384 is CNSA approved [CNSA2.0] for all classification levels.
* 521 bit curve not widely used.

A single invocation of SHA3 is known to behave as a dual-PRF, and thus is sufficient for use as a KDF, see {{sec-cons-kem-combiner}}, however SHA2 is not us must be wrapped in the HKDF construction.

The lower security levels (ie ML-KEM768) are provided with HKDF-SHA2 as the KDF in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-KEM function. Higher security levels (ie ML-KEM1024) are paired with SHA3 for computational efficiency, and the Edwards Curve (X25519 and X448) combinations are paired with SHA3 for compatibility with other similar specifications.

While it may seem odd to use 256-bit hash functions at all security levels, this aligns with ML-KEM which produces a 256-bit shared secret key at all security levels. SHA-256 and SHA3-256 both have >= 256 bits of (2nd) pre-image resistance, which is the required property for a KDF to provide 128 bits of security, as allowed in Table 3 of {{SP.800-57pt1r5}}.

## RSA-OAEP Parameters {#sect-rsaoaep-params}

Use of RSA-OAEP [RFC8017] within `id-MLKEM768-RSA2048`, `id-MLKEM768-RSA3072`, and `id-MLKEM768-RSA4096` requires additional specification.

First, a quick note on the choice of RSA-OAEP as the supported RSA encryption primitive. RSA-KEM [RFC5990] is more straightforward to work with, but it has fairly limited adoption and therefore is of limited backwards compatibility value. Also, while RSA-PKCS#1v1.5 [RFC8017] is still everywhere, but hard to make secure and no longer FIPS-approved as of the end of 2023 [SP800-131Ar2], so it is of limited forwards value. This leaves RSA-OAEP [RFC8017] as the remaining choice.

The RSA component keys MUST be generated at the 2048-bit and 3072-bit security levels respectively.

As with the other Composite ML-KEM algorithms, when `id-MLKEM768-RSA2048`, `id-MLKEM768-RSA3072`, or `id-MLKEM-RSA4096` is used in an AlgorithmIdentifier, the parameters MUST be absent. The RSA-OAEP SHALL be instantiated with the following hard-coded parameters which are the same for the 2048, 3072 and 4096 bit security levels.

| RSAES-OAEP-params           | Value                       |
| ----------------------      | ---------------             |
| hashAlgorithm               | id-sha256                 |
| maskGenAlgorithm            | mgf1SHA256Identifier        |
| pSourceAlgorithm            | pSpecifiedEmpty             |
| ss_len                      | 256 bits                    |
{: #rsa-oaep-params title="RSA-OAEP Parameters"}

where:

* `id-sha256` is defined in [RFC8017].
* `mgf1SHA256Identifier` is defined in [RFC4055], which refers to the MFG1 function defined in [RFC8017] appendix B.2.1.
* `pSpecifiedEmpty` is defined in [RFC8017] to indicate that the empty string is used for the label.

Note: The mask length, according to [RFC8017], is `k - hLen - 1`, where `k` is the size of the RSA modulus. Since the choice of hash function and the RSA key size is fixed for each composite algorithm, implementations could choose to pre-compute and hard-code the mask length.


# Use in CMS

\[EDNOTE: The convention in LAMPS is to specify algorithms and their CMS conventions in separate documents. Here we have presented them in the same document, but this section has been written so that it can easily be moved to a standalone document.\]

Composite ML-KEM algorithms MAY be employed for one or more recipients in the CMS enveloped-data content type [RFC5652], the CMS authenticated-data content type [RFC5652], or the CMS authenticated-enveloped-data content type [RFC5083]. In each case, the KEMRecipientInfo [RFC9629] is used with the chosen Composite ML-KEM Algorithm to securely transfer the content-encryption key from the originator to the recipient.

All recommendations for using Composite ML-KEM in CMS are fully aligned with the use of ML-KEM in CMS {{I-D.ietf-lamps-cms-kyber}}.

## Underlying Components

A compliant implementation MUST support the following algorithm combinations for the KEMRecipientInfo `kdf` and `wrap` fields when the corresponding Composite ML-KEM algorithm is listed in the KEMRecipientInfo `kem` field. The KDFs listed below align with the KDF used internally within the KEM combiner. An implementation MAY also support other key-derivation functions and other key-encryption algorithms within CMS KEMRecipientInfo and SHOULD use algorithms of equivalent strength or greater.

| Composite ML-KEM Algorithm        | KDF                     | Wrap |
|---------                          | ---                     | ---                |
| id-MLKEM768-RSA2048               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-RSA3072               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-RSA4096               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-X25519                | id-kmac256              | id-aes128-wrap     |
| id-MLKEM768-ECDH-P256             | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM768-ECDH-P384             | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM768-ECDH-brainpoolP256r1  | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM1024-ECDH-P384            | id-alg-hkdf-with-sha384 | id-aes256-wrap     |
| id-MLKEM1024-ECDH-brainpoolP384r1 | id-kmac256              | id-aes256-wrap     |
| id-MLKEM1024-X448                 | id-kmac256              | id-aes256-wrap     |
{: #tab-cms-kdf-wrap title="Mandatory-to-implement pairings for CMS KDF and WRAP"}


Full specifications for the referenced algorithms can be found either further down in this section, or in {{appdx_components}}.

Note that here we differ slightly from the internal KDF used within the KEM combiner in {{sec-alg-ids}} because [RFC9629] requires that the KDF listed in the KEMRecipientInfo `kdf` field must have an interface which accepts `KDF(IKM, L, info)`, so here we need to use KMAC and cannot directly use SHA3. Since we require 256-bits of (2nd) pre-image resistance, we use KMAC256 for the Composite ML-KEM algorithms with internally use SHA3-256, as aligned with Table 3 of {{SP.800-57pt1r5}}.


### Use of the HKDF-based Key Derivation Function

The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is defined in {{!RFC5869}}.

The HKDF function is a composition of the HKDF-Extract and HKDF-Expand functions.

~~~
HKDF(salt, IKM, info, L)
  = HKDF-Expand(HKDF-Extract(salt, IKM), info, L)
~~~

HKDF(salt, IKM, info, L) takes the following parameters:

salt:
: optional salt value (a non-secret random value). In this document this parameter is unused, that is it is the zero-length string "".

IKM:
: input keying material. In this document this is the shared secret outputted from the Encapsulate() or Decapsulate() functions.  This corresponds to the IKM KDF input from {{Section 5 of RFC9629}}.

info:
: optional context and application specific information. In this document this corresponds to the info KDF input from {{Section 5 of RFC9629}}. This is the ASN.1 DER encoding of CMSORIforKEMOtherInfo.

L:
: length of output keying material in octets. This corresponds to the L KDF input from {{Section 5 of RFC9629}}, which is identified in the kekLength value from KEMRecipientInfo. Implementations MUST confirm that this value is consistent with the key size of the key-encryption algorithm.

HKDF may be used with different hash functions, including SHA-256 and SHA-384 {{FIPS.180-4}}. The object identifier id-alg-hkdf-with-sha256 and id-alg-hkdf-with-sha384 are defined in [RFC8619], and specify the use of HKDF with SHA-256 and SHA-384. The parameter field MUST be absent when this algorithm identifier is used to specify the KDF for ML-KEM in KemRecipientInfo.



### Use of the KMAC-based Key Derivation Function

KMAC256-KDF is a KMAC-based KDF specified for use in CMS in {{I-D.ietf-lamps-cms-sha3-hash}}. The definition of KMAC is copied here for convenience.  Here, KMAC# indicates the use of either KMAC128-KDF or KMAC256-KDF, although only KMAC256 is used in this specification.

KMAC#(K, X, L, S) takes the following parameters:

> K: the input key-derivation key.  In this document this is the shared secret outputted from the Encapsulate() or Decapsulate() functions.  This corresponds to the IKM KDF input from Section 5 of [RFC9629].

> X: the context, corresponding to the info KDF input from Section 5 of [RFC9629]. This is the ASN.1 DER encoding of CMSORIforKEMOtherInfo.

> L: the output length, in bits.  This corresponds to the L KDF input from Section 5 of [RFC9629], which is identified in the kekLength value from KEMRecipientInfo.  The L KDF input and kekLength values are specified in octets while this L parameter is specified in bits.

> S: the optional customization label.  In this document this parameter is unused, that is it is the zero-length string "".

The object identifier for KMAC256-KDF is id-kmac256, as defined in {{I-D.ietf-lamps-cms-sha3-hash}}.

Since the customization label to KMAC# is not used, the parameter field MUST be absent when id-kmac256 is used as part of an algorithm identifier specifying the KDF to use for Composite ML-KEM in KemRecipientInfo.


## RecipientInfo Conventions {#sec-using-recipientInfo}

When Composite ML-KEM is employed for a recipient, the RecipientInfo alternative for that recipient MUST be OtherRecipientInfo using the KEMRecipientInfo structure as defined in {{RFC9629}}.

The fields of the KEMRecipientInfo MUST have the following values:

> version is the syntax version number; it MUST be 0.

> rid identifies the recipient's certificate or public key.

> kem identifies the KEM algorithm; it MUST contain one of the Composite ML-KEM identifiers listed in {{sec-alg-ids}}.

> kemct is the ciphertext produced for this recipient.

> kdf identifies the key-derivation algorithm. Note that the Key Derivation Function (KDF) used for CMS RecipientInfo process MAY be different than the KDF used within the Composite ML-KEM algorithm or one of its components.

> kekLength is the size of the key-encryption key in octets.

> ukm is an optional random input to the key-derivation function. ML-KEM doesn't place any requirements on the ukm contents.

> wrap identifies a key-encryption algorithm used to encrypt the content-encryption key.

<!-- End of recipientinfo conventions section -->


## Certificate Conventions

The conventions specified in this section augment RFC 5280 [RFC5280].

The willingness to accept a Composite ML-KEM Algorithm MAY be signaled by the use of the SMIMECapabilities Attribute as specified in Section 2.5.2. of [RFC8551] or the SMIMECapabilities certificate extension as specified in [RFC4262].

The intended application for the public key MAY be indicated in the key usage certificate extension as specified in Section 4.2.1.3 of [RFC5280]. If the keyUsage extension is present in a certificate that conveys a Composite ML-KEM public key, then the key usage extension MUST contain only the following value:

~~~
keyEncipherment
~~~

The digitalSignature and dataEncipherment values MUST NOT be present. That is, a public key intended to be employed only with a Composite ML-KEM algorithm MUST NOT also be employed for data encryption or for digital signatures. This requirement does not carry any particular security consideration; only the convention that KEM keys be identified with the `keyEncipherment` key usage.


## SMIMECapabilities Attribute Conventions

Section 2.5.2 of [RFC8551] defines the SMIMECapabilities attribute to announce a partial list of algorithms that an S/MIME implementation can support. When constructing a CMS signed-data content type [RFC5652], a compliant implementation MAY include the SMIMECapabilities attribute that announces support for the RSA-OAEP Algorithm.

The SMIMECapability SEQUENCE representing a Composite ML-KEM Algorithm MUST include the appropriate object identifier as per {{tab-kem-algs}} in the capabilityID field.

# ASN.1 Module {#sec-asn1-module}

~~~ ASN.1

<CODE STARTS>

{::include Composite-MLKEM-2024.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}

##  Object Identifier Allocations

EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-kem-algs}}.

###  Module Registration - SMI Security for PKIX Module Identifier

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-KEM-2023 - id-mod-composite-kems
-  References: This Document

###  Object Identifier Registrations - SMI Security for PKIX Algorithms

-  id-raw-key
  - Decimal: IANA Assigned
  - Description: Designates a public key BIT STRING with no ASN.1 structure.
  - References: This Document

- id-MLKEM768-RSA2048
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA2048
  - References: This Document

- id-MLKEM768-RSA3072
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA3072
  - References: This Document

- id-MLKEM768-RSA4096
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA4096
  - References: This Document

- id-MLKEM768-ECDH-P256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P256
  - References: This Document

- id-MLKEM768-ECDH-P384
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P384
  - References: This Document

- id-MLKEM768-ECDH-brainpoolP256r1
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-brainpoolP256r1
  - References: This Document

- id-MLKEM768-X25519
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-X25519
  - References: This Document

- id-MLKEM1024-ECDH-P384
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-P384
  - References: This Document

- id-MLKEM1024-ECDH-brainpoolP384r1
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-brainpoolP384r1
  - References: This Document

- id-MLKEM1024-X448
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-X448
  - References: This Document

<!-- End of IANA Considerations section -->


# Security Considerations

## KEM Combiner {#sec-cons-kem-combiner}

EDNOTE: the exact text to put here depends on the outcome of the CFRG KEM Combiners and X-Wing discussion. If CFRG doesn't move fast enough for us, then we may need to leverage this security consideration directly on top of the X-Wing paper [X-Wing].

The following KEM combiner construction is as follows is used by both `Composite-ML-KEM.Encap()` and `Composite-ML-KEM.Decap()` and is split out here for easier analysis.

~~~
  KDF(mlkemSS || tradSS || tradCT || tradPK || Domain)
~~~
{: #code-generic-kem-combiner title="KEM combiner construction"}

where:

* `KDF(message)` represents a key derivation function suitable to the chosen KEMs according to {tab-kem-combiners}. All KDFs produce a 256-bit shared secret key to match ML-KEM.
* `mlkemSS` is the shared secret key from the ML-KEM component.
* `tradSS` is the shared secret from the traditional component (elliptic curve or RSA).
* `tradCT` is the ciphertext from the traditional component (elliptic curve or RSA).
* `tradPK` is the public key of the traditional component (elliptic curve or RSA).
* `Domain` is the DER encoded value of the object identifier of the Composite ML-KEM algorithm as listed in {{sec-domsep-values}}.
* `||` represents concatenation.

Each registered Composite ML-KEM algorithm specifies the choice of `KDF` and`Domain` to be used in {{sec-alg-ids}} and {{sec-domsep-values}} below. Given that each Composite ML-KEM algorithm fully specifies the component algorithms, including for example the size of the RSA modulus, all inputs to the KEM combiner are fixed-size and thus do not require length-prefixing. The `CompositeKEM.Decap()` specified in {{sect-composite-decaps}} adds further error handling to protect the KEM combiner from malicious inputs.

The primary security property of the KEM combiner is that it preserves IND-CCA2 of the overall Composite ML-KEM so long as at least one component is IND-CCA2 [X-Wing] [GHP18]. Additionally, we also need to consider the case where one of the component algorithms is completely broken; that the private key is known to an attacker, or worse that the public key, private key, and ciphertext are manipulated by the attacker. In this case, we rely on the construction of the KEM combiner to ensure that the value of the other shared secret cannot be leaked or the combined shared secret predicted via manipulation of the broken algorithm. The following sections continue this discussion.

## Decapsulation failure

Provided all inputs are well-formed, the key establishment procedure of ML-KEM will never explicitly fail. Specifically, the ML-KEM.Encaps and ML-KEM.Decaps algorithms from [FIPS.203] will always output a value with the same data type as a shared secret key, and will never output an error or failure symbol. However, it is possible (though extremely unlikely) that the process will fail in the sense that ML-KEM.Encaps and ML-KEM.Decaps will produce different outputs, even though both of them are behaving honestly and no adversarial interference is present. In this case, the sender and recipient clearly did not succeed in producing a shared secret key. This event is called a decapsulation failure. Estimates for the decapsulation failure probability (or rate) for each of the ML-KEM parameter sets are provided in Table 1  of [FIPS.203] and reproduced here in {{tab-mlkem-failure-rate}}.


| Parameter set     | Decapsulation failure rate  |
|---------          | -----------------           |
| ML-KEM-512        | 2^(-139)                    |
| ML-KEM-768        | 2^(-164)                    |
| ML-KEM-1024       | 2^(-174)                    |
{: #tab-mlkem-failure-rate title="ML-KEM decapsulation failure rates"}

In the case of ML-KEM decapsulation failure, Composite ML-KEM MUST preserve the same behaviour and return a well-formed output.

### Second pre-image resistance of component KEMs {#sec-cons-ct-collision}

The notion of a second pre-image resistant KEM is defined in [X-Wing] being the property that it is computationally difficult to find two different ciphertexts `c != c'` that will decapsulate to the same shared secret under the same public key. For the purposes of a hybrid KEM combiner, this property means that given two composite ciphertexts `(c1, c2)` and `(c1', c2')`, we must obtain a unique overall shared secret so long as either `c1 != c1'` or `c2 != c2'` -- i.e. the overall Composite ML-KEM is second pre-image resistant, and therefore secure so, long as one of the component KEMs is.

In [X-Wing] it is proven that ML-KEM is a second pre-image resistant KEM and therefore the ML-KEM ciphertext can safely be omitted from the KEM combiner. Note that this makes a fundamental assumption on ML-KEM remaining ciphertext second pre-image resistant, and therefore this formulation of KEM combiner does not fully protect against implementation errors in the ML-KEM component -- particularly around the ciphertext check step of the Fujisaki-Okamoto transform -- which could trivially lead to second ciphertext pre-image attacks that break the IND-CCA2 security of the ML-KEM component and of the overall Composite ML-KEM. This could be more fully mitigated by binding the ML-KEM ciphertext in the combiner, but a design decision was made to settle for protection against algorithmic attacks and not implementation attacks against ML-KEM in order to increase performance.

However, since neither RSA-OAEP nor ECDH guarantee second pre-image resistance at all, even in a correct implementation, these ciphertexts are bound to the key derivation in order to guarantee that `c != c'` will yield a unique ciphertext, and thus restoring second pre-image resistance to the overall Composite ML-KEM.

### SHA3 vs HKDF-SHA2

In order to achieve the desired security property that the Composite ML-KEM is IND-CCA2 whenever at least one of the component KEMs is, the KDF used in the KEM combiner needs to possess collision and second pre-image resistance with respect to each of its inputs independently; a property sometimes called "dual-PRF" [Aviram22]. Collision and second-pre-image resistance protects against compromise of one component algorithm from resulting in the ability to construct multiple different ciphertexts which result in the same shared secret. Pre-image resistance protects against compromise of one component algorithm being used to attack and learn the value of the other shared secret.

SHA3 is known to have all of the necessary dual-PRF properties [X-Wing], but SHA2 does not and therefore all SHA2-based constructions MUST use SHA2 within an HMAC construction such as HKDF-SHA2 [GHP18].

### Generifying this construction

It should be clear that the security analysis of the presented KEM combiner construction relies heavily on the specific choices of component algorithms and combiner KDF, and this combiner construction SHOULD NOT by applied to any other combination of ciphers without performing the appropriate security analysis.

## Key Reuse {#sec-cons-key-reuse}

When using single-algorithm cryptography, the best practice is to always generate fresh keying material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device, however in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated. With composite keys we have a much stricter security requirement. However this reasoning does not hold in the PQ / Traditional hybrid setting.

Within the broader context of PQ / Traditional hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions and did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take already-deployed RSA keys and add an ML-KEM key to them to form a hybrid. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" where one component signature can be extracted and presented as a single-algorithm signature. Hybrid KEMs using a concatenation-style KEM combiner, as is done in this document, do not have the analogous attack surface because even if an attacker is able to extract and decrypt one of the component ciphertexts, this will yield a different shared secret than the overall shared secret derived from the composite, so any subsequent symmetric cryptographic operations will fail. However there is still a risk of key reuse which relates to certificate revocation, as well as general key reuse security issues.

Upon receiving a new certificate enrollment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, even if both components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, it is RECOMMENDED to avoid key reuse and always generate fresh component keys for a new composite. It is also RECOMMENDED that CAs performing revocation checks on a composite key should also check both component keys independently.

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), the path to deprecating it and removing it from operational environments is, at least is principle, straightforward.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled independently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLKEM512-ECDH-P256` even after ECDH-P256 is deprecated.

The Composite ML-KEM design specified in this document, and especially that of the KEM combiner specified in this document, and discussed in {{sec-cons-kem-combiner}}, means that the overall Composite ML-KEM algorithm should be considered to have the security strength of the strongest of its component algorithms; ie as long as one component algorithm remains strong, then the overall composite algorithm remains strong.


<!-- End of Security Considerations section -->

--- back

# Samples {#appdx-samples}

TODO

# Component Algorithm Reference {#appdx_components}

This section provides references to the full specification of the algorithms used in the composite constructions.

| Component KEM Algorithm ID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | [FIPS.203] |
| id-ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | [FIPS.203] |
| id-X25519 | 1.3.101.110 | [RFC8410] |
| id-X448 | 1.3.101.111 | [RFC8410] |
| id-ecDH | 1.3.132.1.12 | [RFC5480] |
| id-RSAES-OAEP | 1.2.840.113549.1.1.7 | [RFC8017] |
{: #tab-component-encr-algs title="Component Encryption Algorithms used in Composite Constructions"}

| Elliptic CurveID | OID | Specification |
| ----------- | ----------- | ----------- |
| secp256r1 | 1.2.840.10045.3.1.7 | [RFC6090] |
| secp384r1 | 1.3.132.0.34 | [RFC6090] |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | [RFC5639] |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | [RFC5639] |
{: #tab-component-curve-algs title="Elliptic Curves used in Composite Constructions"}

| HashID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-sha256 | 2.16.840.1.101.3.4.2.1 | [RFC6234] |
| id-sha512 | 2.16.840.1..101.3.4.2.3 | [RFC6234] |
| id-alg-hkdf-with-sha256 | 1.2.840.113549.1.9.16.3.28 | [RFC8619] |
| id-alg-hkdf-with-sha384 | 1.2.840.113549.1.9.16.3.29 | [RFC8619] |
| id-sha3-256 | 2.16.840.1.101.3.4.2.8 | [FIPS.202] |
| id-KMAC128  | 2.16.840.1.101.3.4.2.21 | [SP.800-185] |
{: #tab-component-hash title="Hash algorithms used in Composite Constructions"}


# Fixed Component Algorithm Identifiers

The following sections list explicitly the DER encoded `AlgorithmIdentifier` that MUST be used when reconstructing `SubjectPublicKeyInfo` objects for each component public key, which may be required for example if cryptographic library requires the public key in this form in order to process each component algorithm. The public key `BIT STRING` should be taken directly from the respective component of the CompositeKEMPublicKey.


**ML-KEM-768**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-alg-ml-kem-768   -- (2.16.840.1.101.3.4.4.2)
    }

DER:
  30 0B 06 07 60 86 48 01 65 03 04 04 02
~~~

**ML-KEM-1024**

ASN.1:

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-alg-ml-kem-1024   -- (2.16.840.1.101.3.4.4.3)
    }

DER:
  30 0B 06 07 60 86 48 01 65 03 04 04 03
~~~

**RSA-OAEP - all sizes**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSAES-OAEP,   -- (1.2.840.113549.1.1.7)
    parameters RSAES-OAEP-params {
         hashFunc      [0] id-sha256,  -- (2.16.840.1.101.3.4.2.1)
         maskGenFunc   [1] mgf1SHA256Identifier,
         pSourceFunc   [2] pSpecifiedEmpty  }
    }


where
      mgf1SHA256Identifier  AlgorithmIdentifier  ::=  {
                          algorithm id-mgf1,  -- (1.2.840.113549.1.1.8)
                          parameters sha256Identifier }


      sha256Identifier  AlgorithmIdentifier  ::=  { id-sha256, NULL }

DER:
 30 4D 06 09 2A 86 48 86 F7 0D 01 01 07 30 40 A0 0F 30 0D 06 09 60 86
 48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01
 08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 0F 30 0D 06 09 2A
 86 48 86 F7 0D 01 01 09 04 00
~~~


**ECDH NIST-P-384**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm secp384r1    -- (1.3.132.0.34)
        }
      }
    }

DER:
  30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22
~~~

**ECDH Brainpool-256**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm brainpoolP256r1   -- (1.3.36.3.3.2.8.1.1.7)
        }
      }
    }

DER:
  30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07
~~~

**ECDH Brainpool-384**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm brainpoolP384r1   -- (1.3.36.3.3.2.8.1.1.11)
        }
      }
    }

DER:
  30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B
~~~

**X25519**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-X25519   -- (1.3.101.110)
    }

DER:
  30 05 06 03 2B 65 6E
~~~

**X448**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-X448   -- (1.3.101.111)
    }

DER:
  30 05 06 03 2B 65 6F
~~~




# Implementation Considerations {#sec-in-pract}

## FIPS Certification {#sec-fips}

TODO -- update this once NIST SP 800-227 is published.

EDNOTE At time of writing, it is unclear that the KEM combiner presented in this document would pass a FIPS certification. The SHA3 instantiations should pass under SP 800-56Cr2 Option 1, but the HKDF-SHA2 combinations are technically not allowed under SP 800-56Cr2 even though Option 2 allows HMAC-based constructions, but unfortunately only HKDF-Extract is FIPS-allowed, not HKDF-Expand. The authors have been in contact with NIST to ensure compatibility either by NIST making SP 800-227 more flexible, or by changing this specification to only use HKDF-Extract.

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not. Implementers seeking FIPS certification of a Composite ML-KEM algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorithm with zero security, and the overall composite should be considered full strength and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions; for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.

### FIPS certification of Combiner Function

TODO: update this to NIST SP 800-227, once it is published.

One of the primary NIST documents which is relevant for certification of a composite algorithm is NIST SP.800-56Cr2 [SP.800-56Cr2] by using the allowed "hybrid" shared secret of the form `Z' = Z || T`. Compliance is achieved in the following way:

SP.800-56Cr2 section 4 "One-Step Key Derivation" requires a `counter` which begins at the 4-byte value 0x00000001. However, the counter is allowed to be omitted when the hash function is executed only once, as specified on page 159 of the FIPS 140-3 Implementation Guidance [FIPS-140-3-IG].

The HKDF-SHA2 options can be certified under SP.800-56Cr2 One-Step Key Derivation Option 1: `H(x) = hash(x)`.

The SHA3 options can be certified under SP.800-56Cr2 One-Step Key Derivation Option 2: `H(x) = HMAC-hash(salt, x)` with the salt omitted.


## Backwards Compatibility {#sec-backwards-compat}

As noted in the introduction, the post-quantum cryptographic migration will face challenges in both ensuring cryptographic strength against adversaries of unknown capabilities, as well as providing ease of migration. The composite mechanisms defined in this document primarily address cryptographic strength, however this section contains notes on how backwards compatibility may be obtained.

The term "ease of migration" is used here to mean that existing systems can be gracefully transitioned to the new technology without requiring large service disruptions or expensive upgrades. The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can inter-operate with the upgraded systems of the future.

These migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to key establishment and content encryption, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] encrypted structures.

## Decapsulation Requires the Public Key {#impl-cons-decaps-pubkey}

ML-KEM always requires the public key in order to perform various steps of the Fujisaki-Okamoto decapsulation [FIPS.203], and for this reason the private key encoding specified in FIPS 203 includes the public key. Therefore it is not required to carry it in the `OneAsymmetricKey.publicKey` field, which remains optional, but is strictly speaking redundant since an ML-KEM public key can be parsed from an ML-KEM private key, and thus populating the `OneAsymmetricKey.publicKey` field would mean that two copies of the public key data are transmitted.


With regard to the traditional algorithms, RSA or Elliptic Curve, in order to achieve the public-key binding property the KEM combiner used to form the Composite ML-KEM, the combiner requires the traditional public key as input to the KDF that derives the output shared secret. Therefore it is required to carry the public key within the respective `OneAsymmetricKey.publicKey` as per the private key encoding given in {{sec-priv-key}}. Implementers who choose to use a different private key encoding than the one specified in this document MUST consider how to provide the component public keys to the decapsulate routine. While some implementations might contain routines to computationally derive the public key from the private key, it is not guaranteed that all implementations will support this; for this reason the interoperable composite private key format given in this document in {{sec-priv-key}} requires the public key of the traditional component to be included.

<!-- End of Implementation Considerations section -->


# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/

EDNOTE TODO: Check with Max Pala whether this IPR actually applies to this draft.



# Contributors and Acknowledgments

This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust), Ali Noman (Entrust), Peter C. (UK NCSC), Sophie Schmieg (Google), Deirdre Connolly (SandboxAQ), Falko Strenzke (MTG AG), Dan van Geest (Crypto Next), Piotr Popis (Enigma), and
Douglas Stebila (University of Waterloo).

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].


<!-- End of Contributors section -->
