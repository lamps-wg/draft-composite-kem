---
title: Composite ML-KEM for use in X.509 Public Key Infrastructure
abbrev: Composite ML-KEM
docname: draft-ietf-lamps-pq-composite-kem-latest

# <!-- stand_alone: true -->
ipr: trust200902
area: Security
stream: IETF
wg: LAMPS
keyword:
 - X.509
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
  RFC2104:
  #RFC2119: -- does not need to be explicit; added by bcp14 boilerplate
  RFC5280:
  RFC5480:
  RFC5652:
  RFC5869:
  RFC5958:
  RFC6234:
  RFC7748:
  RFC8017:
  #RFC8174: -- does not need to be explicit; added by bcp14 boilerplateu
  RFC8410:
  RFC8411:
  RFC9629:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        - org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    date: May 21, 2009
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec1-v2.pdf
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    date: January 27, 2010
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec2-v2.pdf
  SP.800-56Ar3:
    title: "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography"
    date: April 2018
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
  SP.800-56Cr2:
    title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
    date: August 2020
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
  SP.800-57pt1r5:
    title: "Recommendation for Key Management: Part 1 – General"
    date: May 2020
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
  SP.800-185:
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
    date: December 2016
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
  FIPS.180-4:
    title: "FIPS Publication 180-4: Secure Hash Standard"
    date: August 2015
    author:
      - org: National Institute of Standards and Technology (NIST)
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
  FIPS.202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    author:
      - org: National Institute of Standards and Technology (NIST)
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  FIPS.203:
    title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
    date: August 13, 2024
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

informative:
  RFC2986:
  RFC4210:
  RFC4211:
  RFC5639:
  RFC5914:
  RFC5990:
  RFC6090:
  RFC7292:
  RFC7296:
  RFC8446:
  RFC8551:
  I-D.draft-ietf-pquip-pqt-hybrid-terminology-06:
  I-D.draft-ietf-lamps-kyber-certificates-10:
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
      - org: National Institute of Standards and Technology (NIST)
  SP-800-227ipd:
    title: "Recommendations for Key-Encapsulation Mechanisms (Initial Public Draft)"
    target: https://csrc.nist.gov/pubs/sp/800/227/ipd
    author:
      - name: Gorjan Alagic
      - name: Elaine Barker
      - name: Lily Chen
      - name: Dustin Moody
      - name: Angela Robinson
      - name: Hamilton Silberg
      - name: Noah Waller
      - org: National Institute of Standards and Technology (NIST)
  GHP18:
    title: KEM Combiners
    author:
      - name: Federico Giacon
      - name: Felix Heuer
      - name: Bertram Poettering
    date: 2018
    target: https://eprint.iacr.org/2018/024
  Aviram22:
    title: "Practical (Post-Quantum) Key Combiners from One-Wayness and Applications to TLS"
    author:
      - name: Nimrod Aviram
      - name: Benjamin Dowling
      - name: Ilan Komargodski
      - name: Kenneth G. Paterson
      - name: Eyal Ronen
      - name: Eylon Yogev
    target: https://eprint.iacr.org/2022/065
  CNSA2.0:
    title: "Commercial National Security Algorithm Suite 2.0"
    author:
     - org: National Security Agency
    target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  FIPS-140-3-IG:
    title: Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation Program
    target: https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: July 26, 2024
  ETSI.TS.103.744:
    title: "ETSI TS 103 744 V1.2.1 CYBER-QSC; Quantum-safe Hybrid Key Establishment"
    target: https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf
    author:
      - org: ETSI
    date: 2025-03


--- abstract

This document defines combinations of ML-KEM [FIPS.203] in hybrid with traditional algorithms RSA-OAEP, ECDH, X25519, and X448. These combinations are tailored to meet security best practices and regulatory guidelines. Composite ML-KEM is applicable in any application that uses X.509 or PKIX data structures that accept ML-KEM, but where the operator wants extra protection against breaks or catastrophic bugs in ML-KEM.

<!-- End of Abstract -->


--- middle

# Changes in version -07

Interop-affecting changes:

* ML-KEM secret keys are now only seeds.
* Since all ML-KEM keys and ciphertexts are now fixed-length, dropped the length-tagged encoding.
* Added complete test vectors.
* Added ML-KEM1024 + RSA3072 combination.
* Added ML-KEM1024+ECDH-P521 combination.
* Updated prototype OIDs so these don't conflict with the previous versions
* Removed the "Use in CMS" section so that we can get this document across the finish line, and defer CMS-related debates to a separate document.

Editorial changes:

* Since we are only using the first step of HKDF, which is HKDF-Extract() and not HKDF-Expand(), it was decided that it's clearer to systematically rename this to "HMAC Combiner".
* Added an informative section on the difference between SHA3 and HMAC-SHA2 combiners, and the difference between HKDF(), HKDF-Extract(), and HMAC().
* Since the serialization is now non-DER, drastically reduced the ASN.1-based text.
* Changed `HKDF-SHA384` to `HKDF-SHA512`. Since SHA-384 is a truncated version of SHA-512, and we are further truncating it to 256 bits, these are binary-compatible, might as well list the parent algorithm for clarity.
* Added a new section "KEM Combiner Examples" that show all the intermediate values of the KEM Combiner.

Still to do in a future version:

- Nothing. Authors believe this version to be complete.


# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic key establishment algorithms such as RSA-OAEP, Diffie-Hellman and its elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify both algorithmic weaknesses as well as implementation flaws across all the new implementations.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward.
For instance, the aggressive migration timelines may require deploying PQC algorithms before their implementations have been fully hardened or certified, and dual-algorithm data protection may be desirable over a longer time period to hedge against CVEs and other implementation flaws in the new implementations.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of a composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021], [ANSSI2024].

This specification defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key encapsulation mechanism (KEM) presenting a single public key and ciphertext such that it can be treated as a single atomic algorithm at the protocol level; a property referred to as "protocol backwards compatibility" since it can be applied to protocols that are not explicitly hybrid-aware. composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite ML-KEM algorithms are provided based on ML-KEM, RSA-OAEP and ECDH. Backwards compatibility in the sence of upgraded systems continuing to inter-operate with legacy systems is not directly covered in this specification, but is the subject of {{sec-backwards-compat}}.

Composite ML-KEM is applicable in any PKIX-related application that would otherwise use ML-KEM.


## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This specification is consistent with all terminology from {{I-D.ietf-pquip-pqt-hybrid-terminology}}.
In addition, the following terms are used in this specification:

**ALGORITHM**:
          The usage of the term "algorithm" within this
          specification generally refers to any function which
          has a registered Object Identifier (OID) for
          use within an ASN.1 AlgorithmIdentifier. This
          loosely, but not precisely, aligns with the
          definitions of "cryptographic algorithm" and
          "cryptographic scheme" given in {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

**COMBINER**:
  A combiner specifies how multiple shared secret keys are combined
  into a single shared secret key.

**COMPONENT / PRIMITIVE**:
  The words "component" or "primitive" are used interchangeably
  to refer to a cryptographic algorithm that is used internally
  within a composite algorithm. For example this could be an
  asymmetric algorithm such as "ML-KEM-768" or "RSA-OAEP", or a KDF such
  as "HMAC-SHA256".

**DER:**
  Distinguished Encoding Rules as defined in [X.690].

**KEM:**
   A key encapsulation mechanism as defined in {{sec-kems}}.

**PKI:**
  Public Key Infrastructure, as defined in {{RFC5280}}.

**SHARED SECRET KEY:**
  A value established between two communicating parties for use as
  cryptographic key material suitable for direct use by symmetric
  cryptographic algorithms. This specification is concerned with shared
  secrets established via public key cryptographic operations.



Notation:
The algorithm descriptions use python-like syntax. The following symbols deserve special mention:

 * `||` represents concatenation of two byte arrays.

 * `[:]` represents byte array slicing.

 * `(a, b)` represents a pair of values `a` and `b`. Typically this indicates that a function returns multiple values; the exact conveyance mechanism -- tuple, struct, output parameters, etc -- is left to the implementer.

 * `(a, _)`: represents a pair of values where one -- the second one in this case -- is ignored.

 * `Func<TYPE>()`: represents a function that is parametrized by `<TYPE>` meaning that the function's implementation will have minor differences depending on the underlying TYPE. Typically this means that a function will need to look up different constants or use different underlying cryptographic primitives depending on which composite algorithm it is implementing.


## Composite Design Philosophy

{{I-D.ietf-pquip-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite algorithms, as defined in this specification, follow this definition and should be regarded as a single key that performs a single cryptographic operation typical of a key establishment mechanism such as key generation, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, and ciphertext can be carried in existing fields in protocols such as PKCS#10 {{RFC2986}}, CMP {{RFC4210}}, X.509 {{RFC5280}}, CMS {{RFC5652}}, and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts an analogous single-algorithm cryptographic scheme without requiring any modification of the protocol to handle multiple algorithms.

Discussion of the specific choices of algorithm pairings can be found in {{sec-rationale}}.

# Overview of the Composite ML-KEM Scheme {#sec-kems}

Composite ML-KEM is a Post-Quantum / Traditional hybrid Key Encapsulation Mechanism (KEM) which combines ML-KEM as specified in [FIPS.203] and {{I-D.ietf-lamps-kyber-certificates}} with one of RSA-OAEP defined in [RFC8017], the Elliptic Curve Diffie-Hellman key agreement schemes ECDH defined in section 5.7.1.2 of [SP.800-56Ar3], and X25519 / X448 defined in [RFC8410]. A KEM combiner function is used to combine the two component shared secret keyss into a single shared secret key.

Composite Key Encapsulation Mechanisms are defined as cryptographic primitives that consist of three algorithms. These definitions are borrowed from {{RFC9180}}.

   *  `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
      which generates a public key `pk` and a secret key `sk`. Some cryptographic modules may also expose a `KeyGen(seed) -> (pk, sk)`, which generates `pk` and `sk` deterministically from a seed. This specification assumes a seed-based keygen for ML-KEM.

   *  `Encap(pk) -> (ss, ct)`: A probabilistic encapsulation algorithm,
      which takes as input a public key `pk` and outputs a ciphertext `ct`
      and shared secret key `ss`. Note: this specification uses `Encap()` to conform to {{?RFC9180}},
      but [FIPS.203] uses `Encaps()`.

   *  `Decap(sk, ct) -> ss`: A decapsulation algorithm, which takes as
      input a secret key `sk` and ciphertext `ct` and outputs a shared
      secret `ss`, or in some cases a distinguished error value.
      Note: this specification uses `Decap()` to conform to {{RFC9180}},
      but [FIPS.203] uses `Decaps()`.


The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}) and thus Composite ML-KEM MUST be used with KEMRecipientInfo defined in {{RFC9629}}, however full conventions for use of Composite ML-KEM within the Cryptographic Message Syntax will be included in a separate specification.

The KEM interface was chosen as the interface for a composite key establishment because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs as described in {{sec-RSAOAEPKEM}} and {{sec-DHKEM}} below.

The following algorithms are defined for serializing and deserializing component values. These algorithms are inspired by similar algorithms in {{RFC9180}}.

   * `SerializePublicKey(mlkemPK, tradPK) -> bytes`: Produce a byte string encoding of the component public keys.

   * `DeserializePublicKey(bytes) -> (mlkemPK, tradPK)`: Parse a byte string to recover the component public keys.

   * `SerializeCiphertext(mlkemCT, tradCT) -> bytes`: Produce a byte string encoding of the component ciphertexts.

   * `DeserializeCiphertext(bytes) -> (mlkemCT, tradCT)`: Parse a byte string to recover the component ciphertexts.

   * `SerializePrivateKey(mlkemSeed, tradSK) -> bytes`: Produce a byte string encoding of the component private keys.

   * `DeserializePrivateKey(bytes) -> (mlkemSeed, tradSK)`: Parse a byte string to recover the component private keys.

Full definitions of serialization and deserialization algorithms can be found in {{sec-serialization}}.



## Promotion of RSA-OAEP into a KEM {#sec-RSAOAEPKEM}

The RSA Optimal Asymmetric Encryption Padding (OAEP), as defined in section 7.1 of [RFC8017] is a public key encryption algorithm used to transport key material from a sender to a receiver. A "key transport" type algorithm has the following API:

   * `Encrypt(pk, ss) -> ct`: Take an existing shared secret key `ss` and encrypt it for `pk`.

   * `Decrypt(sk, ct) -> ss`: Decrypt the ciphertext `ct` to recover `ss`.

Note the difference between the API of `RSA.Encrypt(pk, ss) -> ct` and `KEM.Encap(pk) -> (ss, ct)` presented above. For this reason, RSA-OAEP cannot be directly combined with ML-KEM. Fortunately, a key transport mechanism such as RSA-OAEP can be easily promoted into a KEM by having the sender generate a random 256 bit shared secret key and encrypt it.

~~~
RSAOAEPKEM.Encap(pkR):
  shared_secret = SecureRandom(ss_len)
  enc = RSAES-OAEP-ENCRYPT(pkR, shared_secret)

  return shared_secret, enc
~~~

Acceptable public key encodings for `pkR` are described in {{sec-serialization}}.

Note that the OAEP label `L` is left to its default value, which is the empty string as per [RFC8017]. The shared secret key output by the overall Composite ML-KEM already binds a composite domain separator, so there is no need to also use the component domain separators.

The value of `ss_len` as well as concrete values for all the RSA-OAEP parameters used within this specification can be found in {{sect-rsaoaep-params}}.

`Decap(sk, ct) -> ss` is accomplished by direct use of OAEP Decrypt.

~~~
RSAOAEPKEM.Decap(skR, enc):
  shared_secret = RSAES-OAEP-DECRYPT(skR, enc)

  return shared_secret
~~~

A quick note on the choice of RSA-OAEP as the supported RSA encryption primitive. RSA-KEM [RFC5990] is cryptographically robust and is more straightforward to work with, but it has fairly limited adoption and therefore is of limited value as a PQ migration mechanism. Also, while RSA-PKCS#1v1.5 [RFC8017] is still widely used, it is hard to make secure and no longer FIPS-approved as of the end of 2023 [SP800-131Ar2], so it is of limited forwards value. This leaves RSA-OAEP [RFC8017] as the remaining choice. See {{sec-rationale}} for further discussion of algorithm choices.

Note that, at least at the time of writing, the algorithm `RSAOAEPKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it cannot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.

## Promotion of ECDH into a KEM {#sec-DHKEM}

The elliptic curve Diffie-Hellman algorithm identified by the OID `id-ecDH` as defined in [RFC5480] and [SEC1] is a key agreement algorithm requiring both parties to contribute an asymmetric keypair to the derivation of the shared secret key. A "key agreement" type algorithm has the following API:

   * `DH(skX, pkY) -> ss`: Each party combines their secret key `skX` with the other party's public key `pkY`.

Note the difference between the API of `DH(skX, pkY) -> ss` and `KEM.Encap(pk) -> (ss, ct)` presented above. For this reason, a Diffie-Hellman key exchange cannot be directly combined with ML-KEM. Fortunately, a Diffie-Hellman key agreement can be easily promoted into a KEM `Encap(pk) -> (ss, ct)` by having the sender generate an ephemeral keypair for themself and sending their public key as the ciphertext `ct`. Composite ML-KEM uses a simplified version of the DHKEM definition from [RFC9180]:

~~~
DHKEM.Encap(pkR):
  (skE, pkE) = GenerateKeyPair()
  ss = DH(skE, pkR)
  ct = SerializePublicKey(pkE)

  return ss, ct
~~~

`Decap(sk, ct) -> ss` is accomplished in the analogous way.

~~~
DHKEM.Decap(skR, ct):
  pkE = DeserializePublicKey(ct)
  ss = DH(skR, pkE)

  return ss
~~~

This construction applies for all variants of elliptic curve Diffie-Hellman used in this specification: ECDH, X25519, and X448.

For ECDH, `DH()` yields the value `Z` as described in section 5.7.1.2 of [SP.800-56Ar3].
Acceptable public key encodings for `enc` and `pkE` are described in {{sec-serialization}}.

For X25519 and X448, `DH()` yields the value `K` as described in section 6 of [RFC7748].
Acceptable public key encodings for `enc` and `pkE` are described in {{sec-serialization}}.

The promotion of DH to a KEM is similar to the DHKEM functions in [RFC9180], but it is simplified in the following ways:

1. Notation has been aligned to the notation used in this specification.
1. Since a domain separator is included explicitly in the Composite ML-KEM combiner, there is no need to perform the labeled steps of `ExtractAndExpand()`.
1. Since the ciphertext and receiver's public key are included explicitly in the Composite ML-KEM combiner, there is no need to construct the `kem_context` object.

Note that here, `SerializePublicKey()` and `DeserializePublicKey()` refer to the underlying encoding of the DH primitive, and not to the composite serialization functions defined in {{sec-serialization}}. Acceptable serializations for the underlying DH primitives are described in {{sec-serialization}}.

Note that, at least at the time of writing, the algorithm `DHKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it cannot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.


# Composite ML-KEM Functions {#sec-composite-mlkem}

This section describes the composite ML-KEM functions needed to instantiate the public API of a Key Encapsulation Mechanism as defined in {{sec-kems}}.

## Key Generation {#sec-keygen}

In order to maintain security properties of the composite, applications that use composite keys MUST always perform fresh key generations of both component keys and MUST NOT reuse existing key material. See {{sec-cons-key-reuse}} for a discussion.

To generate a new keypair for composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms independently. Multi-process or multi-threaded applications might choose to execute the key generation functions in parallel for better key generation performance.

The following describes how to instantiate a `KeyGen()` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-KEM<OID.KeyGen() -> (pk, sk)

Explicit Inputs:
     None

Implicit Inputs mapped from <OID>:

  ML-KEM     The underlying ML-KEM algorithm and
             parameter set, for example, could be "ML-KEM-768".

  Trad       The underlying traditional algorithm and
             parameter, for example "RSA-OAEP"
             or "X25519".

Output:
  (pk, sk)  The composite keypair.

Key Generation Process:

  1. Generate component keys

    mlkemSeed = Random(64)
    (mlkemPK, _) = ML-KEM.KeyGen(mlkemSeed)
    (tradPK, tradSK) = Trad.KeyGen()

  2. Check for component key gen failure
    if NOT (mlkemPK, mlkemSK) or NOT (tradPK, tradSK):
      output "Key generation error"

  3. Output the composite public and private keys

    pk = SerializePublicKey(mlkemPK, tradPK)
    sk = SerializePrivateKey(mlkemSK, tradSK)
    return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite KeyGen() -> (pk, sk)"}

In order to ensure fresh keys, the key generation functions MUST be executed for both component algorithms. Compliant parties MUST NOT use, import or export component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use. For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.

Note that in step 2 above, both component key generation processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

Variations in the keygen process above and decapsulation processes below to accommodate particular private key storage mechanisms or alternate interfaces to the underlying cryptographic modules are considered to be conformant to this specification so long as they produce the same output and error handling.
For example, component private keys stored in separate software or hardware modules where it is not possible to do a joint simultaneous keygen would be considered compliant so long as both keys are freshly generated. It is also possible that the underlying cryptographic module does not expose a `ML-KEM.KeyGen(seed)` that accepts an externally-generated seed, and instead an alternate keygen interface must be used. Note however that cryptographic modules that do not support seed-based ML-KEM key generation will be incapable of importing or exporting composite keys in the standard format since the private key serialization routines defined in {{sec-serialize-privkey}} only support ML-KEM keys as seeds.

## Encapsulation

The `Encap(pk)` of a Composite ML-KEM algorithm is designed to behave exactly the same as `ML-KEM.Encaps(ek)` defined in Algorithm 20 in Section 7.2 of [FIPS.203]. Specifically, `Composite-ML-KEM.Encap(pk)` produces a 256-bit shared secret key that can be used directly with any symmetric-key cryptographic algorithm. In this way, Composite ML-KEM can be used as a direct drop-in replacement anywhere that ML-KEM is used.

The following describes how to instantiate a `Encap(pk)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-KEM<OID>.Encap(pk) -> (ss, ct)

Explicit Inputs:

  pk      Composite public key consisting of encryption public keys
          for each component.

Implicit inputs mapped from <OID>:

  ML-KEM  The underlying ML-KEM algorithm and
          parameter set, for example "ML-KEM-768".

  Trad    The underlying ML-KEM algorithm and
          parameter set, for example "RSA-OAEP"
          or "X25519".

  KDF     The KDF specified for the given Composite ML-KEM algorithm.
          See algorithm specifications below.

  Domain  Domain separator value for binding the ciphertext to the
          Composite OID. See section on Domain Separators below.

Output:

  ss      The shared secret key, a 256-bit key suitable for use with
          symmetric cryptographic algorithms.

  ct      The ciphertext, a byte string.

Encap Process:

  1. Separate the public keys.

      (mlkemPK, tradPK) = DeserializePublicKey(pk)

  2.  Perform the respective component Encap operations according to
      their algorithm specifications.

      (mlkemCT, mlkemSS) = ML-KEM.Encaps(mlkemPK)
      (tradCT, tradSS) = TradKEM.Encap(tradPK)

  3. If either ML-KEM.Encaps() or TradKEM.Encap() return an error,
     then this process must return an error.

      if NOT (mlkemCT, mlkemSS) or NOT (tradCT, tradSS):
        output "Encapsulation error"

  4. Encode the ciphertext

      ct = SerializeCiphertext(mlkemCT, tradCT)

  5. Combine the KEM secrets and additional context to yield the
     composite shared secret key.

        ss = KemCombiner<KDF>(mlkemSS, tradSS, tradCT, tradPK, Domain)

  6. Output composite shared secret key and ciphertext.

     return (ss, ct)
~~~
{: #alg-composite-mlkem-encap title="Composite-ML-KEM.Encap(pk)"}

Depending on the security needs of the application, it MAY be advantageous to perform steps 2, 3, and 5 in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed and from learning any of the inputs or output of the KEM combiner.

The specific values for `KDF` are defined per Composite ML-KEM algorithm in {{tab-kem-algs}} and the specific values for `Domain` are defined per Composite ML-KEM algorithm in {{sec-alg-ids}}.

## Decapsulation {#sect-composite-decaps}

The `Decap(sk, ct) -> ss` of a Composite ML-KEM algorithm is designed to behave exactly the same as `ML-KEM.Decaps(dk, c)` defined in Algorithm 21 in Section 7.3 of [FIPS.203]. Specifically, `Composite-ML-KEM.Decap(sk, ct)` produces a 256-bit shared secret key that can be used directly with any symmetric-key cryptographic algorithm. In this way, Composite ML-KEM can be used as a direct drop-in replacement anywhere that ML-KEM is used.

The following describes how to instantiate a `Decap(sk, ct)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-KEM<OID>.Decap(sk, ct) -> ss

Explicit inputs

  sk      Composite private key consisting of decryption private keys
          for each component.

  ct      The ciphertext, a byte string.

Implicit inputs mapped from <OID>:

  ML-KEM  The underlying ML-KEM algorithm and
          parameter set, for example, could be "ML-KEM-768".

  Trad    The underlying traditional algorithm and
          parameter set, for example "RSA-OAEP"
          or "X25519".

  KDF     The KDF specified for the given Composite ML-KEM algorithm.
          See algorithm specifications below.

  Domain  Domain separator value for binding the ciphertext to the
          Composite ML-KEM OID. See section on Domain Separators below.

Output:

  ss      The shared secret key, a 256-bit key suitable for use with
          symmetric cryptographic algorithms.

Decap Process:

  1. Separate the private keys and ciphertexts

      (mlkemSK, tradSK) = DeserializePrivateKey(sk)
      (mlkemCT, tradCT) = DeserializeCiphertext(ct)

  2.  Perform the respective component Encap operations according to
      their algorithm specifications.

      mlkemSS = MLKEM.Decaps(mlkemSK, mlkemCT)
      (_, tradSS)  = TradKEM.Decap(tradSK, tradCT)

  3. If either ML-KEM.Decaps() or TradKEM.Decap() return an error,
     then this process must return an error.

      if NOT mlkemSS or NOT tradSS:
        output "Encapsulation error"

  4. Combine the KEM secrets and additional context to yield the
     composite shared secret key.

      ss = KemCombiner<KDF>(mlkemSS, tradSS, tradCT, tradPK, Domain)

  5. Output composite shared secret key.

     return ss
~~~
{: #alg-composite-mlkem-decap title="Composite-ML-KEM.Decap(sk, ct)"}

Steps 2, 3, and 4 SHOULD be performed in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed and from learning any of the inputs or output of the KEM combiner.

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this specification so long as it produces the same output and error handling as the process sketched above.

In order to properly achieve its security properties, the KEM combiner requires that all inputs are fixed-length. Since each Composite ML-KEM algorithm fully specifies its component algorithms, including key sizes, all inputs should be fixed-length in non-error scenarios except for minor variations introduced by encoding. However some implementations may choose to perform additional checking to handle certain error conditions. In particular, the KEM combiner step should not be performed if either of the component decapsulations returned an error condition indicating malformed inputs. For timing-invariance reasons, it is RECOMMENDED to perform both decapsulation operations and check for errors afterwards to prevent an attacker from using a timing channel to tell which component failed decapsulation. Also, RSA-based composites MUST ensure that the modulus size (i.e. the size of `tradCT` and `tradPK`) matches that specified for the given Composite ML-KEM algorithm in {{tab-kem-algs}}; depending on the cryptographic library used, this check may be done by the library or may require an explicit check as part of the `Composite-ML-KEM.Decap()` routine. Implementers should keep in mind that some instances of `tradCT` and `tradPK` will be DER-encoded which could introduce minor length variations such as dropping leading zeroes; since these variations are not attacker-controlled they are considered benign.


## KEM Combiner Function {#sec-kem-combiner}

As noted in the Encapsulation and Decapsulation procedures above, the KEM combiner is parameterized by the choice of underlying KDF. This specification provides two combiner constructions, one with SHA3 and one with HMAC-SHA2.

The following describes how to instantiate a `KemCombiner()` function for a given key derivation function represented by `<KDF>`.

~~~
KemCombiner<KDF>(mlkemSS, tradSS, tradCT, tradPK, Domain) -> ss

Explicit inputs:

  The list of input values to be combined.

Implicit inputs:

  KDF      The KDF specified for the given Composite ML-KEM algorithm.
           In particular, for the KEM combiner it only matters
           whether this as a SHA3 function, which can be used
           as a KDF directly, or a SHA2 function which requires
           an HMAC construction.

Output:

  ss      The shared secret key, a 256-bit key suitable for use with
          symmetric cryptographic algorithms.


Process:

  if KDF is "SHA3-256":
    ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Domain)

  else if KDF is "HMAC-{Hash}":

    ss = HMAC-{Hash}(key={0}, text=mlkemSS || tradSS || tradCT
                                           || tradPK || Domain)
    ss = truncate(ss, 256)
        # Where "{0}" is the string of HashLen zeros according to
        # section 2.2 of [RFC5869].

        # Where "{Hash} is the underlying hash function used
        # for the given composite algorithm.

        # Since Composite ML-KEM always outputs a 256-bit shared
        # secret key, the output is always truncated to 256 bits,
        # regardless of underlying hash function.

  return ss
~~~

Implementation note: The HMAC-based combiner here is exactly the "HKDF-Extract" step from [RFC5869] with an empty `salt`. Implementations with access to "HKDF-Extract", without the "HKDF-Expand" step, MAY use this interchangeably with the HMAC-based construction presented above. Note that a full invocation of HKDF with both HKDF-Extract and HKDF-Expand, even with the correct output length and empty `info` param is not equivalent to the HMAC construction above since HKDF-Expand will always perform at least one extra iteration of HMAC.


# Serialization {#sec-serialization}

This section presents routines for serializing and deserializing composite public keys, private keys, and ciphertext values to bytes via simple concatenation of the underlying encodings of the component algorithms.
The functions defined in this section are considered internal implementation detail and are referenced from within the public API definitions in {{sec-composite-mlkem}}.

Deserialization is possible because ML-KEM has fixed-length public keys, private keys (seeds), and ciphertext values as shown in the following table.

| Algorithm   | Public Key  | Private Key |  Ciphertext  |
| ----------- | ----------- | ----------- |  ----------- |
| ML-KEM-768  |    1184     |     64      |     1088     |
| ML-KEM-1024 |    1568     |     64      |     1568     |
{: #tab-mlkem-sizes title="ML-KEM Key and Ciphertext Sizes"}

For all serialization routines below, when these values are required to be carried in an ASN.1 structure, they are wrapped as described in {{sec-encoding-to-der}}.

While ML-KEM has a single fixed-size representation for each of public key, private key, and ciphertext, the traditional component might allow multiple valid encodings; for example an elliptic curve public key, and therefore also ciphertext, might be validly encoded as either compressed or uncompressed [SEC1], or an RSA private key could be encoded in Chinese Remainder Theorem form [RFC8017]. In order to obtain interoperability, composite algorithms MUST use the following encodings of the underlying components:

* **ML-KEM**: MUST be encoded as specified in [FIPS.203], using a 64-byte seed as the private key.
* **RSA**: MUST be encoded with the `(n,e)` public key representation as specified in A.1.1 of [RFC8017] and the private key representation as specified in A.1.2 of [RFC8017].
* **ECDH**: public key MUST be encoded as an `ECPoint` as specified in section 2.2 of [RFC5480], with both compressed and uncompressed keys supported. For maximum interoperability, it is RECOMMENEDED to use uncompressed points.
* **X25519 and X448**: MUST be encoded as per section 5 of [RFC7748].

Even with fixed encodings for the traditional component, there may be slight differences in size of the encoded value due to, for example, encoding rules that drop leading zeroes. See {{sec-sizetable}} for further discussion of encoded size of each composite algorithm.

The deserialization routines described below do not check for well-formedness of the cryptographic material they are recovering. It is assumed that underlying cryptographic primitives will catch malformed values and raise an appropriate error.


## SerializePublicKey and DeserializePublicKey {#sec-serialize-pubkey}

The serialization routine for keys simply concatenates the public keys of the component algorithms, as defined below:

~~~
Composite-ML-KEM.SerializePublicKey(mlkemPK, tradPK) -> bytes

Explicit inputs:

  mlkemPK The ML-KEM public key, which is bytes.

  tradPK  The traditional public key in the appropriate
          encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite public key.


Serialization Process:

  1. Combine and output the encoded public key

     output mlkemPK || tradPK

~~~
{: #alg-composite-serialize title="SerializePublicKey(mlkemPK, tradPK) -> bytes"}

Deserialization reverses this process. Each component key is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializePublicKey(bytes)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-KEM<OID>.DeserializePublicKey(bytes) -> (mlkemPK, tradPK)

Explicit inputs:

  bytes   An encoded composite public key.

Implicit inputs mapped from <OID>:

  ML-KEM   The underlying ML-KEM algorithm and
           parameter, for example, could be "ML-KEM-768".

Output:

  mlkemPK  The ML-KEM public key, which is bytes.

  tradPK   The traditional public key in the appropriate
           encoding for the underlying component algorithm.


Deserialization Process:

  1. Parse each constituent encoded public key.
       The length of the mlkemPK is known based on the size of
       the ML-KEM component key length specified by the Object ID.

     switch ML-KEM do
        case ML-KEM-768:
          mlkemPK = bytes[:1184]
          tradPK  = bytes[1184:]
        case ML-KEM-1024:
          mlkemPK = bytes[:1568]
          tradPK  = bytes[1568:]

     Note that while ML-KEM has fixed-length keys, RSA and ECDH
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component public keys

     output (mlkemPK, tradPK)
~~~
{: #alg-composite-deserialize-pk title="DeserializePublicKey(bytes) -> (mlkemPK, tradPK)"}




## SerializePrivateKey and DeserializePrivateKey {#sec-serialize-privkey}

The serialization routine for keys simply concatenates the private keys of the component algorithms, as defined below:

~~~
Composite-ML-KEM.SerializePrivateKey(mlkemSeed, tradSK) -> bytes

Explicit inputs:

  mlkemSeed  The ML-KEM private key, which is the bytes of the seed.

  tradSK     The traditional private key in the appropriate
             encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite private key.

Serialization Process:

  1. Combine and output the encoded private key.

     output mlkemSeed || tradSK
~~~
{: #alg-composite-serialize-priv-key title="SerializePrivateKey(mlkemSeed, tradSK) -> bytes"}


Deserialization reverses this process. Each component key is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializePrivateKey(bytes)` function. Since ML-KEM private keys are 64 bytes for all paramater sets, this function does not need to be parametrized.

~~~
Composite-ML-KEM.DeserializePrivateKey(bytes) -> (mlkemSeed, tradSK)

Explicit inputs:

  bytes   An encoded composite private key.

Implicit inputs:

  That an ML-KEM private key is 64 bytes for all parameter sets.

Output:

  mlkemSeed  The ML-KEM private key, which is the bytes of the seed.

  tradSK    The traditional private key in the appropriate
             encoding for the underlying component algorithm.


Deserialization Process:

  1. Parse each constituent encoded key.
     The length of an ML-KEM private key is always a 64 byte seed
     for all parameter sets.

     mlkemSeed = bytes[:64]
     tradSK  = bytes[64:]

     Note that while ML-KEM has fixed-length keys, RSA and ECDH
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component private keys

     output (mlkemSeed, tradSK)
~~~
{: #alg-composite-deserialize-priv-key title="DeserializeKey(bytes) -> (mlkemSeed, tradSK)"}




## SerializeCiphertext and DeserializeCiphertext

The serialization routine for the composite ciphertext value simply concatenates the fixed-length
ML-KEM ciphertext with the ciphertext from the traditional algorithm, as defined below:

~~~
Composite-ML-KEM.SerializeCiphertext(mlkemCT, tradCT) -> bytes

Explicit inputs:

  mlkemCT  The ML-KEM ciphertext, which is bytes.

  tradCT   The traditional ciphertext in the appropriate
           encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite ciphertext value.


Serialization Process:

  1. Combine and output the encoded composite ciphertext

     output mlkemCT || tradCT

~~~
{: #alg-composite-serialize-ct title="SerializeCiphertext(mlkemCT, tradCT) -> bytes"}


Deserialization reverses this process, raising an error in the event that the input is malformed.  Each component signature is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializeCiphertext(bytes)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-KEM<OID>.DeserializeCiphertext(bytes)
                                                -> (mldkemCT, tradCT)

Explicit inputs:

  bytes   An encoded composite ciphertext value.

Implicit inputs mapped from <OID>:

  ML-KEM   The underlying ML-KEM algorithm and
           parameter, for example, could be "ML-KEM-768".

Output:

  mlkemCT  The ML-KEM ciphertext, which is bytes.

  tradCT   The traditional ciphertext in the appropriate
           encoding for the underlying component algorithm.


Deserialization Process:

  1. Parse each constituent encoded ciphertext.
     The length of the mlkemCT is known based on the size of
     the ML-KEM component ciphertext length specified by the Object ID.

     switch ML-KEM do
        case ML-KEM-768:
          mlkemCT = bytes[:1088]
          tradCT  = bytes[1088:]
        case ML-KEM-1024:
          mlkemCT= bytes[:1568]
          tradCT  = bytes[1568:]

     Note that while ML-KEM has fixed-length ciphertexts, RSA and ECDH
     may not, depending on encoding, so rigorous length-checking is
     not always possible here.

  2. Output the component ciphertext values

     output (mlkemCT, tradCT)
~~~
{: #alg-composite-deserialize-ct title="DeserializeCiphertext(bytes) -> (mldkemCT, tradCT)"}




# Use within X.509 and PKIX

The following sections provide processing logic and the necessary ASN.1 modules necessary to use composite ML-KEM within X.509 and PKIX protocols. Use within the Cryptographic Message Syntax (CMS) will be covered in a separate specification.

While composite ML-KEM keys and ciphertext values MAY be used raw, the following sections provide conventions for using them within X.509 and other PKIX protocols such that Composite ML-KEM can be used as a drop-in replacement for KEM algorithms in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], and related protocols.


## Encoding to DER {#sec-encoding-to-der}

The serialization routines presented in {{sec-serialization}} produce raw binary values. When these values are required to be carried within a DER-encoded message format such as an X.509's `subjectPublicKey BIT STRING` [RFC5280] or a CMS `KEMRecipientInfo.kemct OCTET STRING` [RFC9629], then the composite value MUST be wrapped into a DER BIT STRING or OCTET STRING in the obvious ways.

When a BIT STRING is required, the octets of the composite data value SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

When an OCTET STRING is required, the DER encoding of the composite data value SHALL be used directly.



## Key Usage Bits

When any Composite ML-KEM Object Identifier appears within the `SubjectPublicKeyInfo.AlgorithmIdentifier` field of an X.509 certificate [RFC5280], the key usage certificate extension MUST only contain:

~~~
keyEncipherment
~~~

Composite ML-KEM keys MUST NOT be used in a "dual usage" mode because even if the
traditional component key supports both signing and encryption,
the post-quantum algorithms do not and therefore the overall composite algorithm does not. Implementations MUST NOT use one component of the composite for the purposes of digital signature and the other component for the purposes of encryption or key establishment.


## ASN.1 Definitions {#sec-asn1-defs}

Composite ML-KEM uses a substantially non-ASN.1 based encoding, as specified in {{sec-serialization}}. However, as as composite algorithms will be used within ASN.1-based X.509 and PKIX protocols, some conventions for ASN.1 wrapping are necessary.

The following ASN.1 Information Object Classes are defined to allow for compact definitions of each composite algorithm, leading to a smaller overall ASN.1 module.

~~~ ASN.1
pk-CompositeKEM {OBJECT IDENTIFIER:id}
  PUBLIC-KEY ::= {
    IDENTIFIER id
    KEY BIT STRING
    PARAMS ARE absent
    CERT-KEY-USAGE { keyEncipherment }
  }

kema-CompositeKEM {
  OBJECT IDENTIFIER:id,
    PUBLIC-KEY:publicKeyType }
    KEM-ALGORITHM ::= {
         IDENTIFIER id
         VALUE OCTET STRING
         PARAMS ARE absent
         PUBLIC-KEYS { publicKeyType }
        }
~~~
{: #asn1-info-classes title="ASN.1 Object Information Classes for Composite ML-KEM"}

As an example, the public key and KEM algorithm types associated with `id-MLKEM768-ECDH-P256-HMAC-SHA256` are defined as:

~~~
pk-MLKEM768-ECDH-P256-HMAC-SHA256 PUBLIC-KEY ::=
  pk-CompositeKEM {
    id-MLKEM768-ECDH-P256-HMAC-SHA256 }

kema-MLKEM768-ECDH-P256-HMAC-SHA256 KEM-ALGORITHM ::=
    kema-CompositeKEM{
      id-MLKEM768-ECDH-P256-HMAC-SHA256,
      pk-MLKEM768-ECDH-P256-HMAC-SHA256 }
~~~


The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


Use cases that require an interoperable encoding for composite private keys will often need to place a composite private key inside a `OneAsymmetricKey` structure defined in [RFC5958], such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211]. The definition of `OneAsymmetricKey` is copied here for convenience:

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
{: artwork-name="RFC5958-OneAsymmetricKey-asn.1-structure" title="OneAsymmetricKey as defined in [RFC5958]"}

When a composite private key is conveyed inside a `OneAsymmetricKey` structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the `privateKeyAlgorithm` field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}} and its parameters field MUST be absent.  The `privateKey` field SHALL contain the OCTET STRING reperesentation of the serialized composite private key as per {{sec-serialize-privkey}}. The `publicKey` field remains OPTIONAL. If the `publicKey` field is present, it MUST be a composite public key as per {{sec-serialize-pubkey}}.

Some applications might need to reconstruct the `SubjectPublicKeyInfo` or `OneAsymmetricKey` objects corresponding to each component key individually, for example if this is required for invoking the underlying primitive. {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

Component keys of a composite private key MUST NOT be used in any other type of key or as a standalone key. For more details on the security considerations around key reuse, see {{sec-cons-key-reuse}}.



# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the OID and the component algorithms for each Composite ML-KEM algorithm.

EDNOTE: these are prototyping OIDs to be replaced by IANA.

&lt;CompKEM&gt; is equal to 2.16.840.1.114027.80.5.2

| Composite ML-KEM Algorithm         | OID                  | ML-KEM | Trad     | KDF      |
|---------                           | -----------------    | ----------      | ----------           | -------- |
| id-MLKEM768-RSA2048-HMAC-SHA256    | &lt;CompKEM&gt;.50   | ML-KEM-768        | RSA-OAEP 2048        | HMAC-SHA256 |
| id-MLKEM768-RSA3072-HMAC-SHA256    | &lt;CompKEM&gt;.51   | ML-KEM-768        | RSA-OAEP 3072        | HMAC-SHA256 |
| id-MLKEM768-RSA4096-HMAC-SHA256    | &lt;CompKEM&gt;.52   | ML-KEM-768        | RSA-OAEP 4096        | HMAC-SHA256 |
| id-MLKEM768-X25519-SHA3-256        | &lt;CompKEM&gt;.53   | ML-KEM-768        | X25519               | SHA3-256 |
| id-MLKEM768-ECDH-P256-HMAC-SHA256  | &lt;CompKEM&gt;.54   | ML-KEM-768        | ECDH with secp256r1            | HMAC-SHA256 |
| id-MLKEM768-ECDH-P384-HMAC-SHA256  | &lt;CompKEM&gt;.55   | ML-KEM-768        | ECDH with secp384r1            | HMAC-SHA256 |
| id-MLKEM768-ECDH-brainpoolP256r1-HMAC-SHA256   | &lt;CompKEM&gt;.56   | ML-KEM-768        | ECDH with brainpoolp256r1 | HMAC-SHA256 |
| id-MLKEM1024-RSA3072-HMAC-SHA512   | &lt;CompKEM&gt;.61   | ML-KEM-1024       | RSA-OAEP 3072        | HMAC-SHA512 |
| id-MLKEM1024-ECDH-P384-HMAC-SHA512 | &lt;CompKEM&gt;.57   | ML-KEM-1024       | ECDH with secp384r1            | HMAC-SHA512 |
| id-MLKEM1024-ECDH-brainpoolP384r1-HMAC-SHA512  | &lt;CompKEM&gt;.58   | ML-KEM-1024       | ECDH with brainpoolP384r1 | HMAC-SHA512 |
| id-MLKEM1024-X448-SHA3-256         | &lt;CompKEM&gt;.59   | ML-KEM-1024       | X448                 | SHA3-256 |
| id-MLKEM1024-ECDH-P521-HMAC-SHA512 | &lt;CompKEM&gt;.60   | ML-KEM-1024       | ECDH with secp521r1            | HMAC-SHA512 |
{: #tab-kem-algs title="Composite ML-KEM key types"}

In alignment with ML-KEM [FIPS.203], Composite KEM algorithms output a 256-bit shared secret key at all security levels, truncating is necessary as described in {{sec-kem-combiner}}.

The KDFs were chosen to roughly match the security level of the stronger component. In the case of X25519 and X448 SHA3-256 is used to match the construction in {{X-Wing}}.

Full specifications for the referenced component algorithms can be found in {{appdx_components}}.

As the number of algorithms can be daunting to implementers, see {{sec-impl-profile}} for a discussion of choosing a subset to support.


## Domain Separator Values {#sec-domsep-values}

The KEM combiner used in this specification requires a domain separator `Domain` input.  The following table shows the HEX-encoded domain separator for each Composite ML-KEM AlgorithmID; to use it, the value MUST be HEX-decoded and used in binary form. The domain separator is simply the DER encoding of the composite algorithm OID.


Each Composite ML-KEM algorithm has a unique domain separator value which is used in constructing the KEM combiner in ({{sec-kem-combiner}}). This helps protect against a different algorithm arriving at the same shared secret key even if all inputs are the same; for example `id-MLKEM768-X25519-SHA3-256` and X-Wing {{X-Wing}} have identical component algorithms and KEM combiners but since they have different security properties, they use different domain separators in order to make them incompatible by design.

The domain separator is simply the DER encoding of the OID. The following table shows the HEX-encoded domain separator value for each Composite ML-KEM algorithm.


<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/domSepTable.md}
{: #tab-kem-domains title="Composite ML-KEM fixedInfo Domain Separators"}

EDNOTE: these domain separators are based on the prototyping OIDs assigned on the Entrust arc. We will need to ask for IANA early allocation of these OIDs so that we can re-compute the domain separators over the final OIDs.



## Rationale for choices {#sec-rationale}


In generating the list of composite algorithms, the idea was to provide composite algorithms at various security levels with varying performance charactaristics.

The main design consideration in choosing pairings is to prioritize providing pairings of each ML-KEM security level with commonly-deployed traditional algorithms. This supports the design goal of using composites as a stepping stone to efficiently deploy post-quantum on top of existing hardened and certified traditional algorithm implementations. This was prioritized rather than attempting to exactly match the security level of the post-quantum and traditional components -- which in general is difficult to do since there is no academic consensus on how to compare the "bits of security" against classical attackers and "qubits of security" against quantum attackers.

SHA2 is prioritized over SHA3 in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-KEM module. However SHA3 is used with X25519 and X448 SHA3-256 to match the construction in {{X-Wing}}. This also provides a slight efficiency gain for the X25519 and X448 based composites since a single invocation of SHA3 is known to behave as a dual-PRF, and thus is sufficient for use as a KDF, see {{sec-cons-kem-combiner}}, compared with an HMAC-SHA2 construction.

While it may seem odd to use 256-bit outputs at all security levels, this aligns with ML-KEM [FIPS.203] which produces a 256-bit shared secret key at all security levels. All hash functions used have >= 256 bits of (2nd) pre-image resistance, which is the required property for a KDF to provide 128 bits of security, as allowed in Table 3 of {{SP.800-57pt1r5}}. Composite algorithms at higher security levels use a larger hash function in order to preserve internal collision resistance of the hash function at a comparable strength to the underlying component algorithms up to the point where truncation to a 256-bit output is performed.




## RSA-OAEP Parameters {#sect-rsaoaep-params}

Use of RSA-OAEP [RFC8017] requires additional parameters to be specified.

The RSA component keys MUST be generated at the specified 2048-bit, 3072-bit, 4096-bit key sizes respectively (up to small differences such as dropping leading zeros); intermediate sizes are not acceptable.

As with the other Composite ML-KEM algorithms, AlgorithmIdentifier parameters MUST be absent. The RSA-OAEP primitive SHALL be instantiated with the following hard-coded parameters which are the same for the 2048, 3072 and 4096 bit security levels since the objective is to carry and output a 256-bit shared secret key at all security levels.

| RSAES-OAEP-params           | Value               |
| ----------------------      | ---------------     |
| hashAlgorithm               | id-sha256           |
| MaskGenAlgorithm.algorithm  | id-mgf1             |
| maskGenAlgorithm.parameters | id-sha256           |
| pSourceAlgorithm            | pSpecifiedEmpty     |
| ss_len                      | 256 bits            |
{: #rsa-oaep-params title="RSA-OAEP Parameters"}

Full specifications for the referenced algorithms can be found in {{appdx_components}}.

Note: The mask length, according to [RFC8017], is `k - hLen - 1`, where `k` is the size of the RSA modulus. Since the choice of hash function and the RSA key size is fixed for each composite algorithm, implementations could choose to pre-compute and hard-code the mask length.


# ASN.1 Module {#sec-asn1-module}

~~~ ASN.1

<CODE STARTS>

{::include Composite-MLKEM-2025.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}

##  Object Identifier Allocations

EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-kem-algs}}.

###  Module Registration

The following is to be regisetered in "SMI Security for PKIX Module Identifier":

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-KEM-2023 - id-mod-composite-kems
-  References: This Document

###  Object Identifier Registrations

The following is to be registered in "SMI Security for PKIX Algorithms":

- id-MLKEM768-RSA2048-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA2048-HMAC-SHA256
  - References: This Document

- id-MLKEM768-RSA3072-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA3072-HMAC-SHA256
  - References: This Document

- id-MLKEM768-RSA4096-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-RSA4096-HMAC-SHA256
  - References: This Document

- id-MLKEM768-ECDH-P256-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P256-HMAC-SHA256
  - References: This Document

- id-MLKEM768-ECDH-P384-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P384-HMAC-SHA256
  - References: This Document

- id-MLKEM768-ECDH-brainpoolP256r1-HMAC-SHA256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-brainpoolP256r1-HMAC-SHA256
  - References: This Document

- id-MLKEM768-X25519-SHA3-256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-X25519-SHA3-256
  - References: This Document

- id-MLKEM1024-RSA3072-HMAC-SHA512
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-RSA3072-HMAC-SHA512
  - References: This Document

- id-MLKEM1024-ECDH-P384-HMAC-SHA512
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-P384-HMAC-SHA512
  - References: This Document

- id-MLKEM1024-ECDH-brainpoolP384r1-HMAC-SHA512
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-brainpoolP384r1-HMAC-SHA512
  - References: This Document

- id-MLKEM1024-X448-SHA3-256
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-X448-SHA3-256
  - References: This Document

- id-MLKEM1024-ECDH-P521-HMAC-SHA512
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-P521-HMAC-SHA512
  - References: This Document

<!-- End of IANA Considerations section -->


# Security Considerations

## Why Hybrids?

In broad terms, a PQ/T Hybrid can be used either to provide dual-algorithm security or to provide migration flexibility. Let's quickly explore both.

Dual-algorithm security. The general idea is that the data is protected by two algorithms such that an attacker would need to break both in order to compromise the data. As with most of cryptography, this property is easy to state in general terms, but becomes more complicated when expressed in formalisms. The following sections go into more detail here.

Migration flexibility. Some PQ/T hybrids exist to provide a sort of "OR" mode where the application can choose to use one algorithm or the other or both. The intention is that the PQ/T hybrid mechanism builds in backwards compatibility to allow legacy and upgraded applications to co-exist and communicate. The composite algorithms presented in this specification do not provide this since they operate in a strict "AND" mode. They do, however, provide codebase migration flexibility. Consider that an organization has today a mature, validated, certified, hardened implementation of RSA or ECC; composites allow them to add an ML-KEM implementation which immediately starts providing benefits against harvest-now-decrypt-later attacks even if that ML-KEM implementation is still an experimental, non-validated, non-certified, non-hardened implementation. More details of obtaining FIPS certification of a composite algorithm can be found in {{sec-fips}}.

## KEM Combiner {#sec-cons-kem-combiner}

The KEM combiner from {{sec-kem-combiner}} is reproduced here for reference.

~~~
  KDF(mlkemSS || tradSS || tradCT || tradPK || Domain)
~~~
{: #code-generic-kem-combiner title="KEM combiner construction"}


The primary security property of the KEM combiner is that it preserves IND-CCA2 of the overall Composite ML-KEM so long as at least one component is IND-CCA2 {{X-Wing}} [GHP18]. Additionally, we also need to consider the case where one of the component algorithms is completely broken; that the private key is known to an attacker, or worse that the public key, private key, and ciphertext are manipulated by the attacker. In this case, we rely on the construction of the KEM combiner to ensure that the value of the other shared secret key cannot be leaked or the combined shared secret key predicted via manipulation of the broken algorithm.


Each registered Composite ML-KEM algorithm specifies the choice of `KDF` and `Domain` -- see {{sec-alg-ids}} and {{sec-domsep-values}}. Given that each Composite ML-KEM algorithm fully specifies the component algorithms, including for example the size of the RSA modulus, all inputs to the KEM combiner are fixed-size and thus do not require length-prefixing.

* `mlkemSS` is always 32 bytes.
* `tradSS` in the case of ECDH this is derived by the decapsulator and therefore the length is not controlled by the attacker, however in the case of RSA-OAEP this value is directly chosen by the sender and both the length and content could be freely chosen by an attacker.
* `tradCT` is either an elliptic curve public key or an RSA-OAEP ciphertext which is required to have its length checked by step 1b of RSAES-OAEP-DECRYPT in [RFC8017].
* `tradPK` is the public key of the traditional component (elliptic curve or RSA) and therefore fixed-length.
* `Domain` is a fixed value specified in this document.


### IND-CCA Security of the hybrid scheme {#sec-hybrid-security}

Informally, a Composite ML-KEM algorithm is secure if the combiner (HMAC-SHA2 or SHA3) is secure, and either ML-KEM is secure or the traditional component (RSA-OAEP, ECDH, or X25519) is secure.

The security of ML-KEM and ECDH hybrids is covered in [X-Wing] and requires that the first KEM component (ML-KEM in this construction) is IND-CCA and second ciphertext preimage resistant (C2PRI) and that the second traditional component is IND-CCA. This design choice improves performance by not including the large ML-KEM public key and ciphertext, but means that an implementation error in the ML-KEM component that affects the ciphertext check step of the FO transform could result in the overall composite no longer achieving IND-CCA2 security. Note that ciphertext collisions exist in the traditional component by the composite design choice to support any underlying encoding of the traditional component, such as compressed vs uncompressed EC points as the ECDH KEM ciphertext. This solution remains IND-CCA due to binding the `tradPK` and `tradCT` in the KEM combiner.

The QSF framework presented in [X-Wing] is extended to cover RSA-OAEP as the traditional algorithm in place of ECDH by noting that RSA-OAEP is also IND-CCA secure [RFC8017].

Note that X-Wing uses SHA3 as the combiner KDF whereas Composite ML-KEM uses either SHA3 or HMAC-SHA2 which are interchangeable in the X-Wing proof since both behave as random oracles under multiple concatenated inputs.

The composite combiner cannot be assumed to be secure when used with different KEMs and a more cautious approach would bind the public key and ciphertext of the first KEM as well.


### Second pre-image resistance of component KEMs {#sec-cons-ct-collision}

The notion of a "ciphertext second pre-image resistant KEM" is defined in [X-Wing] as being the property that it is computationally difficult to find two different ciphertexts `c != c'` that will decapsulate to the same shared secret key under the same public key. For the purposes of a hybrid KEM combiner, this property means that given two composite ciphertexts `(c1, c2)` and `(c1', c2')`, we must obtain a unique overall shared secret key so long as either `c1 != c1'` or `c2 != c2'` -- i.e. the overall Composite ML-KEM is ciphertext second pre-image resistant, and therefore secure so long as one of the component KEMs is secure.

In [X-Wing] it is proven that ML-KEM is a second pre-image resistant KEM and therefore the ML-KEM ciphertext can safely be omitted from the KEM combiner. Note that this makes a fundamental assumption on ML-KEM remaining ciphertext second pre-image resistant, and therefore this formulation of KEM combiner does not fully protect against implementation errors in the ML-KEM component -- particularly around the ciphertext check step of the Fujisaki-Okamoto transform -- which could trivially lead to second ciphertext pre-image attacks that break the IND-CCA2 security of the ML-KEM component and of the overall Composite ML-KEM. This could be more fully mitigated by binding the ML-KEM ciphertext in the combiner, but a design decision was made to settle for protection against algorithmic attacks and not implementation attacks against ML-KEM in order to increase performance.

However, since neither RSA-OAEP nor ECDH guarantee second pre-image resistance at all, even in a correct implementation, these ciphertexts are bound to the key derivation in order to guarantee that `c != c'` will yield a unique ciphertext, and thus restoring second pre-image resistance to the overall Composite ML-KEM.

### SHA3 vs HMAC-SHA2

In order to achieve the desired security property that the Composite ML-KEM is IND-CCA2 whenever at least one of the component KEMs is, the KDF used in the KEM combiner needs to possess collision and second pre-image resistance with respect to each of its inputs independently; a property sometimes called "dual-PRF" [Aviram22]. Collision and second-pre-image resistance protects against compromise of one component algorithm from resulting in the ability to construct multiple different ciphertexts which result in the same shared secret key. Pre-image resistance protects against compromise of one component algorithm being used to attack and learn the value of the other shared secret key.

SHA3 is known to have all of the necessary dual-PRF properties [X-Wing], but SHA2 does not and therefore all SHA2-based constructions MUST use SHA2 within an HMAC construction such as HKDF-Extract upon which the composite HMAC combiner is based [GHP18].

### Generifying this construction

It should be clear that the security analysis of the presented KEM combiner construction relies heavily on the specific choices of component algorithms and combiner KDF, and this combiner construction SHOULD NOT by applied to any other combination of ciphers without performing the appropriate security analysis.

## Key Reuse {#sec-cons-key-reuse}

While conformance with this specification requires that both components of a composite key MUST be freshly generated, the designers are aware that some implementers may be forced to break this rule due to operational constraints. This section documents the implications of doing so.

When using single-algorithm cryptography, the best practice is to always generate fresh keying material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device. However, in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated. However this reasoning does not hold in the PQ / Traditional hybrid setting.

Within the broader context of PQ / Traditional hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions and did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take already-deployed RSA keys and add an ML-KEM key to them to form a hybrid. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" where one component signature can be extracted and presented as a single-algorithm signature. Hybrid KEMs using a concatenation-style KEM combiner, as is done in this specification, do not have the analogous attack surface because even if an attacker is able to extract and decrypt one of the component ciphertexts, this will yield a different shared secret key than the overall shared secret key derived from the composite, so any subsequent symmetric cryptographic operations will fail.

In addition, there is a further implication to key reuse regarding certificate revocation. Upon receiving a new certificate enrolment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, if one, or even both, components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, because the possibility of key reuse exists even though forbidden in this specification, CAs performing revocation checks on a composite key SHOULD also check both component keys independently to verify that the component keys have not been revoked.


## Decapsulation failure

Provided all inputs are well-formed, the key establishment procedure of ML-KEM will never explicitly fail. Specifically, the `ML-KEM.Encaps()` and `ML-KEM.Decaps()` algorithms from [FIPS.203] will always output a value with the same data type as a shared secret key, and will never output an error or failure symbol. However, it is possible (though extremely unlikely) that the process will fail in the sense that `ML-KEM.Encaps()` and `ML-KEM.Decaps()` will produce different outputs, even though both of them are behaving honestly and no adversarial interference is present. This is due to the lattice arithmetic for decapsulation with the secret key having hit an unrecoverable degenerate case that could not have been predicted by the encapsulator without knowledge of the secret key. In this case, the sender and recipient clearly did not succeed in producing a shared secret key. This event is called a decapsulation failure. Estimates for the decapsulation failure probability (or rate) for each of the ML-KEM parameter sets are provided in Table 1  of [FIPS.203] and reproduced here in {{tab-mlkem-failure-rate}}.


| Parameter set     | Decapsulation failure rate  |
|---------          | -----------------           |
| ML-KEM-512        | 2^(-139)                    |
| ML-KEM-768        | 2^(-164)                    |
| ML-KEM-1024       | 2^(-174)                    |
{: #tab-mlkem-failure-rate title="ML-KEM decapsulation failure rates"}

In the case of ML-KEM decapsulation failure, Composite ML-KEM MUST preserve the same behaviour and return a well-formed output shared secret key.


## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), the path to deprecating it through policy and removing it from operational environments is, at least is principle, straightforward.

In the composite model this is less obvious since a PQ/T hybrid is expected to still be considered valid after the traditional component is deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms. In general this should be manageable through policy by removing OIDs for the standalone component algorithms while still allowing OIDs for composite algorithms. However, complications may arise when the composite implementation needs to invoke the cryptographic module for a deprecated component algorithm. In particular, this could lead to complex Cryptographic Bills of Materials that show implementations of deprecated algorithms still present and being used.


<!-- End of Security Considerations section -->




# Implementation Considerations {#sec-in-pract}

## FIPS Certification {#sec-fips}

The following sections give guidance to implementers wishing to FIPS-certify a composite implementation.

This guidance is not authoritative and has not been endorsed by NIST.

Implementers seeking FIPS certification of a composite KEM algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorithm with zero security, and the overall composite should be considered at least as strong and thus FIPS-approved.

The composite algorithm has been designed to treat the underlying primitives as "black-box implementations" and not impose any additional requirements on them that could require an existing implementation of an underlying primitive to run in a mode different from the one under which it was certified. For example, the `KeyGen` defined in {{sec-keygen}} invokes `ML-KEM.KeyGen(seed)` which might not be available in a cryptographic module running in FIPS-mode, but {{sec-keygen}} is only a suggested implementation and the composite KeyGen MAY be implemented using a different available interface for ML-KEM.KeyGen.

The authors wish to note that composite algorithms provide a design pattern to provide utility in future situations that require care to remain FIPS-compliant, such as future cryptographic migrations as well as bridging across jurisdictions with non-intersecting cryptographic requirements.

The following sections go into further detail on specific issues that relate to FIPS certification.

### Combiner Function

For reference, the KEM combiner used in Composite ML-KEM is:

~~~
ss = KDF(mlkemSS || tradSS || tradCT || tradPK || Domain)
~~~

where KDF is either SHA3 or HMAC-SHA2.


NIST SP 800-227 [SP-800-227ipd], which at the time of writing is in its initial public draft period, allows hybrid key combiners of the following form:

~~~
K ← KDM(S1‖S2‖ · · · ‖St , OtherInput)           (14)
~~~

Composite ML-KEM maps cleanly into this since it places the two shared secret keys `mlkemSS || tradSS` at the beginning of the KDF input such that all other inputs `tradCT || tradPK || Domain` can be considered part of `OtherInput` for the purposes of FIPS certification.

For the detailed steps of the Key Derivation Mechanism KDM, [SP-800-227ipd] refers to [SP.800-56Cr2].

Compliance of the Composite ML-KEM variants is achieved in the following way:

The Composite ML-KEM algorithms using HMAC-SHA2 can be certified under [SP.800-56Cr2] One-Step Key Derivation Option 2: `H(x) = HMAC-hash(salt, x)` where `salt` is the empty (0 octet) string, which will internally be mapped to the zero vector `0x00..00` of the correct input size for the underlying hash function. This satisfies the requirement in [SP.800-56Cr2]:

> "in the absence of an agreed-upon alternative – the default_salt shall be an all-zero byte string whose bit length equals that specified as the bit length of an input block for the hash function, hash"

The Composite ML-KEM algorithms using SHA3 can be certified under [SP.800-56Cr2] One-Step Key Derivation Option 1: `H(x) = hash(x)`.

[SP.800-56Cr2] section 4 "One-Step Key Derivation" requires a `counter` which begins at the 4-byte value 0x00000001. However, the counter is allowed to be omitted when the hash function is executed only once, as specified on page 159 of the FIPS 140-3 Implementation Guidance [FIPS-140-3-IG].

### Order of KDF inputs with Non-Approved Algorithms

[SP-800-227ipd] adds an important stipulation that was not present in earlier NIST specifications:

> This publication approves the use of the key combiner (14) for any t > 1, so long as at
> least one shared secret (i.e., S_j for some j) is a shared secret generated from the key-
> establishment methods of SP 800-56A or SP 800-56B, or an approved KEM.

This means that although Composite ML-KEM always places the shared secret key from ML-KEM in the first slot, a Composite ML-KEM can be FIPS certified so long as either component is FIPS certified. This is important for several reasons. First, in the early stages of PQC migration, composites allow for a non-FIPS certified ML-KEM implementation to be added to a module that already has a FIPS certified traditional component, and the resulting composite can be FIPS certified. Second, when eventually RSA and Elliptic Curve are no longer FIPS-allowed, the composite can retain its FIPS certified status on the strength of the ML-KEM component. Third, while this is outside the scope of this specification, the general composite construction could be used to create FIPS certified algorithms that contain a component algorithm from a different jurisdiction. Third, a composite where both components are FIPS-certified could allow an implementer to patch one component algorithm while awaiting re-certification while continuing to use the overall composite in FIPS mode.

At the time of writing, [SP-800-227ipd] is in its public draft period and not yet in force. A Composite ML-KEM implementation using a FIPS-certified traditional component and a non-FIPS certified ML-KEM is not believed to be certifiable under [SP.800-56Cr2] since this requires the shared secret key from the certified algorithm to be in the first slot.

## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this specification.

These migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to key establishment and content encryption, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] encrypted structures.



## Profiling down the number of options {#sec-impl-profile}

One daunting aspect of this specification is the number of composite algorithm combinations.
Each option has been specified because there is a community that has a direct application for it; typically because the traditional component is already deployed in a change-managed environment, or because that specific traditional component is required for regulatory reasons.

However, this large number of combinations leads either to fracturing of the ecosystem into non-interoperable sub-groups when different communities choose non-overlapping subsets to support, or on the other hand it leads to spreading development resources too thin when trying to support all options.

This specification does not list any particular composite algorithm as mandatory-to-implement, however organizations that operate within specific application domains are encouraged to define profiles that select a small number of composites appropriate for that application domain.
For applications that do not have any regulatory requirements or legacy implementations to consider, it is RECOMMENDED to focus implementation effort on:

    id-MLKEM768-X25519-SHA3-256
    id-MLKEM768-ECDH-P256-HMAC-SHA256

In applications that only allow NIST PQC Level 5, it is RECOMMENDED to focus implementation effort on:

    id-MLKEM1024-ECDH-P384-HMAC-SHA512




## Decapsulation Requires the Public Key {#impl-cons-decaps-pubkey}

ML-KEM always requires the public key in order to perform various steps of the Fujisaki-Okamoto decapsulation [FIPS.203], and for this reason the private key encoding specified in FIPS 203 includes the public key. Moveover, the KEM combiner as specified in {{sec-kem-combiner}} requires the public key of the traditional component in order to achieve the public-key binding property and ciphertext collision resistance as described in {{sec-cons-kem-combiner}}.

The mechanism by which an application transmits the public keys is out of scope of this specification, but it MAY be accomplished by placing a serialized composite public key into the optional `OneAsymmetricKey.publicKey` field of the private key object.

Implementers who choose to use a different private key encoding than the one specified in this document MUST consider how to provide the component public keys to the decapsulate routine. While some implementations might contain routines to computationally derive the public key from the private key, it is not guaranteed that all implementations will support this.



<!-- End of Implementation Considerations section -->


--- back

# Approximate Key and Ciphertext Sizes {#sec-sizetable}

The sizes listed below are approximate: these values are measured from the test vectors, however, several factors could cause fluctuations in the size of the traditional component. For example, this could be due to:

* Compressed vs uncompressed EC point.
* The RSA public key `(n, e)` allows `e` to vary is size between 3 and `n - 1` [RFC8017].
* When the underlying RSA or EC value is itself DER-encoded, integer values could occaisionally be shorter than expected due to leading zeros being dropped from the encoding.

By contrast, ML-KEM values are always fixed size, so composite values can always be correctly de-serialized based on the size of the ML-KEM component.

Implementations MUST NOT perform strict length checking based on the values in this table except for ML-KEM + X25519 or X448; since these algorithms produce fixed-size outputs, the values in the table below for these variants MAY be treated as constants.

Non-hybrid ML-KEM is included for reference.


<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/sizeTable.md}
{: #tab-size-values title="Approximate size values of composite ML-KEM"}



# Component Algorithm Reference {#appdx_components}

This section provides references to the full specification of the algorithms used in the composite constructions.

| Component KEM Algorithm ID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | [FIPS.203] |
| id-ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | [FIPS.203] |
| id-X25519 | 1.3.101.110 | [RFC7748], [RFC8410] |
| id-X448 | 1.3.101.111 | [RFC7748], [RFC8410] |
| id-ecDH | 1.3.132.1.12 | [RFC5480], [SEC1] |
| id-RSAES-OAEP | 1.2.840.113549.1.1.7 | [RFC8017] |
{: #tab-component-encr-algs title="Component Encryption Algorithms used in Composite Constructions"}

| Elliptic CurveID | OID | Specification |
| ----------- | ----------- | ----------- |
| secp256r1 | 1.2.840.10045.3.1.7 | [RFC6090], [SEC2] |
| secp384r1 | 1.3.132.0.34 | [RFC6090], [SEC2] |
| secp521r1 | 1.3.132.0.35 | [RFC6090], [SEC2] |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | [RFC5639] |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | [RFC5639] |
{: #tab-component-curve-algs title="Elliptic Curves used in Composite Constructions"}

| HashID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-sha256 | 2.16.840.1.101.3.4.2.1 | [RFC6234] |
| id-sha512 | 2.16.840.1.101.3.4.2.3 | [RFC6234] |
| id-sha3-256 | 2.16.840.1.101.3.4.2.8 | [FIPS.202] |
{: #tab-component-hash title="Hash algorithms used in Composite Constructions"}


# Fixed Component Algorithm Identifiers

The following sections list explicitly the DER encoded `AlgorithmIdentifier` that MUST be used when reconstructing `SubjectPublicKeyInfo` objects for each component algorithm type, which may be required for example if cryptographic library requires the public key in this form in order to process each component algorithm. The public key `BIT STRING` should be taken directly from the respective component of the Composite ML-KEM public key.


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

**ECDH NIST-P-521**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm secp521r1    -- (1.3.132.0.35)
        }
      }
    }

DER:
  30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23
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


# Comparison with other Hybrid KEMs

## X-Wing

This specification borrows extensively from the analysis and KEM combiner construction presented in [X-Wing]. In particular, X-Wing and id-MLKEM768-X25519-SHA3-256 are largely interchangeable. The one difference is that X-Wing uses a combined KeyGen function to generate the two component private keys from the same seed, which gives some additional binding properties. However, using a derived value as the seed for `ML-KEM.KeyGen_internal()` is, at time of writing, explicitly disallowed by [FIPS.203] which makes it impossible to create a FIPS-compliant implementation of X-Wing's KeyGen  or private key import functionality. For this reason, this specification keeps the key generation for both components separate and only loosely-specified so that implementers are free to use an existing certified hardware or software module for one or both components.

Due to the difference in key generation and security properties, X-Wing and id-MLKEM768-X25519-SHA3-256 have been registered as separate algorithms with separate OIDs, and they use a different domain separator string in order to ensure that their ciphertexts are not inter-compatible.

## ETSI CatKDF

[ETSI.TS.103.744] section 8.2.3 defines CatKDF as:

~~~
1) Form secret = psk || k1 || k 2.
2) Set context = f(info, MA, MB), where f is a context formatting function.
3) key_material = KDF(secret, label, context, length).
4) Return key_material.

MA shall contain all of the public keys.
MB shall contain all of the corresponding public keys and ciphertexts.
~~~

The main difference between the Composite ML-KEM combiner and the ETSI CatKDF combiner is that CatKDF makes the more conservative choice to bind the public keys and ciphertexts of both components, while Composite ML-KEM follows the analysis presented in [X-Wing] that while preserving the security properties of the traditional component requires binding the public key and ciphertext of the traditional component, it is not necessary to do so for ML-KEM thanks to the rejection sampling step of the Fujisaki-Okamoto transform.

Additionally, ETSI CatKDF can be instantiated with either HMAC [RFC2104], KMAC [SP.800-185] or HKDF [RFC5869] as KDF. Using HMAC aligns with some of the KDF variants in this specification, but not the ones that use SHA3 which do not have an equivalent construction of CatKDF.

# KEM Combiner Examples

This section provides examples of constructing the input for the KEM Combiner, showing all intermediate values. This is intended to be useful for debugging purposes. See {{sec-kem-combiner}} for additional information.

Each input component is shown. Note that values are shown hex-encoded for display purposes only, they are actually raw binary values.

* `mlkemSS` is the shared secret produced by the ML-KEM encapsulate or decapsulate function which is always 32 bytes.
* `tradSS` is the shared secret produce by the traditional algorithm.
* `tradCT` is either an elliptic curve public key or an RSA-OAEP ciphertext depending on the algorithm chosen.
* `tradPK` is the public key of the traditional component (elliptic curve or RSA) and therefore fixed-length.
* `Domain` is the specific domain separator for this composite algorithm.  See {{sec-domsep-values}}

Next, the `Combined KDF Input` is given, which is simply the concatenation of the above values.

Finally, the `KDF Function` and the `ss Output` are shown as outputs.  The `ss` is the Composite ML-KEM shared-secret generated by applying the KDF to the `Combined KDF Input`.

Examples are given for each recommended Composite ML-KEM algorithm from {{sec-impl-profile}}, which happens to demonstrate all three combiner functions.

Example 1:

~~~
{::include ./src/kemCombiner_MLKEM768_ECDH_P256_HMAC-SHA256.md}
~~~

Example 2:

~~~
{::include ./src/kemCombiner_MLKEM768_X25519_SHA3_256.md}
~~~

Example 3:

~~~
{::include ./src/kemCombiner_MLKEM1024_ECDH_P384_HMAC_SHA512.md}
~~~

# Test Vectors {#appdx-samples}

The following test vectors are provided in a format similar to the NIST ACVP Known-Answer-Tests (KATs).

The structure is that a global `cacert` is provided which is used to sign each KEM certificate.


Within each test case there are the following values:

* `tcId` the name of the algorithm.
* `ek` the encapsulation public key.
* `x5c` the X.509 certificate of the encapsulation key, signed by the cacert.
* `dk` the raw decapsulation private key.
* `dk_pkcs8` the decapsulation private key in a PKCS#8 object.
* `c` the ciphertext.
* `k` the derived shared secret key.

Implementers should be able to perform the following tests using the test vectors below:

1. Load the public key `ek` or certificate `x5c` and perform an encapsulation for it.
2. Load the decapsulation private key `dk` or `dk_pkcs8` and the ciphertext `c` and ensure that the same shared secret key `k` can be derived.

Test vectors are provided for each underlying ML-KEM algorithm in isolation for the purposes of debugging.


Due to the length of the test vectors, some readers will prefer to retrieve the non-word-wrapped copy from GitHub. The reference implementation written in python that generated them is also available.

https://github.com/lamps-wg/draft-composite-kem/tree/main/src

TODO: lock this to a specific commit.

~~~
{::include src/testvectors_wrapped.json}
~~~



# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/



# Contributors and Acknowledgments

This document incorporates contributions and comments from a large group of experts. The editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past six years in pursuit of this document:

Serge Mister (Entrust),
Felipe Ventura (Entrust),
Richard Kettlewell (Entrust),
Ali Noman (Entrust),
Peter C. (UK NCSC),
Tim Hollebeek (Digicert),
Sophie Schmieg (Google),
Deirdre Connolly (SandboxAQ),
Chris A. Wood (Apple),
Bas Westerbaan (Cloudflare),
Falko Strenzke (MTG AG),
Dan van Geest (Crypto Next),
Piotr Popis (Enigma),
Jean-Pierre Fiset (Crypto4A),
陳志華 (Abel C. H. Chen, Chunghwa Telecom),
林邦曄 (Austin Lin, Chunghwa Telecom) and
Douglas Stebila (University of Waterloo).

Thanks to Giacomo Pope (github.com/GiacomoPope) whose ML-DSA and ML-KEM implementations were used to generate the test vectors.

We are grateful to all who have given feedback over the years, formally or informally, on mailing lists or in person, including any contributors who may have been inadvertently omitted from this list.

Finally, we wish to thank the authors of all the referenced documents upon which this specification was built. "Copying always makes things easier and less error prone" - [RFC8411].

<!-- End of Contributors section -->
