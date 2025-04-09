---
title: Composite ML-KEM for use in Cryptographic Message Syntax (CMS)
abbrev: Composite ML-KEM CMS
docname: draft-ietf-lamps-cms-composite-kem-latest

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
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany


normative:
  RFC2119:
  RFC4055:
  RFC5280:
  RFC5480:
  RFC5652:
  RFC5869:
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
  I-D.draft-ietf-lamps-pq-composite-kem:
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
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

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
  ETSI.TS.103.744:
    title: "ETSI TS 103 744 V1.1.1 CYBER; Quantum-safe Hybrid Key Exchanges"
    target: https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.01.01_60/ts_103744v010101p.pdf
    author:
      org: ETSI
    date: 2020-12


--- abstract

This document defines conventions for using Composite ML-KEM within the Cryptographic Message Syntax (CMS). This document is intended to be coupled with the CMS KEMRecipientInfo mechanism in {{RFC9629}}.

<!-- End of Abstract -->


--- middle



# Introduction {#sec-intro}

This document acts as a companion to {{I-D.draft-ietf-lamps-pq-composite-kem}} by providing conventions for using the Composite ML-KEM algorithm withith the Cryptographic Message Syntax (CMS).





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



# Overview of the Composite ML-KEM Scheme {#sec-kems}

The following text is copied from {{I-D.draft-ietf-lamps-pq-composite-kem}} and provides an overview of the KEM interface provided by Composite ML-KEM.

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

   *  `SerializePublicKey(pk) -> bytes`: Produce a byte string encoding the public key pk.

   *  `DeserializePublicKey(bytes) -> pk`: Parse a byte string to recover a public key pk. This function can fail if the input byte string is malformed.

We define the following algorithms which are used to serialize and deseralize the CompositeCiphertextValue

   *  `SerializeCiphertextValue(CompositeCiphertextValue) -> bytes`: Produce a byte string encoding the CompositeCiphertextValue.

   *  `DeserializeCipherTextValue(bytes) -> pk`: Parse a byte string to recover a CompositeCiphertextValue. This function can fail if the input byte string is malformed.

The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}).

The KEM interface was chosen as the interface for a composite key establishment because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs as described in {{sec-RSAOAEPKEM}} and {{sec-DHKEM}} below.

This specification uses the Post-Quantum KEM ML-KEM as specified in [FIPS.203] and {{I-D.ietf-lamps-kyber-certificates}}. For Traditional KEMs, this document uses the RSA-OAEP algorithm defined in [RFC8017], the Elliptic Curve Diffie-Hellman key agreement schemes ECDH defined in section 5.7.1.2 of [SP.800-56Ar3], and X25519 / X448 which are defined in [RFC8410]. A combiner function is used to combine the two component shared secrets into a single shared secret.






# Use in CMS

Composite ML-KEM algorithms MAY be employed for one or more recipients in the CMS enveloped-data content type [RFC5652], the CMS authenticated-data content type [RFC5652], or the CMS authenticated-enveloped-data content type [RFC5083]. In each case, the KEMRecipientInfo [RFC9629] is used with the chosen Composite ML-KEM Algorithm to securely transfer the content-encryption key from the originator to the recipient.

All recommendations for using Composite ML-KEM in CMS are fully aligned with the use of ML-KEM in CMS {{I-D.ietf-lamps-cms-kyber}}.

## Underlying Components

A compliant implementation MUST support the following algorithm combinations for the KEMRecipientInfo `kdf` and `wrap` fields when the corresponding Composite ML-KEM algorithm is listed in the KEMRecipientInfo `kem` field. The KDFs listed below align with the KDF used internally within the KEM combiner. An implementation MAY also support other key-derivation functions and other key-encryption algorithms within CMS KEMRecipientInfo and SHOULD use algorithms of equivalent strength or greater.

| Composite ML-KEM Algorithm                    | KDF                     | Wrap |
|---------                                      | ---                     | ---                |
| id-MLKEM768-RSA2048-HKDF-SHA256               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-RSA3072-HKDF-SHA256               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-RSA4096-HKDF-SHA256               | id-alg-hkdf-with-sha256 | id-aes128-wrap     |
| id-MLKEM768-X25519-SHA3-256                   | id-kmac256              | id-aes128-wrap     |
| id-MLKEM768-ECDH-P256-HKDF-SHA256             | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM768-ECDH-P384-HKDF-SHA256             | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM768-ECDH-brainpoolP256r1-HKDF-SHA256  | id-alg-hkdf-with-sha256 | id-aes256-wrap     |
| id-MLKEM1024-ECDH-P384-HKDF-SHA384            | id-alg-hkdf-with-sha384 | id-aes256-wrap     |
| id-MLKEM1024-ECDH-brainpoolP384r1-HKDF-SHA384 | id-kmac256              | id-aes256-wrap     |
| id-MLKEM1024-X448-SHA3-256                    | id-kmac256              | id-aes256-wrap     |
{: #tab-cms-kdf-wrap title="Mandatory-to-implement pairings for CMS KDF and WRAP"}


Full specifications for the referenced algorithms can be found either further down in this section, or in {{appdx_components}}.

Note that here we differ slightly from the internal KDF used within the KEM combiner in {{sec-alg-ids}} because [RFC9629] requires that the KDF listed in the KEMRecipientInfo `kdf` field must have an interface which accepts `KDF(IKM, L, info)`, so here we need to use KMAC and cannot directly use SHA3. Since we require 256-bits of (2nd) pre-image resistance, we use KMAC256 for the Composite ML-KEM algorithms with internally use SHA3-256, as aligned with Table 3 of {{SP.800-57pt1r5}}.


### Use of the HKDF-based Key Derivation Function within CMS

Unlike within the Composite KEM Combiner function, When used as a KDF for CMS, HKDF requires use of the HKDF-Expand step so that it can accept the length parameter `kekLength` from CMS KEMRecipientInfo as the HKDF parameter `L`.

The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is defined in {{!RFC5869}}. The HKDF function is a composition of the HKDF-Extract and HKDF-Expand functions.

~~~
HKDF(salt, IKM, info, L)
  = HKDF-Expand(HKDF-Extract(salt, IKM), info, L)
~~~

HKDF(salt, IKM, info, L) takes the following parameters:

salt:
: optional salt value (a non-secret random value). In this document this parameter is left at its default value, which is the string of HashLen zeros.

IKM:
: input keying material. In this document this is the shared secret outputted from the Encaps() or Decaps() functions.  This corresponds to the IKM KDF input from {{Section 5 of RFC9629}}.

info:
: optional context and application specific information. In this document this corresponds to the info KDF input from {{Section 5 of RFC9629}}. This is the ASN.1 DER encoding of CMSORIforKEMOtherInfo.

L:
: length of output keying material in octets. This corresponds to the L KDF input from {{Section 5 of RFC9629}}, which is identified in the kekLength value from KEMRecipientInfo. Implementations MUST confirm that this value is consistent with the key size of the key-encryption algorithm.

HKDF may be used with different hash functions, including SHA-256 and SHA-384 {{FIPS.180-4}}. The object identifier id-alg-hkdf-with-sha256 and id-alg-hkdf-with-sha384 are defined in [RFC8619], and specify the use of HKDF with SHA-256 and SHA-384. The parameter field MUST be absent when this algorithm identifier is used to specify the KDF for ML-KEM in KemRecipientInfo.



### Use of the KMAC-based Key Derivation Function within CMS

KMAC256-KDF is a KMAC-based KDF specified for use in CMS in {{I-D.ietf-lamps-cms-sha3-hash}}. The definition of KMAC is copied here for convenience.  Here, KMAC# indicates the use of either KMAC128-KDF or KMAC256-KDF, although only KMAC256 is used in this specification.

KMAC#(K, X, L, S) takes the following parameters:

> K: the input key-derivation key.  In this document this is the shared secret outputted from the Encaps() or Decaps() functions.  This corresponds to the IKM KDF input from Section 5 of [RFC9629].

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

> kdf identifies the key-derivation algorithm. Note that the Key Derivation Function (KDF) used for CMS RecipientInfo process (to calculate the RecipientInfo KEK key) MAY be different than the KDF used within the Composite ML-KEM algorithm (to calculate the shared secret ss) and MAY also be different from any KDFs used internally within a component algorithm.

> kekLength is the size of the key-encryption key in octets.

> ukm is an optional random input to the key-derivation function. ML-KEM doesn't place any requirements on the ukm contents.

> wrap identifies a key-encryption algorithm used to encrypt the content-encryption key.

> encryptedKey is the result of encryptiong the CEK with the KEK.

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

{::include Composite-MLKEM-2025.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}

IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry [RFC7299] for the included ASN.1 module.

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-KEM-2025 - id-mod-composite-cms-kems
-  References: This Document

<!-- End of IANA Considerations section -->


# Security Considerations

## Why Hybrids?

In broad terms, a PQ/T Hybrid can be used either to provide dual-algorithm security or to provide migration flexibility. Let's quickly explore both.

Dual-algorithm security. The general idea is that the data is proctected by two algorithms such that an attacker would need to break both in order to compromise the data. As with most of cryptography, this property is easy to state in general terms, but becomes more complicated when expressed in formalisms. The following sections go into more detail here.

Migration flexibility. Some PQ/T hybrids exist to provide a sort of "OR" mode where the client can choose to use one algorithm or the other or both. The intention is that the PQ/T hybrid mechanism builds in backwards compatibility to allow legacy and upgraded clients to co-exist and communicate. The Composites presented in this specification do not provide this since they operate in a strict "AND" mode, but they do provide codebase migration flexibility. Consider that an organization has today a mature, validated, certified, hardened implementation of RSA or ECC. Composites allow them to add to this an ML-KEM implementation which immediately starts providing benefits against harvest-now-decrypt-later attacks even if that ML-KEM implemtation is still experimental, non-validated, non-certified, non-hardened implementation. More details of obtaining FIPS certification of a composite algorithm can be found in {{sec-fips}}.

## SHA3 vs HKDF-SHA2

This specification uses both HKDF-SHA2 as well as SHA3 / KMAC as Key Derivation Functions (KDFs) within the CMS layer. From a security perspective, these are considered to have equivalent strength. As such, HKDF-SHA2 is generally the preferred choice simply for the reason that SHA2 tends to have better adoption and hardware acceleration at the time of publication. Several combinations have been specified with a mandatory-to-implement SHA3 / KMAC KDF in order to provide some cryptographic diversity in case HKDF-SHA2 falls out of favour in the future, and to allow closer alignment to the internal construction of ML-KEM.


## Key Reuse {#sec-cons-key-reuse}

When using single-algorithm cryptography, the best practice is to always generate fresh keying material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device, however in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated. With composite keys we have a much stricter security requirement. However this reasoning does not hold in the PQ / Traditional hybrid setting.

Within the broader context of PQ / Traditional hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions and did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take already-deployed RSA keys and add an ML-KEM key to them to form a hybrid. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" where one component signature can be extracted and presented as a single-algorithm signature. Hybrid KEMs using a concatenation-style KEM combiner, as is done in this document, do not have the analogous attack surface because even if an attacker is able to extract and decrypt one of the component ciphertexts, this will yield a different shared secret than the overall shared secret derived from the composite, so any subsequent symmetric cryptographic operations will fail. However there is still a risk of key reuse which relates to certificate revocation, as well as general key reuse security issues.

Upon receiving a new certificate enrollment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, even if both components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, it is RECOMMENDED to avoid key reuse and always generate fresh component keys for a new composite. It is also RECOMMENDED that CAs performing revocation checks on a composite key should also check both component keys independently.



## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), the path to deprecating it and removing it from operational environments is, at least is principle, straightforward.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled independently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLKEM512-ECDH-P256` even after ECDH-P256 is deprecated.

The Composite ML-KEM design specified in this document, and especially that of the KEM combiner specified in this document, and discussed in {{sec-cons-kem-combiner}}, means that the overall Composite ML-KEM algorithm should be considered to have the security strength of the strongest of its component algorithms; i.e. as long as one component algorithm remains strong, then the overall composite algorithm remains strong.


<!-- End of Security Considerations section -->

--- back





# Implementation Considerations {#sec-in-pract}


## Backwards Compatibility {#sec-backwards-compat}

TODO - say something meaningful about backwards compatibility within the CMS context.

## Decapsulation Requires the Public Key {#impl-cons-decaps-pubkey}

TODO - shorten this to the bit that's relevant to CMS.

ML-KEM always requires the public key in order to perform various steps of the Fujisaki-Okamoto decapsulation [FIPS.203], and for this reason the private key encoding specified in FIPS 203 includes the public key. Therefore it is not required to carry it in the `OneAsymmetricKey.publicKey` field, which remains optional, but is strictly speaking redundant since an ML-KEM public key can be parsed from an ML-KEM private key, and thus populating the `OneAsymmetricKey.publicKey` field would mean that two copies of the public key data are transmitted.


With regard to the traditional algorithms, RSA or Elliptic Curve, in order to achieve the public-key binding property the KEM combiner used to form the Composite ML-KEM, the combiner requires the traditional public key as input to the KDF that derives the output shared secret. Therefore it is required to carry the public key within the respective `OneAsymmetricKey.publicKey` as per the private key encoding given in {{sec-priv-key}}. Implementers who choose to use a different private key encoding than the one specified in this document MUST consider how to provide the component public keys to the decapsulate routine. While some implementations might contain routines to computationally derive the public key from the private key, it is not guaranteed that all implementations will support this; for this reason the interoperable composite private key format given in this document in {{sec-priv-key}} requires the public key of the traditional component to be included.

<!-- End of Implementation Considerations section -->

# Comparison with other Hybrid KEMs

## X-Wing

This specification borrows extensively from the analysis and KEM combiner construction presented in [X-Wing]. In particular, X-Wing and id-MLKEM768-X25519-SHA3-256 are largely interchangeable. The one difference is that X-Wing uses a combined KeyGen function to generate the two component private keys from the same seed, which gives some additional binding properies. However, using a derived value as the seed for ML-KEM.KeyGen_internal() is, at time of writing, explicitely disallowed by [FIPS.203] which makes it impossible to create a FIPS-compliant implentation of X-Wing KeyGen / private key import. For this reason, this specification keeps the key generatation for both components separate so that implementers are free to use an existing certified hardware or software module for one or both components.

Due to the difference in key generation and security properties, X-Wing and id-MLKEM768-X25519-SHA3-256 have been registered as separate algorithms with separate OIDs, and they use a different domain separator string in order to ensure that their ciphertexts are not inter-compatible.

## ETSI CatKDF

[ETSI.TS.103.744] section 8.2 defines CatKDF as:

~~~
1) Form secret = psk || k1 || k 2 || … || k n.
2) Set f_context = f(context, MA, MB), where f is a context formatting function.
3) key_material = KDF(secret, label, f_context, length).
4) Return key_material.

MA shall contain all of the public keys.
MB shall contain all of the corresponding public keys and ciphertexts.
~~~

The main difference between the Composite KEM combiner and the ETSI CatKDF combiner is that CatKDF makes the more conservative choice to bind the public keys and ciphertexts of both components, while Composite KEM follows the analysis presented in [X-Wing] that while preserving the security properties of the traditional component requires binding the public key and ciphertext of the traditional component, it is not necessary to do so for ML-KEM thanks to the rejection sampling step of the Fujisaki-Okamoto transform.

Additionally, ETSI CatKDF uses HKDF [RFC5869] as the KDF which aligns with some of the variants in this specification, but not the ones that use SHA3.


# Test Vectors {#appdx-samples}

TODO - Fix this once we have test vectors.


The following test vectors are provided in a format similar to the NIST ACVP Known-Answer-Tests (KATs).

The structure is that a global `cacert` is provided which is used to sign each KEM certificate.
Within each test case there are the following values:

* `tcId` the name of the algorithm.
* `ek` the encapsulation public key.
* `x5c` the X.509 certificate of the encapsulation key, signed by the cacert.
* `dk` the decapsulation private key.
* `c` the ciphertext.
* `k` the derived shared secret key.

Implementers should be able to perform the following tests using the test vectors below:

1. Load the public key `ek` or certificate `x5c` and perform an encapsulation for it.
2. Load the decapsulation private key `dk` and the ciphertext `c` and ensure that the same shared secret key `k` can be derived.

Test vectors are provided for each underlying component in isolation for the purposes of debugging.


Due to the length of the test vectors, you may prefer to retrieve them from GitHub. The reference implementation that generated them is also available:

https://github.com/lamps-wg/draft-composite-kem/tree/main/src

~~~
{::include src/testvectors_wrapped.json}
~~~



# Intellectual Property Considerations

None.


# Contributors and Acknowledgments

This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust), Ali Noman (Entrust), Peter C. (UK NCSC), Sophie Schmieg (Google), Deirdre Connolly (SandboxAQ), Falko Strenzke (MTG AG), Dan van Geest (Crypto Next), Piotr Popis (Enigma), and
Douglas Stebila (University of Waterloo).

Thanks to Giacomo Pope (github.com/GiacomoPope) whose ML-DSA and ML-KEM implementation was used to generate the test vectors.

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].


<!-- End of Contributors section -->
