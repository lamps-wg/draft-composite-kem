---
title: Composite ML-KEM For Use In Internet PKI
abbrev: Composite KEMs
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
  latest: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html#name-asn1-module

coding: us-ascii
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

normative:
  RFC2119:
  RFC5280:
  RFC5652:
  RFC5958:
  RFC8174:
  RFC8410:
  RFC8411:
  I-D.draft-ietf-lamps-rfc5990bis-04:
  I-D.draft-housley-lamps-cms-sha3-hash-01:
  ANS-X9.44:
    title: "Public Key
              Cryptography for the Financial Services Industry -- Key
              Establishment Using Integer Factorization Cryptography"
    author:
      org: "American National Standards Institute"
    date: 2007
    seriesinfo: American National Standard X9.44
  # SHA3:
  #   title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, FIPS PUB 202, DOI 10.6028/NIST.FIPS.202"
  #   author:
  #     org: "National Institute of Standards and Technology (NIST)"
  #   date: August 2015
  #   target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  SP800-185:
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash"
    author:
      org: "National Institute of Standards and Technology (NIST)"
    date: December 2016
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  BSI-ECC:
    title: "Technical Guideline BSI TR-03111: Elliptic Curve Cryptography. Version 2.10"
    author:
      org: "Federal Office for Information Security (BSI)"
    date: 2018-06-01
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
  FIPS.203-ipd:
    title: "Module-Lattice-based Key-Encapsulation Mechanism Standard"
    date: August 2023
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf


informative:
  RFC2986:
  RFC4210:
  RFC4211:
  RFC5639:
  RFC5914:
  RFC6090:
  RFC7292:
  RFC7296:
  RFC7748:
  RFC8446:
  RFC8551:
  I-D.draft-ietf-tls-hybrid-design-04:
  I-D.draft-driscoll-pqt-hybrid-terminology-01:
  I-D.draft-ounsworth-cfrg-kem-combiners-04:
  I-D.draft-ietf-lamps-kyber-certificates-01:
  I-D.draft-becker-guthrie-noncomposite-hybrid-auth-00:
  I-D.draft-housley-lamps-cms-kemri-02:
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


--- abstract

This document defines Post-Quantum / Traditional composite Key Encapsulation Mechanism (KEM) algorithms suitable for use within X.509 and PKIX and CMS protocols. Composite algorithms are provided which combine ML-KEM with RSA-KEM, ECDH, X25519, and X448. The provided set of composite algorithms should meet most CMS needs. For use within CMS, this document is intended to be coupled with the CMS KEMRecipientInfo mechanism in {{I-D.housley-lamps-cms-kemri}}.

<!-- End of Abstract -->


--- middle

# Changes in version -03

Changes to sync with X-Wing:

  - Removed ML-KEM ciphertext from KDF as per X-Wing proof -- this makes the KEM combiner ML-KEM specific, so:
    - Changed title to be ML-KEM specific.
  - Removed RSA-KEM ciphertext from KDF.
  - Changed the KDF from KMAC to SHA3.
  - Removed references to I-D.ounsworth-lamps-cms-dhkem since we'll just inline it and don't need a DHKEM wrapper.


Still to do in a future version:

  `[ ]` We need PEM samples … 118 hackathon? OQS friends? David @ BC? The right format for samples is probably to follow the hackathon ... a Dilithium or ECDSA trust anchor certificate, a composite KEM end entity certificate, and a CMS EnvolepedData sample encrypted for that composite KEM certificate.
  `[ ]` Open question: do we need to incluede the ECDH, X25519, X448, and RSA public keys is the KDF? X-Wing does, but previous versions of this spec do not. In general existing ECC and RSA hardware decryptor implementations might not know their own public key.

# Introduction {#sec-intro}


The migration to post-quantum cryptography is unique in the history of modern digital cryptography in that neither the old outgoing nor the new incoming algorithms are fully trusted to protect data for long data lifetimes. The outgoing algorithms, such as RSA and elliptic curve, may fall to quantum cryptalanysis, while the incoming post-quantum algorithms face uncertainty about both the underlying mathematics falling to classical algorithmic attacks as well as hardware and software implementations that have not had sufficient maturing time to rule out catestrophic implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear.

Cautious implementers may wish to combine cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected. Such mechanisms are referred to as Post-Quantum / Traditional Hybrids {{I-D.driscoll-pqt-hybrid-terminology}}.

PQ/T Hybrid cryptography can, in general, provide solutions to two migration problems:

- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Ease-of-migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.

This document defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key encapsulation mechanism (KEM) key and ciphertext such that they can be treated as a single atomic algorithm at the protocol level. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite KEM algorithms are provided based on ML-KEM, RSA-KEM and ECDH-KEM. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.


This document is intended for general applicability anywhere that key establishment or enveloped content encryption is used within PKIX or CMS structures.


## Terminology {#sec-terminology}
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This document is consistent with all terminology from {{I-D.driscoll-pqt-hybrid-terminology}}.
In addition, the following terms are used in this document:

**COMBINER:**
  A combiner specifies how multiple shared secrets are combined into
  a single shared secret.

**DER:**
  Distinguished Encoding Rules as defined in [X.690].

**KEM:**
   A key encapsulation mechanism as defined in {{sec-kems}}.

**PKI:**
  Public Key Infrastructure, as defined in [RFC5280].

**SHARED SECRET:**
  A value established between two communicating parties for use as
  cryptographic key material, but which cannot be learned by an active
  or passive adversary. This document is concerned with shared
  secrets established via public key cryptagraphic operations.

## Composite Design Philosophy

{{I-D.driscoll-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys as defined here follow this definition and should be regarded as a single key that performs a single cryptographic operation such key generation, signing, verifying, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, and ciphertext can be carried in existing fields in protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts KEM algorithms without requiring any modification of the protocol to handle multiple keys.


## Composite Key Encapsulation Mechanisms (KEMs) {#sec-kems}

We borrow here the definition of a key encapsulation mechanism (KEM) from {{I-D.ietf-tls-hybrid-design}}, in which a KEM is a cryptographic primitive that consists of three algorithms:

   *  KeyGen() -> (pk, sk): A probabilistic key generation algorithm,
      which generates a public key pk and a secret key sk.

   *  Encaps(pk) -> (ct, ss): A probabilistic encapsulation algorithm,
      which takes as input a public key pk and outputs a ciphertext ct
      and shared secret ss.

   *  Decaps(sk, ct) -> ss: A decapsulation algorithm, which takes as
      input a secret key sk and ciphertext ct and outputs a shared
      secret ss, or in some cases a distinguished error value.

The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}).

The KEM interface was chosen as the interface for a composite key establishment because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs. This specification uses the Post-Quantum KEM ML-KEM as specified in {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203-ipd]. For Traditional KEMs, this document relies on the RSA-KEM construction defined in {{I-D.ietf-lamps-rfc5990bis}} while the Elliptic Curve Diffie-Hellman key agreement schemes are inlined directly.

A composite KEM allows two or more underlying key transport, key agreement, or KEM algorithms to be combined into a single cryptographic operation by performing each operation, transformed to a KEM as outline above, and using a specified combiner function to combine the two or more component shared secrets into a single shared secret.


### Composite KeyGen

The `KeyGen() -> (pk, sk)` of a composite KEM algorithm will perform the `KeyGen()` of the respective component KEM algorithms and it produces a composite public key `pk` as per {{sec-composite-pub-keys}} and a composite secret key `sk` is per {{sec-priv-key}}.

### Composite Encaps

The `Encaps(pk) -> (ct, ss)` of a composite KEM algorithm is defined as:

~~~
Encaps(pk):
  # Split the component public keys
  pk1 = pk[0]
  pk2 = pk[1]

  # Perform the respective component Encaps operations
  (ct1, ss1) = ComponentKEM1.Encaps(pk1)
  (ct2, ss2) = ComponentKEM2.Encaps(pk2)

  # combine
  ct = CompositeCiphertextValue(ct1, ct2)
  ss = Combiner(ct1, ss1, ct2, ss2, algName)

  return (ct, ss)
~~~
{: #alg-composite-encaps title="Composite Encaps(pk)"}

where `Combiner(ct1, ss1, ct2, ss2, fixedInfo)` is defined in general in {{sec-kem-combiner}} with specific instantiations per composite KEM algorithm in {{sec-alg-ids}} and `CompositeCiphertextValue` is defined in {{sec-CompositeCiphertextValue}}.

### Composite Decaps

The `Decaps(sk, ct) -> ss` of a composite KEM algorithm is defined as:

~~~
Decaps(sk, ct):
  # Sptil the component ciphertexts
  ct1 = ct[0]
  ct2 = ct[1]

  # Perform the respective component Decaps operations
  ss1 = ComponentKEM1.Encaps(sk1, ct1)
  ss2 = ComponentKEM2.Encaps(sk2, ct2)

  # combine
  ss = Combiner(ct1, ss1, ct2, ss2, algName)

  return ss
~~~
{: #alg-composite-decaps title="Composite Decaps(sk, ct)"}

where `Combiner(ct1, ss1, ct2, ss2, fixedInfo)` is defined in {sec-kem-combiner}.


## Component Algorithm Selection Criteria {#sec-selection-criteria}

The composite algorithm combinations defined in this document were chosen according to the following guidelines:

1. RSA combinations are provided at key sizes of 2048 and 3072 bits. Since RSA 2048 and 3072 are considered to have 112 and 128 bits of classical security respectively, they are both matched with NIST PQC Level 1 algorithms and 128-bit symmetric algorithms.
1. Elliptic curve algorithms are provided with combinations on each of the NIST [RFC6090], Brainpool [RFC5639], and Edwards [RFC7748] curves. NIST PQC Levels 1 - 3 algorithms are matched with 256-bit curves, while NIST levels 4 - 5 are matched with 384-bit elliptic curves. This provides a balance between matching classical security levels of post-quantum and traditional algorithms, and also selecting elliptic curves which already have wide adoption.
1. NIST level 1 candidates are provided, matched with 256-bit elliptic curves, intended for constrained use cases.

If other combinations are needed, a separate specification should be submitted to the IETF LAMPS working group.  To ease implementation, these specifications are encouraged to follow the construction pattern of the algorithms specified in this document.

The composite structures defined in this specification allow only for pairs of algorithms. This also does not preclude future specification from extending these structures to define combinations with three or more components.

<!-- End of Introduction section -->


# Composite Key Structures {#sec-composite-keys}

## pk-CompositeKEM

The following ASN.1 Information Object Class is a template to be used in defining all composite KEM public key types.

~~~ ASN.1
pk-CompositeKEM {
  OBJECT IDENTIFIER:id, FirstPublicKeyType,
  SecondPublicKeyType} PUBLIC-KEY ::=
  {
    IDENTIFIER id
    KEY SEQUENCE {
     BIT STRING (CONTAINING FirstPublicKeyType)
     BIT STRING (CONTAINING SecondPublicKeyType)
    }
    PARAMS ARE absent
    CERT-KEY-USAGE { keyEncipherment }
  }
~~~
{: artwork-name="CompositeKeyObject-asn.1-structures"}

As an example, the public key type `pk-MLKEM512-ECDH-P256` is defined as:

~~~
pk-MLKEM512-ECDH-P256 PUBLIC-KEY ::=
  pk-CompositeKEM {
    id-MLKEM512-ECDH-P256,
    OCTET STRING, ECPoint }
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


## CompositeKEMPublicKey {#sec-composite-pub-keys}

Composite public key data is represented by the following structure:

~~~ ASN.1
CompositeKEMPublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="CompositeKEMPublicKey-asn.1-structures"}


A composite key MUST contain two component public keys. The order of the component keys is determined by the definition of the corresponding algorithm identifier as defined in section {{sec-alg-ids}}.

Some applications may need to reconstruct the `SubjectPublicKeyInfo` objects corresponding to each component public key. {{tab-kem-algs}} in {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction. This also motivates the design choice of `SEQUENCE OF BIT STRING` instead of `SEQUENCE OF OCTET STRING`; using `BIT STRING` allows for easier transcription between CompositeKEMPublicKey and SubjectPublicKeyInfo.

When the CompositeKEMPublicKey must be provided in octet string or bit string format, the data structure is encoded as specified in {{sec-encoding-rules}}.


## CompositeKEMPrivateKey {#sec-priv-key}

Usecases that require an interoperable encoding for composite private keys, such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211] MUST use the following structure.

~~~ ASN.1
CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
~~~
{: artwork-name="CompositeKEMPrivateKey-asn.1-structures"}

Each element is a `OneAsymmetricKey`` [RFC5958] object for a component private key.

The parameters field MUST be absent.

The order of the component keys is the same as the order defined in {{sec-composite-pub-keys}} for the components of CompositeKEMPublicKey.

When a `CompositePrivateKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}}, the privateKey field SHALL contain the CompositeKEMPrivateKey, and the publicKey field MUST NOT be present. Associated public key material MAY be present in the CompositeKEMPrivateKey.

In some usecases the private keys that comprise a composite key may not be represented in a single structure or even be contained in a single cryptographic module; for example if one component is within the FIPS boundary of a cryptographic module and the other is not; see {sec-fips} for more discussion. The establishment of correspondence between public keys in a CompositeKEMPublicKey and private keys not represented in a single composite structure is beyond the scope of this document.


## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that the composite public key and composite private key data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

~~~ ASN.1
CompositeKEMPublicKeyOs ::= OCTET STRING (CONTAINING CompositeKEMPublicKey ENCODED BY der)
~~~

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

~~~ ASN.1
CompositeKEMPublicKeyBs ::= BIT STRING (CONTAINING CompositeKEMPublicKey ENCODED BY der)
~~~



# Composite KEM Structures

## kema-CompositeKEM {#sec-kema-CompositeKEM}

The ASN.1 algorithm object for a composite KEM is:

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

The compositeCipherTextValue is a concatenation of the ciphertexts of the
underlying component algorithms.  It is represented in ASN.1 as follows:

~~~
CompositeCiphertextValue ::= SEQUENCE SIZE (2) OF OCTET STRING
~~~

A composite KEM and `CompositeCipherTextValue` MAY be associated with a composite KEM public key, but MAY also be associated with multiple public keys from different sources, for example multiple X.509 certificates, or multiple cryptographic modules. In the latter case, composite KEMs MAY be used as the mechanism for carrying multiple ciphertexts, for example, in a non-composite hybrid encryption equivalent of those described for digital signatures in {{I-D.becker-guthrie-noncomposite-hybrid-auth}}.


## KEM Combiner {#sec-kem-combiner}

TODO: as per https://www.enisa.europa.eu/publications/post-quantum-cryptography-integration-study section 4.2, might need to specify behaviour in light of KEMs with a non-zero failure probility.

This document follows the construction of {{I-D.ounsworth-cfrg-kem-combiners}}, which is repeated here for clarity, however it has been simplified to take two imput shared secrets, and to take advantage of ML-KEM specific optimizations as per [X-Wing], and RSA-KEM specific optimizations since RSA-KEM is a bijective map between ciphertexts and plaintexts.

The general combiner defined in {{I-D.ounsworth-cfrg-kem-combiners}} is:

~~~
Combiner(ct1, ss1, ct2, ss2, fixedInfo) =
  KDF(counter || ct1 || ss1 || ct2 || ss2 || fixedInfo, outputBits)
~~~
{: #code-generic-kem-combiner title="Generic KEM combiner construction"}

where:

* `KDF(message, outputBits)` represents a hash function suitable to the chosen KEMs according to {tab-kem-combiners}.
* `fixedInfo` SHALL be the ASCII-encoded string name of the composite KEM algorithm as listed in {{tab-kem-algs}}.
* `counter` SHALL be the fixed 32-bit value `0x00000001` which is placed here soly for the purposes of easy compliance with [SP.800-56Cr2].
* `||` represents concatenation.

Each registered composite KEM algorithm must specify the choice of `KDF`, `fixedInfo`, and `outputBits` to be used.

See {{sec-cons-kem-combiner}} for further discussion of the security coniserations of this KEM combiner.

However, optimazations may be made in the following ways:

* As discussed in {{sec-cons-ct-collision}}, the ML-KEM ciphertext may be safely omited.
* As discussed in {{sec-cons-ct-collision}}, the RSA-KEM ciphertext may be safely omited.
* As the KDF we use everywhere SHA3-256 or SHA3-512.

That yields combiners of the form

~~~
SHA3-256(counter || ss1 || ct2 || ss2 || fixedInfo, outputBits)
~~~
{: #code-optimized-kem-combiner title="Optimized KEM combiner construction"}


For example, the KEM combiner used with the first entry of {{tab-kem-algs}}, `id-MLKEM512-ECDH-P256` would be:

~~~
SHA3-256( 0x00000001 || ss_mlkem || ct_ecdh-p256 || ss_ecdh-p256
            || "id-MLKEM512-ECDH-P256", "")
~~~


# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of composite KEM algorithms and lists the OID, two component algorithms, and the combiner function.

EDNOTE: The OID referenced are TBD and MUST be used only for prototyping and replaced with the final IANA-assigned OIDS. The following prefix is used for each: replace &lt;CompKEM&gt; with the String "2.16.840.1.114027.80.5.2".

TODO: OIDs to be replaced by IANA.

Therefore &lt;CompKEM&gt;.1 is equal to 2.16.840.1.114027.80.5.2.1

| KEM Type                          | OID                | First Algorithm | Second Algorithm     |
|---------                          | -----------------  | ----------      | ----------           |
| id-MLKEM512-ECDH-P256             | &lt;CompKEM&gt;.1  | MLKEM512        | ECDH-P256            |
| id-MLKEM512-ECDH-brainpoolP256r1  | &lt;CompKEM&gt;.2  | MLKEM512        | ECDH-brainpoolp256r1 |
| id-MLKEM512-X25519                | &lt;CompKEM&gt;.3  | MLKEM512        | X25519               |
| id-MLKEM512-RSA2048               | &lt;CompKEM&gt;.13 | MLKEM512        | RSA-KEM 2048         |
| id-MLKEM512-RSA3072               | &lt;CompKEM&gt;.4  | MLKEM512        | RSA-KEM 3072         |
| id-MLKEM768-ECDH-P256             | &lt;CompKEM&gt;.5  | MLKEM768        | ECDH-P256            |
| id-MLKEM768-ECDH-brainpoolP256r1  | &lt;CompKEM&gt;.6  | MLKEM768        | ECDH-brainpoolp256r1 |
| id-MLKEM768-X25519                | &lt;CompKEM&gt;.7  | MLKEM768        | X25519               |
| id-MLKEM1024-ECDH-P384            | &lt;CompKEM&gt;.8  | MLKEM1024       | ECDH-P384            |
| id-MLKEM1024-ECDH-brainpoolP384r1 | &lt;CompKEM&gt;.9  | MLKEM1024       | ECDH-brainpoolP384r1 |
| id-MLKEM1024-X448                 | &lt;CompKEM&gt;.10 | MLKEM1024       | X448                 |
{: #tab-kem-algs title="Composite KEM key types"}

EDNOTE: The original reason for using KMAC was that RSA, in general, allows for the attacker to choose the shared secret ss, but with RSA-KEM I think this is actually not the case since the final step of RSA-KEM is SS = KDF(Z), so SHA3 should be fine.

Full specifications for the referenced algorithms can be found as follows:

* _ECDH_: There does not appear to be a single IETF definition of ECDH, so we refer to the following:
  * _ECDH NIST_: SHALL be Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) as defined in section 5.7.1.2 of [SP.800-56Ar3].
  * _ECDH BSI / brainpool_: SHALL be Elliptic Curve Key Agreement algorithm (ECKA) as defined in section 4.3.1 of [BSI-ECC]
* _ML-KEM_: {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203-ipd]
* _RSA-KEM_: {{I-D.ietf-lamps-rfc5990bis}}
* _X25519 / X448_: [RFC8410]

EDNOTE: I believe that [SP.800-56Ar3] and [BSI-ECC] give equivalent and interoperable algorithms, so maybe this is extranuous detail to include?

The KEM combiners for each algorithm are instantiated as follows


| KEM Type                          | KDF          | KDF Input X            |
|---------                          | ----------   | -------------          |
| id-MLKEM512-ECDH-P256             | SHA3-256     | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM512-ECDH-brainpoolP256r1  | SHA3-256     | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM512-X25519                | SHA3-256     | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM512-RSA2048               | SHA3-256     | ss1 \|\| ss2           |
| id-MLKEM512-RSA3072               | SHA3-256     | ss1 \|\| ss2           |
| id-MLKEM768-ECDH-P256             | SHA3-512/384 | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM768-ECDH-brainpoolP256r1  | SHA3-512/384 | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM768-X25519                | SHA3-512/384 | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM1024-ECDH-P384            | SHA3-512     | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM1024-ECDH-brainpoolP384r1 | SHA3-512     | ss1 \|\| ss2 \|\| ct2  |
| id-MLKEM1024-X448                 | SHA3-512     | ss1 \|\| ss2 \|\| ct2  |
{: #tab-kem-combiner-instantiations title="KEM Combiner Instattiations"}

Note that since ML-KEM-768 only claims security equivalent to a 384-bit hash function, the output of SHA3-512 is truncated to 384 bits to not give a false sense of security to developers using this value.

The tables above contains everything needed to implement the listed explicit composite algorithms, with the exception of some special notes found below in this section. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.



## RSA-KEM Parameters

Use of RSA-KEM {{I-D.ietf-lamps-rfc5990bis}} within `id-MLKEM512-RSA2048` and `id-MLKEM512-RSA3072` requires additional specification.

The RSA component keys MUST be generated at the 2048-bit and 3072-bit security level respectively.

As with the other composite KEM algorithms, when `id-MLKEM512-RSA2048` or `id-MLKEM512-RSA3072` is used in an AlgorithmIdentifier, the parameters MUST be absent. The RSA-KEM SHALL be instantiated with the following parameters:

| RSA-KEM Parameter          | Value                      |
| -------------------------- | -------------------------- |
| keyDerivationFunction      | kda-kdf3 with id-sha3-256  |
| keyLength                  | 128                        |
{: #rsa-kem-params2048 title="RSA-KEM 2048 Parameters"}

where:

* `kda-kdf3` is defined in {{I-D.ietf-lamps-rfc5990bis}} which references it from [ANS-X9.44].
* `mda-shake256` is defined in {{I-D.housley-lamps-cms-sha3-hash}}.


# ASN.1 Module {#sec-asn1-module}

~~~ ASN.1

<CODE STARTS>

{::include Composite-KEM-2023.asn}

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

- id-MLKEM512-ECDH-P256
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-ECDH-P256
  - References: This Document

- id-MLKEM512-ECDH-brainpoolP256r1
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-ECDH-brainpoolP256r1
  - References: This Document

- id-MLKEM512-X25519
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-X25519
  - References: This Document

- id-MLKEM768-RSA3072
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-3072
  - References: This Document

- id-MLKEM768-ECDH-P256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P256
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

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), it is obvious that the public keys or certificates using that algorithm are to be considered revoked.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled indpendently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLKEM512-ECDH-P256` even after ECDH-P256 is deprecated.

The composite KEM design specified in this document, and especially that of the KEM combiner specified in {{sec-kem-combiner}} means that the overall composite KEM algorithm should be considered to have the security strength of the strongest of its component algorithms; ie as long as one component algorithm remains strong, then the overall composite algorithm remains strong.


## KEM Combiner {#sec-cons-kem-combiner}

This document uses directly the KEM Combiner defined in {{I-D.ounsworth-cfrg-kem-combiners}} and therefore IND-CCA2 of any of its ingredient KEMs, i.e. the newly formed combined KEM is IND-CCA2 secure as long as at least one of the ingredient KEMs is

{{I-D.ounsworth-cfrg-kem-combiners}} provides two different constructions depending on the properties of the component KEMs:

> If both the secret share `ss_i` and the ciphertext `ct_i` are constant length, then k_i MAY be constructed concatenating the two values.
> If `ss_i` or `ct_i` are not guaranteed to have constant length, it is REQUIRED to append the rlen encoded length when concatenating, prior to inclusion in the overall construction.

The component KEMs used in this specification are RSA-KEM {{I-D.ietf-lamps-rfc5990bis}}, ECDH, X25519, X448, and ML-KEM {{FIPS.203-ipd}} all of which meet the criteria of having constant-length shared secrets and ciphertexts and therefore we justify using the simpler construction that omits the length tag.

### Ciphertext collision resistance {#sec-cons-ct-collision}

The notion of a ciphertext cellision resistant KEM is defined in [X-Wing] being the property that it is computationally difficult to find two different ciphertexts that will decapsulate to the same shared secret under the same public key. In [X-Wing] it is proven that ML-KEM has this property and therefore the ML-KEM ciphertext can safely be omitted from the KEM combiner. Similarly, RSA-KEM {{I-D.ietf-lamps-rfc5990bis}} is a bijective map between the shared secret `Z` and the ciphertext `C` and so is naturally immune to ciphertext collision. This leaves only ECDH, X25519 and X448 which are not ciphertext collision resistant and for which the ciphertexts need to be included in the derivation of the shared secret.


<!-- End of Security Considerations section -->

--- back

# Samples {#appdx-samples}

TBD


# Implementation Considerations {#sec-in-pract}

## FIPS certification {#sec-fips}

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not. The combiner presented in {{sec-kem-combiner}} was chosen to align with [SP.800-56Cr2] for this reason.

Implementors seeking FIPS certification of a composite KEM algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorith with zero security, and the overall composite should be considered full strength and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions; for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.

## Backwards Compatibility {#sec-backwards-compat}

As noted in the introduction, the post-quantum cryptographic migration will face challenges in both ensuring cryptographic strength against adversaries of unknown capabilities, as well as providing ease of migration. The composite mechanisms defined in this document primarily address cryptographic strength, however this section contains notes on how backwards compatibility may be obtained.

The term "ease of migration" is used here to mean that existing systems can be gracefully transitioned to the new technology without requiring large service disruptions or expensive upgrades. The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.

These migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to key establishment and content encryption, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] encrypted structures.


### Parallel PKIs

EDNOTE: remove this section?

We present the term "Parallel PKI" to refer to the setup where a PKI end entity possesses two or more distinct public keys or certificates for the same identity (name), but containing keys for different cryptographic algorithms. One could imagine a set of parallel PKIs where an existing PKI using legacy algorithms (RSA, ECC) is left operational during the post-quantum migration but is shadowed by one or more parallel PKIs using pure post quantum algorithms or composite algorithms (legacy and post-quantum).

Equipped with a set of parallel public keys in this way, a client would have the flexibility to choose which public key(s) or certificate(s) to use in a given signature operation.

For negotiated protocols, the client could choose which public key(s) or certificate(s) to use based on the negotiated algorithms.

For non-negotiated protocols, the details for obtaining backwards compatibility will vary by protocol, but for example in CMS [RFC5652].

EDNOTE: I copied and pruned this text from I-D.ounsworth-pq-composite-sigs. It probably needs to be fleshed out more as we better understand the implementation concerns around composite encryption.

<!-- End of Implementation Considerations section -->


# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/

EDNOTE TODO: Check with Max Pala whether this IPR actually applies to this draft.



# Contributors and Acknowledgements

This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust), Ali Noman (Entrust), Scott Fluhrer (Cisco), Jan Klaußner (D-Trust), Max Pala (CableLabs), and
Douglas Stebila (University of Waterloo).

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].


<!-- End of Contributors section -->
