---
title: Composite KEM For Use In Internet PKI
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
  RFC5990:
  # RFC8017: # RSA v2.2
  RFC8174:
  RFC8410:
  RFC8411:
  RFC8692:
  I-D.draft-housley-lamps-cms-kemri-02:
  I-D.draft-ietf-lamps-rfc5990bis-01:
  I-D.draft-ounsworth-lamps-cms-dhkem-00:
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


--- abstract

This document defines Post-Quantum / Traditional composite Key Encapsulation Mechanism (KEM) algorithms suitable for use within X.509 and PKIX and CMS protocols. Composite algorithms are provided which combine ML-KEM with RSA-KEM and ECDH-KEM. The provided set of composite algorithms should meet most Internet needs.

This document assumes that all component algorithms are KEMs, and therefore it depends on [RFC5990] and {{I-D.ounsworth-lamps-cms-dhkem}} in order to promote RSA and ECDH respectively into KEMs. For the purpose of combining KEMs, the combiner function from {{I-D.ounsworth-cfrg-kem-combiners}} is used. For use within CMS, this document is intended to be coupled with the CMS KEMRecipientInfo mechanism in {{I-D.housley-lamps-cms-kemri}}.

<!-- End of Abstract -->


--- middle

# Changes in version -01

Changes affecting interoperability:

* Re-worked wire format and ASN.1 to remove vestiges of Generics.
  * Changed all `SEQUENCE OF SIZE (2..MAX)` to `SEQUENCE OF SIZE (2)`.
  * Changed the definition of `CompositeKEMPublicKey` from `SEQUENCE OF SubjectPublicKeyInfo` to `SEQUENCE OF BIT STRING` since with complete removal of Generic Composites, there is no longer any need to carry the component AlgorithmIdentifiers.
  * Added a paragraph describing how to reconstitute component SPKIs.
* Defined `KeyGen()`, `Encaps()`, and `Decaps()` for a composite KEM algorithm.
* Removed the discussion of KeyTrans -> KEM and KeyAgree -> KEM promotions, and instead simply referenced {{I-D.ietf-lamps-rfc5990bis}} and {{I-D.ounsworth-lamps-cms-dhkem}}.
* Made RSA keys fixed-length at 3072.
* Re-worked section 4.1 (id-MLKEM768-RSA3072-KMAC256) to Reference 5990bis and its updated structures.
* Removed RSA-KEM KDF params and make them implied by the OID; ie provide a profile of 5990bis.
* Aligned combiner with draft-ounsworth-cfrg-kem-combiners-04.

Editorial changes:

* Refactored to use MartinThomson github template.
* Made this document standalone by folding in the minimum necessary content from composite-keys and dropping the cross-reference to composite-sigs.
* Added an Implementation Consideration about FIPS validation where only one component algorithm is FIPS-approved.
* Shortened the abstract (moved some content into Intro).
* Brushed up the Security Considerations.
* Made a proper IANA Considerations section.
* Rename "Kyber" to "ML-KEM".

TODO:

  `[ ]` Get Russ' approval that I've used RFC5990bis correctly. Email sent. Waiting for a reply.

  `[ ]` Top-to-bottom read, especially looking for redundancies or references to signatures from merging in the more generic Keys content.

  Still to do in a future version:

  * I need an ASN.1 expert to help me fix how it references ECC named curves.
  * We need PEM samples … 118 hackathon? OQS friends? David @ BC?


# Introduction {#sec-intro}


The migration to post-quantum cryptography is unique in the history of modern digital cryptography in that neither the old outgoing nor the new incoming algorithms are fully trusted to protect data for the required data lifetimes. The outgoing algorithms, such as RSA and elliptic curve, may fall to quantum cryptalanysis, while the incoming post-quantum algorithms face uncertainty about both the underlying mathematics as well as hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear.

Cautious implementers may wish to combine cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected by using a Post-Quantum / Traditional Hybrid. This document defines a specific instantiation of hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key encapsulation mechanism (KEM) key and ciphertext such that they can be treated as a single atomic algorithm at the protocol level.

The deployment of composite public keys and composite encryption using post-quantum algorithms will face two challenges


- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.

This document provides a mechanism to address algorithm strength uncertainty by providing the format and procedures for combining multiple KEM algorithms into a single composite KEM algorithm. Concrete instantiations are provided based on ML-KEM, RSA-KEM and ECDH-KEM Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.


This document is intended for general applicability anywhere that key establishment or enveloped content encryption is used within PKIX or CMS structures.


## Terminology {#sec-terminology}
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This document is consistent with all terminology from {{I-D.driscoll-pqt-hybrid-terminology}}.
In addition, the following terms are used in this document:

**BER:**
  Basic Encoding Rules (BER) as defined in [X.690].

**CLIENT:**
  Any software that is making use of a cryptographic key.
  This includes a signer, verifier, encrypter, decrypter.

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


## Algorithm Selection Criteria {#sec-selection-criteria}

The composite algorithm combinations defined in this document were chosen according to the following guidelines:

1. A single RSA combination is provided at a key size of 3072 bits, matched with NIST PQC Level 3 algorithms.
1. Elliptic curve algorithms are provided with combinations on each of the NIST [RFC6090], Brainpool [RFC5639], and Edwards [RFC7748] curves. NIST PQC Levels 1 - 3 algorithms are matched with 256-bit curves, while NIST levels 4 - 5 are matched with 384-bit elliptic curves. This provides a balance between matching classical security levels of post-quantum and traditional algorithms, and also selecting elliptic curves which already have wide adoption.
1. NIST level 1 candidates are provided, matched with 256-bit elliptic curves, intended for constrained use cases.

If other combinations are needed, a separate specification should be submitted to the IETF LAMPS working group.  To ease implementation, these specifications are encouraged to follow the construction pattern of the algorithms specified in this document.

The composite structures defined in this specification allow only for pairs of algorithms. This also does not preclude future specification from extending these structures to define combinations with three or more components.

<!-- End of Introduction section -->


# Composite Key Structures {#sec-composite-keys}

{{I-D.driscoll-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys as defined here follow this definition and should be regarded as a single key that performs a single cryptographic operation such key generation, signing, verifying, encapsulating, or decapsulating -- using its encapsulated sequence of component keys as if it was a single key. This generally means that the complexity of combining algorithms can and should be ignored by application and protocol layers and deferred to the cryptographic library layer.

In order to represent public keys and private keys that are composed of multiple algorithms, we define encodings consisting of a sequence of public key or private key primitives (aka "components") such that these structures can be used directly in existing public key and private fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914].


## pk-explicitCompositeKEM

The following ASN.1 Information Object Class is a template to be used in defining all composite KEM public key types.

~~~ ASN.1
pk-explicitCompositeKEM{OBJECT IDENTIFIER:id,
  PUBLIC-KEY:firstPublicKey, FirstPublicKeyType,
  PUBLIC-KEY:secondPublicKey, SecondPublicKeyType} PUBLIC-KEY ::= {
  IDENTIFIER id
  KEY ExplicitCompositePublicKey{firstPublicKey, FirstPublicKeyType,
      secondPublicKey, SecondPublicKeyType}
  PARAMS ARE absent
  CERT-KEY-USAGE { keyEncipherment }
}
~~~
{: artwork-name="CompositeKeyObject-asn.1-structures"}

As an example, the public key type `pk-MLKEM512-ECDH-P256-KMAC128` is defined as:

~~~
pk-MLKEM512-ECDH-P256-KMAC128 PUBLIC-KEY ::=
  pk-explicitCompositeKEM{id-MLKEM512-ECDH-P256-KMAC128,
  pk-MLKEM512TBD, OCTET STRING, pk-ec, ECPoint}
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


## CompositePublicKey {#sec-composite-pub-keys}

Composite public key data is represented by the following structure:

~~~ ASN.1
CompositePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="CompositePublicKey-asn.1-structures"}


A composite key MUST contain two component public keys. The order of the component keys is determined by the definition of the corresponding algorithm identifier as defined in section {{sec-alg-ids}}.

Some applications may need to reconstruct the `SubjectPublicKeyInfo` objects corresponding to each component public key. {{tab-kem-algs}} in {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

When the CompositePublicKey must be provided in octet string or bit string format, the data structure is encoded as specified in {{sec-encoding-rules}}.


## CompositePrivateKey {#sec-priv-key}

This section provides an encoding for composite private keys intended for PKIX protocols and other applications that require an interoperable format for transmitting private keys, such as PKCS #12 [RFC7292] or CMP / CRMF [RFC4210], [RFC4211]. It is not intended to dictate a storage format in implementations not requiring interoperability of private key formats.

In some cases the private keys that comprise a composite key may not be represented in a single structure or even be contained in a single cryptographic module; for example if one component is within the FIPS boundary of a cryptographic module and the other is not; see {sec-fips} for more discussion. The establishment of correspondence between public keys in a CompositePublicKey and private keys not represented in a single composite structure is beyond the scope of this document.


Usecases that require an interoperable encodingn for composite private keys MUST use the following structure.

~~~ ASN.1
CompositePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
~~~
{: artwork-name="CompositePrivateKey-asn.1-structures"}

Each element is a `OneAsymmetricKey`` [RFC5958] object for a component private key.

The parameters field MUST be absent.

The order of the component keys is the same as the order defined in {{sec-composite-pub-keys}} for the components of CompositePublicKey.

When a `CompositeProviteKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}}, the privateKey field SHALL contain the CompositePrivateKey, and the publicKey field MUST NOT be present. Associated public key material MAY be present in the CompositePrivateKey.


## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that the composite public key and composite private key data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

~~~ ASN.1
CompositePublicKeyOs ::= OCTET STRING (CONTAINING CompositePublicKey ENCODED BY der)
~~~

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

~~~ ASN.1
CompositePublicKeyBs ::= BIT STRING (CONTAINING CompositePublicKey ENCODED BY der)
~~~



# Composite KEM Structures

## Key Encapsulation Mechanisms (KEMs) {#sec-kems}

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

The KEM interface was chosen as the interface for a composite key exchange because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs. This specification uses the Post-Quantum KEM ML-KEM as specified in {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203-ipd]. For Traditional KEMs, this document relies on the RSA-KEM construction defined in {{I-D.ietf-lamps-rfc5990bis}} and the Elliptic Curve DHKEM defined in {{I-D.ounsworth-lamps-cms-dhkem}}.

A composite KEM allows two or more underlying key transport, key agreement, or KEM algorithms to be combined into a single cryptographic operation by performing each operation, transformed to a KEM as outline above, and using a specified combiner function to combine the two or more component shared secrets into a single shared secret.


### Composite KeyGen

The `KeyGen() -> (pk, sk)` of a composite KEM algorithm will perform the `KeyGen()` of the respective component KEM algorithms and it produces a composite public key `pk` as per {sec-composite-pub-keys} and a composite secret key `sk` is per {sec-priv-key}.

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
  ss = Combiner(ss1, ss2, algName)

  return (ct, ss)
~~~
{: #alg-composite-encaps title="Composite Encaps(pk)"}

where `Combiner(k1, k2)` is defined in {sec-kem-combiner} and `CompositeCiphertextValue` is defined in {sec-CompositeCiphertextValue}.

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
  ss = Combiner(ss1, ss2, algName)

  return ss
~~~
{: #alg-composite-decaps title="Composite Decaps(sk, ct)"}

where `Combiner(k1, k2, fixedInfo)` is defined in {sec-kem-combiner}.


## kema-CompositeKEM {#sec-kema-CompositeKEM}

The ASN.1 algorithm object for a composite KEM is:

~~~
kema-CompositeKEM KEM-ALGORITHM ::= {
    IDENTIFIER TYPE OBJECT IDENTIFIER
    VALUE CompositeCiphertextValue
    PARAMS TYPE CompositeKemParams ARE required
    PUBLIC-KEYS { pk-Composite }
    SMIME-CAPS { IDENTIFIED BY id-alg-composite } }
~~~


The following is an explanation how KEM-ALGORITHM elements are used
to create Composite KEMs:

| SIGNATURE-ALGORITHM element | Definition |
| ---------                   | ---------- |
| IDENTIFIER                  | The Object ID used to identify the composite Signature Algorithm |
| VALUE                       | The Sequence of BIT STRINGS for each component signature value |
| PARAMS                      | Parameters of type CompositeKemParams may be provided when required |
| PUBLIC-KEYS                 | The composite key required to produce the composite signature |
| SMIME_CAPS                  | Not needed for composite |



## CompositeCiphertextValue {#sec-CompositeCiphertextValue}

The compositeCipherTextValue is a concatenation of the ciphertexts of the
underlying component algorithms.  It is represented in ASN.1 as follows:

~~~
CompositeCiphertextValue ::= SEQUENCE SIZE (2) OF OCTET STRING
~~~

A composite KEM and `CompositeCipherTextValue` MAY be associated with a composite KEM public key, but MAY also be associated with multiple public keys from different sources, for example multiple X.509 certificates, or multiple cryptographic modules. In the latter case, composite KEMs MAY be used as the mechanism for carrying multiple ciphertexts, for example, in a non-composite hybrid encryption equivalent of those described for digital signatures in {{I-D.becker-guthrie-noncomposite-hybrid-auth}}.


## CompositeKemParameters {#sec-compositeKemParameters}

Composite KEM parameters are defined as follows and MAY be included when a composite KEM algorithm is used with an AlgorithmIdentifier:

~~~ asn.1
CompositeKemParams ::= SEQUENCE SIZE (2) OF AlgorithmIdentifier{
    KEM-ALGORITHM, {KEMAlgSet} }
~~~

The KEM's `CompositeKemParams` sequence MUST contain the same component algorithms listed in the same order as in the associated CompositePublicKey.

For explicit composite algorithms, it is required in cases where one or both of the components themselves have parameters that need to be carried, however the authors have chosen to always carry it in order to simplify parsers. Implementation SHOULD NOT rely directly on the algorithmIDs contained in the `CompositeKemParams` and SHOULD verify that they match the algorithms expected from the overall composite AlgorithmIdentifier.


## KEM Combiner {#sec-kem-combiner}

TODO: as per https://www.enisa.europa.eu/publications/post-quantum-cryptography-integration-study section 4.2, might need to specify behaviour in light of KEMs with a non-zero failure probility.

This document follows the construction of {{I-D.ounsworth-cfrg-kem-combiners}}, which is repeated here for clarity and simplified to take two imput shared secrets:

~~~
Combiner(ss1, ss2, fixedInfo) = KDF(counter || ss1 || ss2 || fixedInfo,
                                      outputBits)
~~~
{: #code-generic-kem-combiner title="Generic KEM combiner construction"}

where:

* `KDF(message, outputBits)` represents a hash function suitable to the chosen KEMs according to {tab-kem-combiners}.
* `fixedInfo` SHALL be the ASCII-encoded string name of the composite KEM algorithm as listed in {{tab-kem-algs}}.
* `counter` SHALL be the fixed 32-bit value `0x00000001` which is placed here soly for the purposes of easy compliance with [SP.800-56Cr2].
* `||` represents concatenation.

Each registered composite KEM algorithm must specify the exact KEM combiner construction that is to be used.


This specification uses the following KMAC-based instantiations of the generic KEM combiner:

| KEM Combiner Name | KDF     | outputBits |
| ---               | ------- |---         |
| KMAC128/256       | KMAC128 | 256 |
| KMAC256/384       | KMAC256 | 384 |
| KMAC256/512       | KMAC256 | 512 |
{: #tab-kem-combiners title="KEM Combiners"}

KMAC is defined in NIST SP 800-185 [SP800-185]. The `KMAC(K, X, L, S)` parameters are instantiated as follows:

* `K`: the ASCI value of the name of the Kem Type OID.
* `X`: the message input to `KDF()`, as defined above.
* `L`: integer representation of `outputBits`.
* `S`: empty string.

BEGIN EDNOTE

these choices are somewhat arbitrary but aiming to match security level of the input KEMs. Feedback welcome.

* ML-KEM-512: KMAC128/256
* ML-KEM-768: KMAC256/384
* ML-KEM-1024 KMAC256/512

END EDNOTE


For example, the KEM combiner used with the first entry of {{tab-kem-algs}}, `id-MLKEM512-ECDH-P256-KMAC128` would be:

~~~
Combiner(ss1, ss2, "id-MLKEM512-ECDH-P256-KMAC128") =
           KMAC128( 0x00000001 || ss_1 || ss_2 ||
              "id-MLKEM512-ECDH-P256-KMAC128", 256, "")
~~~


# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of explicit composite Signature algorithms by the key and signature OID and the two component algorithms which make up the explicit composite algorithm.  These are denoted by First Signature Alg, and Second Signature Alg.

EDNOTE: The OID referenced are TBD and MUST be used only for prototyping and replaced with the final IANA-assigned OIDS. The following prefix is used for each: replace &lt;CompKEM&gt; with the String "2.16.840.1.114027.80.5.2".

TODO: OIDs to be replaced by IANA.

Therefore &lt;CompKEM&gt;.1 is equal to 2.16.840.1.114027.80.5.2.1

The "KEM Combiner" column refers to the definitions in {{sec-kem-combiner}}.

| KEM Type OID                              | OID                | First Algorithm | Second Algorithm |  KEM Combiner     |
|---------                                  | -----------------  | ----------      | ----------     | ----------    |
| id-MLKEM512-ECDH-P256-KMAC128             | &lt;CompKEM&gt;.1  | MLKEM512        | ECDH-P256      | KMAC128/256  |
| id-MLKEM512-ECDH-brainpoolP256r1-KMAC128  | &lt;CompKEM&gt;.2  | MLKEM512        | ECDH-brainpoolp256r1 | KMAC128/256 |
| id-MLKEM512-X25519-KMAC128                | &lt;CompKEM&gt;.3  | MLKEM512        | X25519         | KMAC128/256 |
| id-MLKEM768-RSA3072-KMAC256               | &lt;CompKEM&gt;.4  | MLKEM768        | RSA-KEM 3072   | KMAC256/384 |
| id-MLKEM768-ECDH-P256-KMAC256             | &lt;CompKEM&gt;.5  | MLKEM768        | ECDH-P256      | KMAC256/384 |
| id-MLKEM768-ECDH-brainpoolP256r1-KMAC256  | &lt;CompKEM&gt;.6  | MLKEM768        | ECDH-brainpoolp256r1 | KMAC256/384 |
| id-MLKEM768-X25519-KMAC256                | &lt;CompKEM&gt;.7  | MLKEM768        | X25519         | KMAC256/384 |
| id-MLKEM1024-ECDH-P384-KMAC256            | &lt;CompKEM&gt;.8  | MLKEM1024       | ECDH-P384     | KMAC256/512 |
| id-MLKEM1024-ECDH-brainpoolP384r1-KMAC256 | &lt;CompKEM&gt;.9  | MLKEM1024       | ECDH-brainpoolP384r1 | KMAC256/512 |
| id-MLKEM1024-X448-KMAC256                 | &lt;CompKEM&gt;.10 | MLKEM1024       | X448          | KMAC256/512 |
{: #tab-kem-algs title="Composite KEM key types"}


The table above contains everything needed to implement the listed explicit composite algorithms, with the exception of some special notes found below in this section. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.

Full specifications for the referenced algorithms can be found as follows:

* _ECDH_: There does not appear to be a single IETF definition of ECDH, so we refer to the following:
  * _ECDH NIST_: SHALL be Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) as defined in section 5.7.1.2 of [SP.800-56Ar3].
  * _ECDH BSI / brainpool_: SHALL be Elliptic Curve Key Agreement algorithm (ECKA) as defined in section 4.3.1 of [BSI-ECC]
* _ML-KEM_: {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203-ipd]
* _RSA-KEM_: {{I-D.ietf-lamps-rfc5990bis}}
* _X25519 / X448_: [RFC8410]

Note that all ECDH as well as X25519 and X448 algorithms MUST be prometed into KEMs according to {{I-D.ounsworth-lamps-cms-dhkem}}.

EDNOTE: I believe that [SP.800-56Ar3] and [BSI-ECC] give equivalent and interoperable algorithms, so maybe this is extranuous detail to include?



## id-MLKEM768-RSA3072-KMAC256 Parameters

Use of RSA-KEM {{I-D.ietf-lamps-rfc5990bis}} requires additional specification.

The RSA component keys MUST be generated at the 3072-bit security level in order to match security level with ML-KEM-768. Parsers SHOULD be flexible since RSA keys generated at the 3072-bit security level may not be exactly 3072 bits in length due to dropped leading zeros.

As with the other composite KEM algorithms, when `id-MLKEM768-RSA3072-KMAC256` is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLKEM768-RSA3072-KMAC256` SHALL instantiate RSA-KEM with the following parameters:

| RSA-KEM Parameter          | Value                      |
| -------------------------- | -------------------------- |
| keyDerivationFunction      | kda-kdf3 with mda-shake256 |
| keyLength                  | 256                        |
| DataEncapsulationMechanism | kwa-aes256-wrap            |
{: #rsa-kem-params title="RSA-KEM Parameters"}

where:
* `kda-kdf3` is defined in {{I-D.ietf-lamps-rfc5990bis}} which references it from [ANS-X9.44].
* `kwa-aes256-wrap` is defined in {{I-D.ietf-lamps-rfc5990bis}}
* `mda-shake256` is defined in [RFC8692].



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

- id-MLKEM512-ECDH-P256-KMAC128
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-ECDH-P256-KMAC128
  - References: This Document

- id-MLKEM512-ECDH-brainpoolP256r1-KMAC128
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-ECDH-brainpoolP256r1-KMAC128
  - References: This Document

- id-MLKEM512-X25519-KMAC128
  - Decimal: IANA Assigned
  - Description: id-MLKEM512-X25519-KMAC128
  - References: This Document

- id-MLKEM768-RSA3072-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-3072-KMAC256
  - References: This Document

- id-MLKEM768-ECDH-P256-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-P256-KMAC256
  - References: This Document

- id-MLKEM768-ECDH-brainpoolP256r1-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-ECDH-brainpoolP256r1-KMAC256
  - References: This Document

- id-MLKEM768-X25519-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM768-X25519-KMAC256
  - References: This Document

- id-MLKEM1024-ECDH-P384-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-P384-KMAC256
  - References: This Document

- id-MLKEM1024-ECDH-brainpoolP384r1-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-ECDH-brainpoolP384r1-KMAC256
  - References: This Document

- id-MLKEM1024-X448-KMAC256
  - Decimal: IANA Assigned
  - Description: id-MLKEM1024-X448-KMAC256
  - References: This Document

<!-- End of IANA Considerations section -->


# Security Considerations

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), it is obvious that the public keys or certificates using that algorithm are to be considered revoked.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled indpendently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLKEM512-ECDH-P256-KMAC128` even after ECDH-P256 is deprecated.

The composite KEM design specified in this document, and especially that of the KEM combiner specified in {{sec-kem-combiner}} means that the overall composite KEM algorithm should be considered to have the security strength of the strongest of its component algorithms; ie as long as one component algorithm remains strong, then the overall composite algorithm remains strong.


## KEM Combiner

This document uses directly the KEM Combiner defined in {{I-D.ounsworth-cfrg-kem-combiners}} and therefore inherits all of its security considerations, which the authors believe have all been addressed by the concrete instantiations of KEM algorithms and combiner parameters specified in this document.

<!-- End of Security Considerations section -->

--- back

# Samples {#appdx-samples}

TBD


# Implementation Considerations {#sec-in-pract}

## FIPS certification {#sec-fips}

One of the primary design goals of the specification is for the overall composite algorithm to be able to considered FIPS-approved even when one of the component algorithms is not. The combiner presented in {{sec-kem-combiner}} was chosen to align with [SP.800-56Cr2] for this reason.

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

EDNOTE:   I don't think this applies to this draft.



# Contributors and Acknowledgements

This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust), Ali Noman (Entrust), Scott Fluhrer (Cisco), Jan Klaußner (D-Trust), Max Pala (CableLabs), and
Douglas Stebila (University of Waterloo).

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/EntrustCorporation/draft-composite-kem/


<!-- End of Contributors section -->
