---
title: Composite ML-KEM for Use in the Internet X.509 Public Key Infrastructure and CMS
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
  latest: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html#name-asn1-module

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
  RFC3394:
  RFC4055:
  RFC5280:
  RFC5652:
  RFC5869:
  RFC5958:
  RFC8017:
  RFC8174:
  RFC8410:
  RFC8411:
  RFC9629:
  I-D.draft-ietf-lamps-cms-sha3-hash-04:
  # ANS-X9.44:
  #   title: "Public Key
  #             Cryptography for the Financial Services Industry -- Key
  #             Establishment Using Integer Factorization Cryptography"
  #   author:
  #     org: "American National Standards Institute"
  #   date: 2007
  #   seriesinfo: American National Standard X9.44
  # SP800-185:
  #   title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash"
  #   author:
  #     org: "National Institute of Standards and Technology (NIST)"
  #   date: December 2016
  #   target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
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
  RFC7748:
  RFC8446:
  RFC8551:
  RFC9180:
  I-D.draft-ietf-tls-hybrid-design-04:
  I-D.draft-driscoll-pqt-hybrid-terminology-01:
  I-D.draft-ietf-lamps-kyber-certificates-01:
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

This document introduces a set of Key Encapsulation Mechanism (KEM) schemes that use pairs of cryptographic elements such as public keys and cipher texts to combine their security properties. These schemes effectively mitigate risks associated with the adoption of post-quantum cryptography and are fully compatible with existing X.509, PKIX, and CMS data structures and protocols. This document defines eleven specific pairwise combinations, namely ML-KEM Composite Schemes, that blend ML-KEM with traditional algorithms such as RSA-OAEP, ECDH, X25519, and X448. For use within CMS, this document is intended to be coupled with the CMS KEMRecipientInfo mechanism in {{I-D.housley-lamps-cms-kemri}}. These combinations are tailored to meet security best practices and regulatory requirements.

<!-- End of Abstract -->


--- middle

# Changes in version -05

* Fixed a bug in the definition of the Encap() functions: KEMs, according to both RFC9180 and FIPS 203 should always return (ss, ct), but we had (ct, ss).
* Adjusted RSA-OAEP section to follow RFC8017 instead of RFC3560. Does not use the RSA-OAEP label.
* Aligning algorithm list with LAMPS WG on-list discussions and draft-openpgp-pqc
  * ML-KEM-768 aligned with P-384 as per Quynh's OpenPGP presentation: https://datatracker.ietf.org/meeting/120/materials/slides-120-openpgp-pqc-with-nist-and-brainpool-curves
  * Removing ML-KEM-512 combinations as per Sophie's recommendation: https://mailarchive.ietf.org/arch/msg/spasm/khasPf3y0_-Lq_0NtJe92unUw6o/
* Specified some options to use HKDF-SHA2, and some to use SHA3 to facilitate implementations that do not have easy access to SHA3 outside the ML-KEM module.
* Tweaks to combiner function, thanks to Quynh and authors of draft-ietf-openpgp-PQC:
  * Removed the `counter`.
  * Un-twisted `tradSS || mlkemSS` to `mlkemSS || tradSS` as you would expect (thanks Quynh for pointing that this is allowed.)
* Enhanced the section about how to get this FIPS-certified.
* Updated OIDs and domain separators.
* ASN.1 module fixes (thanks Russ).


Still to do in a future version:

 - `[ ]` We need PEM samples … hackathon? OQS friends? David @ BC? The right format for samples is probably to follow the hackathon ... a Dilithium or ECDSA trust anchor certificate, a composite KEM end entity certificate, and a CMS EnvelopedData sample encrypted for that composite KEM certificate.
 - `[ ]` Open question: do we need to include the ECDH, X25519, X448, and RSA public keys in the KDF? X-Wing does, but previous versions of this spec do not. In general existing ECC and RSA hardware decrypter implementations might not know their own public key.


# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA-OAEP, ECDH and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.driscoll-pqt-hybrid-terminology}}.

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

This document defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key encapsulation mechanism (KEM) key and ciphertext such that they can be treated as a single atomic algorithm at the protocol level. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite KEM algorithms are provided based on ML-KEM, RSA-OAEP and ECDH. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.

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
  secrets established via public key cryptographic operations.

## Composite Design Philosophy

{{I-D.driscoll-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys, as defined here, follow this definition and should be regarded as a single key that performs a single cryptographic operation such as key generation, signing, verifying, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, and ciphertext can be carried in existing fields in protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts KEM algorithms without requiring any modification of the protocol to handle multiple keys.


## Composite Key Encapsulation Mechanisms (KEMs) {#sec-kems}

We borrow here the definition of a key encapsulation mechanism (KEM) from {{I-D.ietf-tls-hybrid-design}}, in which a KEM is a cryptographic primitive that consists of three algorithms:

   *  `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
      which generates a public key `pk` and a secret key `sk`.

   *  `Encap(pk) -> (ss, ct)`: A probabilistic encapsulation algorithm,
      which takes as input a public key `pk` and outputs a ciphertext `ct`
      and shared secret ss. Note: this document uses `Encap()` to conform to [RFC9180],
      but [FIPS.204] uses `Encaps()`.

   *  `Decap(sk, ct) -> ss`: A decapsulation algorithm, which takes as
      input a secret key `sk` and ciphertext `ct` and outputs a shared
      secret `ss`, or in some cases a distinguished error value.
      Note: this document uses `Decap()` to conform to [RFC9180],
      but [FIPS.204] uses `Decaps()`.

The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}).

The KEM interface was chosen as the interface for a composite key establishment because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs. This specification uses the Post-Quantum KEM ML-KEM as specified in {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203]. For Traditional KEMs, this document uses the RSA-OAEP algorithm defined in [RFC3560], the Elliptic Curve Diffie-Hellman key agreement schemes ECDH defined in section 5.7.1.2 of [SP.800-56Ar3], and X25519 / X448 which are defined in [RFC8410]. A combiner function is used to combine the two component shared secrets into a single shared secret.


### Composite KeyGen

The `KeyGen() -> (pk, sk)` of a composite KEM algorithm will perform the `KeyGen()` of the respective component KEM algorithms and it produces a composite public key `pk` as per {{sec-composite-pub-keys}} and a composite secret key `sk` is per {{sec-priv-key}}.

~~~
CompositeKEM.KeyGen():
  (compositePK[0], compositeSK[0]) = MLKEM.KeyGen()
  (compositePK[1], compositeSK[1]) = TradKEM.KeyGen()

  return (compositePK, compositeSK)
~~~

### Promotion of RSA-OAEP into a KEM

The RSA Optimal Asymmetric Encryption Padding (OAEP), as defined in section 7.1 of [RFC8017] is a public key encryption algorithm used to transport key material from a sender to a receiver. It is promoted into a KEM by having the sender generate a random 256 bit secret and encrypt it.

~~~
RSAOAEPKEM.Encap(pkR):
  shared_secret = SecureRandom(ss_len)
  enc = RSAES-OAEP-ENCRYPT(pkR, shared_secret)

  return shared_secret, enc
~~~

Note that the OAEP label `L` is left to its default value, which is the empty string as per [RFC8017]. The shared secret output by the overall composite KEM already binds a composite domain separator, so there is no need to also utilize the component domain separators.

The value of `ss_len` as well as the RSA-OAEP parameters used within this specification can be found in {{sect-rsaoaep-params}}.

 `Decap(sk, ct) -> ss` is accomplished in the analogous way.

~~~
RSAOAEPKEM.Decap(skR, enc):
  shared_secret = RSAES-OAEP-DECRYPT(skR, enc)

  return shared_secret
~~~


Note that, at least at the time of writing, the algorithm `RSAOAEPKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it connot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.

### Promotion of ECDH into a KEM

An elliptic curve Diffie-Hellman key agreement is promoted into a KEM `Encap(pk) -> (ss, ct)` using a simplified version of the DHKEM definition from [RFC9180].


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

The simplifications from the DHKEM definition in [RFC9180] is that since the ciphertext and receiver's public key are included explicitly in the composite KEM combiner, there is no need to construct the `kem_context` object, and since a domain separator is included explicitly in the composite KEM combiner there is no need to perform the labelled steps of `ExtractAndExpand()`.


### KEM Combiner {#sec-kem-combiner}

TODO: as per https://www.enisa.europa.eu/publications/post-quantum-cryptography-integration-study section 4.2, might need to specify behaviour in light of KEMs with a non-zero failure probability.

The KEM combiner construction is as follows:

~~~
Combiner(mlkemSS, tradSS, tradCT, tradPK, domSep) :

  return KDF(mlkemSS || tradSS || tradCT || tradPK || domSep)
~~~
{: #code-generic-kem-combiner title="Generic KEM combiner construction"}

where:

* `KDF(message)` represents a key derivation function suitable to the chosen KEMs according to {tab-kem-combiners}. All KDFs are specified with a fixed output length.
* `mlkemSS` is the shared secret from the ML-KEM componont.
* `tradSS` is the shared secret from the traditional component (elliptic curve or RSA).
* `tradCT` is the ciphertext from the traditional component (elliptic curve or RSA).
* `tradPK` is the public key of the traditional component (elliptic curve or RSA).
* `domSep` SHALL be the DER encoded value of the object identifier of the composite KEM algorithm as listed in {{sec-domain}}.
* `||` represents concatenation.

Each registered composite KEM algorithm must specify the choice of `KDF`, `demSep` to be used.


### Composite Encap
Note that, at least at the time of writing, the algorithm `DHKEM` is not defined as a standalone algorithm within PKIX standards and it does not have an assigned algorithm OID, so it connot be used directly with CMS KEMRecipientInfo [RFC9629]; it is merely a building block for the composite algorithm.

The `Encap(pk) -> (ss, ct)` of a composite KEM algorithm is defined as:

~~~
CompositeKEM.Encap(pk):
  # Split the component public keys
  mlkemPK = pk[0]
  tradPK  = pk[1]

  # Perform the respective component Encap operations
  (mlkemCT, mlkemSS) = MLKEM.Encaps(mlkemPK)
  (tradCT, tradSS) = TradKEM.Encap(tradPK)

  # Combine
  # note that the order of the traditional and ML-KEM components
  # is flipped here in order to satisfy NIST SP800-56Cr2.
  ct = CompositeCiphertextValue(mlkemCT, tradCT)
  ss = Combiner(mlkemSS, tradSS, tradCT, tradPK, domSep)

  return (ss, ct)
~~~

where `Combiner(tradSS, mlkemSS, tradCT, tradPK, domSep)` is defined in general in {{sec-kem-combiner}} with specific values for `domSep` per composite KEM algorithm in {{sec-alg-ids}} and `CompositeCiphertextValue` is defined in {{sec-CompositeCiphertextValue}}.

### Composite Decap

The `Decap(sk, ct) -> ss` of a composite KEM algorithm is defined as:

~~~
CompositeKEM.Decap(ct, mlkemSK, tradSK):
  # split the component ciphertexts
  mlkemCT = ct[0]
  tradCT  = ct[1]

  # Perform the respective component Decap operations
  mlkemSS = MLKEM.Decaps(mlkemSK, mlkemCT)
  tradSS  = TradKEM.Decap(tradSK, tradCT)

  # Combine
  # note that the order of the traditional and ML-KEM components
  # is flipped here in order to satisfy NIST SP800-56Cr2.
  ss = Combiner(mlkemSS, tradSS, tradCT, tradPK, domSep)

  return ss
~~~

where `Combiner(tradSS, mlkemSS, tradCT, tradPK, domSep)` is defined in general in {{sec-kem-combiner}} with specific values for `domSep` per composite KEM algorithm in {{sec-alg-ids}}. `CompositeCiphertextValue` is defined in {{sec-CompositeCiphertextValue}}.

Here the secret key values `mlkemSK` and `tradSK` may be interpreted as either literal secret key values, or as a handle to a cryptographic module which holds the secret key and is capable of performing the secret key operation.


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

Use cases that require an inter-operable encoding for composite private keys, such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211] MUST use the following structure.

~~~ ASN.1
CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
~~~
{: artwork-name="CompositeKEMPrivateKey-asn.1-structures"}

Each element is a `OneAsymmetricKey`` [RFC5958] object for a component private key.

The parameters field MUST be absent.

The order of the component keys is the same as the order defined in {{sec-composite-pub-keys}} for the components of CompositeKEMPublicKey.

When a `CompositePrivateKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}}, the privateKey field SHALL contain the CompositeKEMPrivateKey, and the publicKey field MUST NOT be present. Associated public key material MAY be present in the CompositeKEMPrivateKey.

In some use-cases the private keys that comprise a composite key may not be represented in a single structure or even be contained in a single cryptographic module; for example if one component is within the FIPS boundary of a cryptographic module and the other is not; see {{sec-fips}} for more discussion. The establishment of correspondence between public keys in a CompositeKEMPublicKey and private keys not represented in a single composite structure is beyond the scope of this document.


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



## Key Usage Bits

For protocols such as X.509 [RFC5280] that specify key usage along with the public key, then the composite public key associated with a composite KEM algorithm MUST contain only a `keyEncipherment` key usage, all other key usages MUST NOT be used.
This is because the composite public key can only be used in situations
that are appropriate for both component algorithms, so even if the
classical component key supports both signing and encryption,
the post-quantum algorithms do not.


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

The order of the component ciphertexts is the same as the order defined in {{sec-composite-pub-keys}}.


Some of the design choices for the combiner, specifically to place `tradSS` first, and to allow `tradCT || tradPK || domSep` to be treated together as a FixedInfo block are made for the purposes of compliance with [SP.800-56Cr2]; see {{sec-fips}} for more discussion.

See {{sec-cons-kem-combiner}} for further discussion of the security considerations of this KEM combiner.



# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of composite KEM algorithms and lists the OID, two component algorithms, and the combiner function.

EDNOTE: The OID referenced are TBD and MUST be used only for prototyping and replaced with the final IANA-assigned OIDs.

TODO: OIDs to be replaced by IANA.

&lt;CompKEM&gt;.1 is equal to 2.16.840.1.114027.80.5.2.1

| Composite KEM                      | OID                  | First Algorithm | Second Algorithm     | KDF      |
|---------                           | -----------------    | ----------      | ----------           | -------- |
| id-MLKEM768-RSA2048                | &lt;CompKEM&gt;.21   | MLKEM768        | RSA-OAEP 2048        | HKDF-SHA256/256 |
| id-MLKEM768-RSA3072                | &lt;CompKEM&gt;.22   | MLKEM768        | RSA-OAEP 3072        | HKDF-SHA256/256 |
| id-MLKEM768-RSA4096                | &lt;CompKEM&gt;.23   | MLKEM768        | RSA-OAEP 4096        | HKDF-SHA256/256 |
| id-MLKEM768-X25519                 | &lt;CompKEM&gt;.24   | MLKEM768        | X25519               | SHA3-256 |
| id-MLKEM768-ECDH-P384              | &lt;CompKEM&gt;.25   | MLKEM768        | ECDH-P384            | HKDF-SHA384/384 |
| id-MLKEM768-ECDH-brainpoolP256r1   | &lt;CompKEM&gt;.26   | MLKEM768        | ECDH-brainpoolp256r1 | HKDF-SHA384/384 |
| id-MLKEM1024-ECDH-P384             | &lt;CompKEM&gt;.27   | MLKEM1024       | ECDH-P384            | SHA3-512 |
| id-MLKEM1024-ECDH-brainpoolP384r1  | &lt;CompKEM&gt;.28   | MLKEM1024       | ECDH-brainpoolP384r1 | SHA3-512 |
| id-MLKEM1024-X448                  | &lt;CompKEM&gt;.29   | MLKEM1024       | X448                 | SHA3-512 |
{: #tab-kem-algs title="Composite KEM key types"}

Full specifications for the referenced algorithms can be found as follows:

* _ECDH_: There does not appear to be a single IETF definition of ECDH, so we refer to the following:
  * _ECDH NIST_: SHALL be Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) as defined in section 5.7.1.2 of [SP.800-56Ar3].
  * _ECDH BSI / brainpool_: SHALL be Elliptic Curve Key Agreement algorithm (ECKA) as defined in section 4.3.1 of [BSI-ECC]
* _ML-KEM_: {{I-D.ietf-lamps-kyber-certificates}} and [FIPS.203]
* _RSA-OAEP_: [RFC3560]
* _X25519 / X448_: [RFC8410]
* _HKDF_: [RFC5869]. Salt is not provided; ie the default salt (all zeroes of length HashLen) will be used. In all cases, the output length of HKDF is the same as the block size of the underlying hash function, for example `HKDF-SHA256/256` means HKDF-SHA256 with an output length `L` of 256 bits (32 octets).
* _SHA2_: [FIPS.180-4]
* _SHA3_: [FIPS.202]


## Rationale for choices

* Pair equivalent levels.
* NIST-P-384 is CNSA approved [CNSA2.0] for all classification levels.
* 521 bit curve not widely used.

A single invocation of SHA3 is known to behave as a dual-PRF, and thus is sufficient for use as a KDF, see {{sec-cons-kem-combiner}}, however SHA2 is not us must be wrapped in the HKDF construction.

The lower security levels are provided with HKDF-SHA2 as the KDF in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-KEM function. Higher security levels are paired with SHA3 for computational efficiency, and the Edwards Curve (X25519 and X448) combinations are paired with SHA3 for compatibility with other similar spicifications.

## Domain Separators {#sec-domain}

The KEM combiner defined in section {{sec-kem-combiner}} requires a domain separator `domSep` input.  The following table shows the HEX-encoded domain separator for each Composite KEM AlgorithmID; to use it, the value should be HEX-decoded and used in binary form. The domain separator is simply the DER encoding of the composite algorithm OID.

| Composite KEM AlgorithmID | Domain Separator (in Hex encoding)|
| -----------               | ----------- |
| id-MLKEM768-RSA2048       | 060B6086480186FA6B50050215 |
| id-MLKEM768-RSA3072       | 060B6086480186FA6B50050216 |
| id-MLKEM768-RSA4096       | 060B6086480186FA6B50050217 |
| id-MLKEM768-ECDH-P384     | 060B6086480186FA6B50050218 |
| id-MLKEM768-ECDH-brainpoolP256r1 | 060B6086480186FA6B50050219 |
| id-MLKEM768-X25519        | 060B6086480186FA6B5005021A |
| id-MLKEM1024-ECDH-P384    | 060B6086480186FA6B5005021B |
| id-MLKEM1024-ECDH-brainpoolP384r1 | 060B6086480186FA6B5005021C |
| id-MLKEM1024-X448         | 060B6086480186FA6B5005021D |
{: #tab-kem-domains title="Composite KEM fixedInfo Domain Separators"}

EDNOTE: these domain separators are based on the prototyping OIDs assigned on the Entrust arc. We will need to ask for IANA early allocation of these OIDs so that we can re-compute the domain separators over the final OIDs.

## RSA-OAEP Parameters {#sect-rsaoaep-params}

Use of RSA-OAEP [RFC8017] within `id-MLKEM768-RSA2048`, `id-MLKEM768-RSA3072`, and `id-MLKEM768-RSA4096` requires additional specification.

First, a quick note on the choice of RSA-OAEP as the supported RSA encryption primitive. RSA-KEM [RFC5990] is more straightforward to work with, but it has fairly limited adoption and therefore is of limited backwards compatibility value. Also, while RSA-PKCS#1v1.5 [RFC8017] is still everywhere, but hard to make secure and no longer FIPS-approved as of the end of 2023 [SP800-131Ar2], so it is of limited forwards value. This leaves RSA-OAEP [RFC3560] as the remaining choice.

The RSA component keys MUST be generated at the 2048-bit and 3072-bit security levels respectively.

As with the other composite KEM algorithms, when `id-MLKEM512-RSA2048` or `id-MLKEM512-RSA3072` is used in an AlgorithmIdentifier, the parameters MUST be absent. The RSA-OAEP SHALL be instantiated with the following hard-coded parameters which are the same for both the 2048 and 3072 bit security levels.

| RSAES-OAEP-params           | Value                       |
| ----------------------      | ---------------             |
| hashAlgorithm               | id-sha2-256                 |
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

Composite KEM algorithms MAY be employed for one or more recipients in the CMS enveloped-data content type [RFC5652], the CMS authenticated-data content type [RFC5652], or the CMS authenticated-enveloped-data content type [RFC5083]. In each case, the KEMRecipientInfo [RFC9629] is used with the chosen composite KEM Algorithm to securely transfer the content-encryption key from the originator to the recipient.

## Underlying Components

A CMS implementation that supports a composite KEM algorithm MUST support at least the following underlying components:

When a particular Composite KEM OID is supported, an implementation MUST support the corresponding KDF algorithm identifier in {{tab-cms-kdf-wrap}}.

When a particular Composite KEM OID is supported, an implementation MUST support the corresponding key-encryption algorithm identifier in {{tab-cms-kdf-wrap}}.

The following table lists the REQUIRED KDF and key-encryption algorithms to preserve security and performance characteristics of each composite algorithm.


| Composite KEM OID                 | KDF         | Key Encryption Alg |
|---------                          | ---         | ---                |
| id-MLKEM768-RSA2048               | SHA3-256 | id-aes128-Wrap     |
| id-MLKEM768-RSA3072               | SHA3-256 | id-aes128-Wrap     |
| id-MLKEM768-ECDH-P384             | SHA3-384 | id-aes256-Wrap     |
| id-MLKEM768-ECDH-brainpoolP256r1  | SHA3-384 | id-aes256-Wrap     |
| id-MLKEM768-X25519                | SHA3-384 | id-aes256-Wrap     |
| id-MLKEM1024-ECDH-P384            | SHA3-512 | id-aes256-Wrap     |
| id-MLKEM1024-ECDH-brainpoolP384r1 | SHA3-512 | id-aes256-Wrap     |
| id-MLKEM1024-X448                 | SHA3-512 | id-aes256-Wrap     |
{: #tab-cms-kdf-wrap title="REQUIRED pairings for CMS KDF and WRAP"}

Note: `id-aes256-Wrap` is stronger than necessary for the MLKEM768 combinations at the NIST level 3 192 bit security level, however `id-aes256-Wrap` was chosen because it has better general adoption than `id-aes192-Wrap`.

where:

* SHA3-* KDF instantiations are defined in {{I-D.ietf-lamps-cms-sha3-hash}}.
* `id-aes*-Wrap` are defined in [RFC3394].


## RecipientInfo Conventions

When a composite KEM Algorithm is employed for a recipient, the RecipientInfo alternative for that recipient MUST be OtherRecipientInfo using the KEMRecipientInfo structure [RFC9629]. The fields of the KEMRecipientInfo MUST have the following values:

`version` is the syntax version number; it MUST be 0.

`rid` identifies the recipient's certificate or public key.

`kem` identifies the KEM algorithm; it MUST contain one of the OIDs listed in {{tab-kem-algs}}.

`kemct` is the ciphertext produced for this recipient; it contains the `ct` output from `Encap(pk)` of the KEM algorithm identified in the `kem` parameter.

`kdf` identifies the key-derivation function (KDF). Note that the KDF used for CMS RecipientInfo process MAY be different than the KDF used within the composite KEM Algorithm, which MAY be different than the KDFs (if any) used within the component KEMs of the composite KEM Algorithm.

`kekLength` is the size of the key-encryption key in octets.

`ukm` is an optional random input to the key-derivation function.

`wrap` identifies a key-encryption algorithm used to encrypt the keying material.

`encryptedKey` is the result of encrypting the keying material with the key-encryption key. When used with the CMS enveloped-data content type [RFC5652], the keying material is a content-encryption key. When used with the CMS authenticated-data content type [RFC5652], the keying material is a message-authentication key. When used with the CMS authenticated-enveloped-data content type [RFC5083], the keying material is a content-authenticated-encryption key.

## Certificate Conventions

The conventions specified in this section augment RFC 5280 [RFC5280].

The willingness to accept a composite KEM Algorithm MAY be signaled by the use of the SMIMECapabilities Attribute as specified in Section 2.5.2. of [RFC8551] or the SMIMECapabilities certificate extension as specified in [RFC4262].

The intended application for the public key MAY be indicated in the key usage certificate extension as specified in Section 4.2.1.3 of [RFC5280]. If the keyUsage extension is present in a certificate that conveys a composite KEM public key, then the key usage extension MUST contain only the following value:

keyEncipherment

The digitalSignature and dataEncipherment values MUST NOT be present. That is, a public key intended to be employed only with a composite KEM algorithm MUST NOT also be employed for data encryption or for digital signatures. This requirement does not carry any particular security consideration; only the convention that KEM keys be identified with the `keyEncipherment` key usage.


## SMIMECapabilities Attribute Conventions

Section 2.5.2 of [RFC8551] defines the SMIMECapabilities attribute to announce a partial list of algorithms that an S/MIME implementation can support. When constructing a CMS signed-data content type [RFC5652], a compliant implementation MAY include the SMIMECapabilities attribute that announces support for the RSA-OAEP Algorithm.

The SMIMECapability SEQUENCE representing a composite KEM Algorithm MUST include the appropriate object identifier as per {{tab-kem-algs}} in the capabilityID field.

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

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), it is obvious that the public keys or certificates using that algorithm are to be considered revoked.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled independently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLKEM512-ECDH-P256` even after ECDH-P256 is deprecated.

The composite KEM design specified in this document, and especially that of the KEM combiner specified in {{sec-kem-combiner}} means that the overall composite KEM algorithm should be considered to have the security strength of the strongest of its component algorithms; ie as long as one component algorithm remains strong, then the overall composite algorithm remains strong.


## KEM Combiner Security Analysis {#sec-cons-kem-combiner}

TODO

TODO: SHA3 is a dual PRF cite: x-wing

EDNOTE: the exact text to put here depends on the outcome of the CFRG KEM Combiners and X-Wing discussion. If CFRG doesn't move fast enough for us, then we may need to leverage this security consideration directly on top of the X-Wing paper [X-Wing].


### Ciphertext collision resistance {#sec-cons-ct-collision}

The notion of a ciphertext collision resistant KEM is defined in [X-Wing] being the property that it is computationally difficult to find two different ciphertexts that will decapsulate to the same shared secret under the same public key. In [X-Wing] it is proven that ML-KEM has this property and therefore the ML-KEM ciphertext can safely be omitted from the KEM combiner. Ciphertext collision resistance is not guaranteed for either RSA-OAEP or ECDH, therefore these ciphertexts are bound to the key derivation.


<!-- End of Security Considerations section -->

--- back

# Samples {#appdx-samples}

TBD

# Fixed Component Algorithm Identifiers

The following table lists explicitly the DER encoded `AlgorithmID` that MUST be used when reconstructing `SubjectPublicKeyInfo` objects for each component public key, which may be required for example if cryptographic library requires the public key in this form in order to process each component algorithm. The public key `BIT STRING` should be taken directly from the respective component of the CompositeKEMPublicKey.

| Composite KEM     | First AlgorithmID | Second AlgorithmID |
| --------------    | ----------------- | ------------------ |
| TODO              | TODO              | TODO               |

TODO: see https://github.com/lamps-wg/draft-composite-kem/issues/20

# Implementation Considerations {#sec-in-pract}

## FIPS Certification {#sec-fips}

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not. Implementers seeking FIPS certification of a composite KEM algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorithm with zero security, and the overall composite should be considered full strength and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions; for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.

### FIPS certification of Combiner Function

One of the primary NIST documents which is relevant for certification of a composite algorithm is NIST SP.800-56Cr2 [SP.800-56Cr2] by using the allowed "hybrid" shared secret of the form `Z' = Z || T`. Compliance is acheived in the following way:

SP.800-56Cr2 section 4 "One-Step Key Derivation" requires a `counter` which begins at the 4-byte value 0x00000001. However, the counter is allowed to be omitted when the hash function is executed only once, as specified on page 159 of the FIPS 140-3 Implementation Guidance [FIPS-140-3-IG].

The HKDF-SHA2 options can be certified under SP.800-56Cr2 One-Step Key Derivation Option 1: `H(x) = hash(x)`.

The SHA3 options can be certified under SP.800-56Cr2 One-Step Key Derivation Option 2: `H(x) = HMAC-hash(salt, x)` with the salt omitted.


## Backwards Compatibility {#sec-backwards-compat}

As noted in the introduction, the post-quantum cryptographic migration will face challenges in both ensuring cryptographic strength against adversaries of unknown capabilities, as well as providing ease of migration. The composite mechanisms defined in this document primarily address cryptographic strength, however this section contains notes on how backwards compatibility may be obtained.

The term "ease of migration" is used here to mean that existing systems can be gracefully transitioned to the new technology without requiring large service disruptions or expensive upgrades. The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can inter-operate with the upgraded systems of the future.

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



# Contributors and Acknowledgments

This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust), Ali Noman (Entrust), and
Douglas Stebila (University of Waterloo).

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].


<!-- End of Contributors section -->
