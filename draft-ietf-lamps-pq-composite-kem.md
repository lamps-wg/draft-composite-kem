---
title: Composite KEM For Use In Internet PKI
abbrev: Composite KEMs
docname: draft-ietf-lamps-pq-composite-kem-latest

# <!-- stand_alone: true -->
ipr: trust200902
area: Security
stream: IETF
wg: LAMPS
kw: Internet-Draft
cat: std

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
  RFC5480:
  RFC5652:
  RFC5990:
  RFC8017:
  RFC8174:
  RFC8410:
  RFC8411:
  I-D.draft-ounsworth-pq-composite-keys-04:
  I-D.draft-housley-lamps-cms-kemri-02:
  I-D.draft-ietf-lamps-kyber-certificates-00:
  SHA3:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions, FIPS PUB 202, DOI 10.6028/NIST.FIPS.202"
    author:
      org: "National Institute of Standards and Technology (NIST)"
    date: August 2015
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf\
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



# <!-- EDNOTE: full syntax for this defined here: https://github.com/cabo/kramdown-rfc2629 -->

informative:
  RFC5639:
  RFC6090:
  RFC7296:
  RFC7748:
  RFC8446:
  RFC8551:
  I-D.draft-ounsworth-pq-composite-sigs-08:
  I-D.draft-ietf-tls-hybrid-design-04:
  I-D.draft-driscoll-pqt-hybrid-terminology-01:
  I-D.draft-ounsworth-cfrg-kem-combiners-03:




--- abstract

The migration to post-quantum cryptography is unique in the history of modern digital cryptography in that neither the old outgoing nor the new incoming algorithms are fully trusted to protect data for the required data lifetimes. The outgoing algorithms, such as RSA and elliptic curve, may fall to quantum cryptalanysis, while the incoming post-quantum algorithms face uncertainty about both the underlying mathematics as well as hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

Cautious implementers may wish to layer cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected using either a Post-Quantum / Traditional Hybrid, Post-Quantum / Post-Quantum Hybrid, or combinations thereof. This document, and its companions, defines a specific instantiation of hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key, signature, or key encapsulation mechanism (KEM) such that they can be treated as a single atomic object at the protocol level.


This document defines the structure CompositeCiphertextValue which is a sequence of the respective ciphertexts for each component algorithm. Explicit pairings of algorithms are defined which should meet most Internet needs. For the purpose of combining KEMs, the combiner function from {{I-D.ounsworth-cfrg-kem-combiners}} is used.


This document is intended to be coupled with the composite keys
structure define in {{I-D.ounsworth-pq-composite-keys}} and the CMS KEMRecipientInfo mechanism in {{I-D.housley-lamps-cms-kemri}}.


<!-- End of Abstract -->


--- middle

# Changes in version -02

* Removed all references to generic composite.
* Added selection criteria note about requesting new explicit combinations.


# Introduction {#sec-intro}

During the transition to post-quantum cryptography, there will be uncertainty as to the strength of cryptographic algorithms; we will no longer fully trust traditional cryptography such as RSA, Diffie-Hellman, DSA and their elliptic curve variants, while we may also not fully trust their post-quantum replacements until they have had sufficient scrutiny and time to discover and fix implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear. Even after the migration period, it may be advantageous for an entity's cryptographic identity to be composed of multiple public-key algorithms.

The deployment of composite public keys and composite encryption using post-quantum algorithms will face two challenges


- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.


This document provides a mechanism to address algorithm strength uncertainty by building on {{I-D.ounsworth-pq-composite-keys}} by providing the format and process for combining multiple cryptographic algorithms into a single key encapsulation operation. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.


This document is intended for general applicability anywhere that key establishment or enveloped content encryption is used within PKIX or CMS structures.


## Algorithm Selection Criteria {#sec-selection-criteria}

The composite algorithm combinations defined in this document were chosen according to the following guidelines:

1. A single RSA combination is provided (but RSA modulus size not mandated), matched with NIST PQC Level 3 algorithms.
1. Elliptic curve algorithms are provided with combinations on each of the NIST [RFC6090], Brainpool [RFC5639], and Edwards [RFC7748] curves. NIST PQC Levels 1 - 3 algorithms are matched with 256-bit curves, while NIST levels 4 - 5 are matched with 384-bit elliptic curves. This provides a balance between matching classical security levels of post-quantum and traditional algorithms, and also selecting elliptic curves which already have wide adoption.
1. NIST level 1 candidates (Falcon512 and Kyber512) are provided, matched with 256-bit elliptic curves, intended for constrained use cases.
The authors wish to note that although all the composite structures defined in this and the companion documents {{I-D.ounsworth-pq-composite-keys}} and {{I-D.ounsworth-pq-composite-sigs}} pecifications are defined in such a way as to easily allow 3 or more component algorithms, it was decided to only specify explicit pairs. This also does not preclude future specification of explicit combinations with three or more components.

To maximize interoperability, use of the specific algorithm combinations specified in this document is encouraged.  If other combinations are needed, a separate specification should be submitted to the IETF LAMPS working group.  To ease implementation, these specifications are encouraged to follow the construction pattern of the algorithms specified in this document.


<!-- End of Introduction section -->


## Terminology {#sec-terminology}
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

This document is consistent with all terminology from {{I-D.driscoll-pqt-hybrid-terminology}}.

In addition, the following terms are used in this document:


BER:
          Basic Encoding Rules (BER) as defined in [X.690].

CLIENT:
          Any software that is making use of a cryptographic key.
          This includes a signer, verifier, encrypter, decrypter.

COMBINER:
          A combiner specifies how multiple shared secrets
          are combined into a single shared secret.
DER:
          Distinguished Encoding Rules as defined in [X.690].

KEM:
        A key encapsulation mechanism as defined in {{sec-kems}}.

PKI:
          Public Key Infrastructure, as defined in [RFC5280].

SHARED SECRET:
        A value established between two communicating parties for use as cryptographic key material, but which cannot be learned by an active or
        passive adversary. This document is concerned with shared secrets established via public key cryptagraphic operations.


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


This document is not concerned with the KeyGen() algorithm of a KEM, but it is included above for completeness.

The KEM interface defined above differs from both traditional key transport mechanism (for example for use with KeyTransRecipientInfo defined in {{RFC5652}}), and key agreement (for example for use with KeyAgreeRecipientInfo defined in {{RFC5652}}).

The KEM interface was chosen as the interface for a composite key exchange because it allows for arbitrary combinations of component algorithm types since both key transport and key agreement mechanisms can be promoted into KEMs in the following ways:

A key transport mechanism can be transformed into a `KEM.Encaps(pk)` by generating a random shared secret ss and performing `KeyTrans.Encrypt(pk, ss) -> ct`; and into a `KEM.Decaps(sk, ct)` by `KeyTrans.Decrypt(sk, ct) -> ss`. This follows the pattern of RSA-KEM [RFC5990].

A key agreement mechanism can be transformed into a `KEM.Encaps(pk)` by generating an ephemeral key pair `(pk_e, sk_e)`, and performing `KeyAgree(pk, sk_e) -> (ss, pk_e)` and into a `KEM.Decaps(sk, ct)` by completing the key agreement as `KeyAgree(pk_e, sk) -> ss`.

A composite KEM allows two or more underlying key transport, key agreement, or KEM algorithms to be combined into a single cryptographic operation by performing each operation, transformed to a KEM as outline above, and using a specified combiner function to combine the two or more component shared secrets into a single shared secret.



The main security property for KEMs is indistinguishability under
adaptive chosen ciphertext attack (IND-CCA2), which means that shared
secret values should be indistinguishable from random strings even
given the ability to have other arbitrary ciphertexts decapsulated.
By using the KEM combiner defined in {{I-D.ounsworth-cfrg-kem-combiners}}, the composite KEMs defined in this document inherit the IND-CCA2 security from the general combiner.

TODO: needs more formal analysis that the methods of transforming KeyTrans and KeyAgree meet this.

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


## Composite Keys

A composite KEM MAY be associated with a composite public key as defined in [I-D.ounsworth-pq-composite-keys], but MAY also be associated with multiple public keys from different sources, for example multiple X.509 certificates, or multiple cryptographic modules. In the latter case, composite KEMs MAY be used as the mechanism for carrying multiple ciphertexts in a non-composite hybrid encryption equivalent of those described for digital signatures in [I-D.becker-guthrie-noncomposite-hybrid-auth].


### Key Usage Bits

When using composite KEM keys in a structure which defines a key usage (such as in an
X509Certificate as defined in [RFC5280]), the following key usage MUST be used.

~~~
  keyEncipherment
~~~

Additional key usages SHOULD not be used.


## CompositeCiphertextValue {#sec-CompositeCiphertextValue}

The compositeCipherTextValue is a concatenation of the ciphertexts of the
underlying component algorithms.  It is represented in ASN.1 as follows:

~~~
CompositeCiphertextValue ::= SEQUENCE SIZE (2..MAX) OF OCTET STRING
~~~


## CompositKemParameters {#sec-compositeKemParameters}

Composite KEM parameters are defined as follows and MAY be included when a composite KEM algorithm is used with an AlgorithmIdentifier:

~~~ asn.1
CompositeKemParams ::= SEQUENCE SIZE (2..MAX) OF AlgorithmIdentifier{
    KEM-ALGORITHM, {KEMAlgSet} }
~~~

The KEM's `CompositeKemParams` sequence MUST contain the same component algorithms listed in the same order as in the associated CompositePublicKey.

For explicit composite algorithms, it is required in cases where one or both of the components themselves have parameters that need to be carried, however the authors have chosen to always carry it in order to simplify parsers. Implementation SHOULD NOT rely directly on the algorithmIDs contained in the `CompositeKemParams` and SHOULD verify that they match the algorithms expected from the overall composite AlgorithmIdentifier.


## Encoding Rules

Many protocol specifications will require that composite KEM data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

EDNOTE: will this definition include an ASN.1 tag and length byte inside the OCTET STRING object? If so, that's probably an extra unnecessary layer.

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

In the interests of simplicity and avoiding compatibility issues, implementations that parse these structures MAY accept both BER and DER.

## KEM Combiner {#sec-kem-combiner}

TODO: as per https://www.enisa.europa.eu/publications/post-quantum-cryptography-integration-study section 4.2, might need to specify behaviour in light of KEMs with a non-zero failure probility.

This document follows the construction of {{I-D.ounsworth-cfrg-kem-combiners}}, which is repeated here for clarity:

~~~
KDF(counter || k_1 || ... || k_n || fixedInfo, outputBits)

where
k_i = H(ss_i || ct_i)
~~~

where:

* `KDF` and `H`, and `outputBits` represent a hash functions suitable to the chosen KEMs,
* `fixedInfo` any additional context string provided by the protocol,
* `counter` is fixed to the 32-bit value `0x00000001`,
* `||` represents concatenation.

Each registered composite KEM algorithm must specify the exact KEM combiner construction that is to be used.



For convenience we define the following KMAC-based instantiations of KEM combiner:

| KEM Combiner | KDF | H   | outputBits |
| ---          | --- |---  |---         |
| KMAC128/256  | KMAC128   | SHA3-256 | 256 |
| KMAC256/384  | KMAC256   | SHA3-512 | 384 |
| KMAC256/512  | KMAC256   | SHA3-512 | 512 |
{: #tab-kem-combiners title="KEM Combiners"}

KMAC is defined in NIST SP 800-185 [SP800-185]. The `KMAC(K, X, L, S)` parameters are instantiated as follows:

* `K`: the ASCI value of the name of the Kem Type OID.
* `X`: the value "`0x00000001 || k_1 || ... || k_n || fixedInfo`", where `k_i = H(ss_i || ct_i)`, as defined above.
* `L`: integer representation of `outputBits`.
* `S`: empty string.

~~~ BEGIN EDNOTE ~~~

these choices are somewhat arbitrary but aiming to match security level of the input KEMs. Feedback welcome.

* Kyber512: KMAC128/256
* Kyber768: KMAC256/384
* Kyber1024 KMAC256/512

~~~ END EDNOTE ~~~


For example, the KEM combiner instantiation of the first entry of {{tab-kem-algs}} would be:

~~~
ss = KMAC128("id-Kyber512-ECDH-P256-KMAC128",
    0x00000001 || SHA3-256(ss_1 || ct_1) || SHA3-256(ss_2 || ct_2) || fixedInfo,
    256, "")
~~~

# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of explicit composite Signature algorithms by the key and signature OID and the two component algorithms which make up the explicit composite algorithm.  These are denoted by First Signature Alg, and Second Signature Alg.

The OID referenced are TBD and MUST be used only for prototyping and replaced with the final IANA-assigned OIDS. The following prefix is used for each: replace &lt;CompKEM&gt; with the String "2.16.840.1.114027.80.5.2"

Therefore &lt;CompKEM&gt;.1 is equal to 2.16.840.1.114027.80.5.2.1

The "KEM Combiner" column refers to the definitions in {{sec-kem-combiner}}.

| KEM Type OID                                     | OID                | First Algorithm   | Second Algorithm |  KEM Combiner     |
|---------                                    | -----------------  | ----------      | ----------     | ----------    |
| id-Kyber512-ECDH-P256-KMAC128              | &lt;CompKEM&gt;.1  | Kyber512        | ECDH-P256      | KMAC128/256  |
| id-Kyber512-ECDH-brainpoolP256r1-KMAC128   | &lt;CompKEM&gt;.2  | Kyber512        | ECDH-brainpoolp256r1 | KMAC128/256 |
| id-Kyber512-X25519-KMAC128                 | &lt;CompKEM&gt;.3  | Kyber512        | X25519         | KMAC128/256 |
| id-Kyber768-RSA-KMAC256                    | &lt;CompKEM&gt;.4  | Kyber768        | RSA-KEM        | KMAC256/384 |
| id-Kyber768-ECDH-P256-KMAC256              | &lt;CompKEM&gt;.5  | Kyber768        | ECDH-P256      | KMAC256/384 |
| id-Kyber768-ECDH-brainpoolP256r1-KMAC256   | &lt;CompKEM&gt;.6  | Kyber768        | ECDH-brainpoolp256r1 | KMAC256/384 |
| id-Kyber768-X25519-KMAC256                 | &lt;CompKEM&gt;.7  | Kyber768        | X25519         | KMAC256/384 |
| id-Kyber1024-ECDH-P384-KMAC256             | &lt;CompKEM&gt;.8  | Kyber1024       | ECDH-P384     | KMAC256/512 |
| id-Kyber1024-ECDH-brainpoolP384r1-KMAC256  | &lt;CompKEM&gt;.9  | Kyber1024       | ECDH-brainpoolP384r1 | KMAC256/512 |
| id-Kyber1024-X448-KMAC256                  | &lt;CompKEM&gt;.10 | Kyber1024       | X448          | KMAC256/512 |
{: #tab-kem-algs title="Composite KEM key types"}


The table above contains everything needed to implement the listed explicit composite algorithms, with the exception of some special notes found below in this section. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.

Full specifications for the referenced algorithms can be found as follows:

* _ECDH_: There does not appear to be a single IETF definition of ECDH, so we refer to the following:
  * _ECDH NIST_: SHALL be Elliptic Curve Cryptography Cofactor Diffie-Hellman (ECC CDH) as defined in section 5.7.1.2 of [SP.800-56Ar3].
  * _ECDH BSI / brainpool_: SHALL be Elliptic Curve Key Agreement algorithm (ECKA) as defined in section 4.3.1 of [BSI-ECC]
* _Kyber_: {{I-D.ietf-lamps-kyber-certificates}}
* _RSA-KEM_: [RFC5990]
* _X25519 / X448_: [RFC8410]

EDNOTE: I believe that [SP.800-56Ar3] and [BSI-ECC] give equivalent and interoperable algorithms, so maybe this is extranuous detail to include?



## Notes on id-Kyber768-RSA-KMAC256

Use of RSA-KEM [RFC5990] deserves a special explanation.


`GenericHybridParameters` is defined in [RFC5990], repeated here for clarity:

~~~
GenericHybridParameters ::= {
    kem  KeyEncapsulationMechanism,
    dem  DataEncapsulationMechanism
}
~~~

The `GenericHybridParameters.kem` MUST be `id-kem-rsa` as defined in [RFC5990]:

~~~
id-kem-rsa OID ::= {
    is18033-2 key-encapsulation-mechanism(2) rsa(4)
}
~~~

The associated parameters for id-kem-rsa have type
RsaKemParameters:

~~~
RsaKemParameters ::= {
    keyDerivationFunction  KeyDerivationFunction,
    keyLength              KeyLength
}
~~~


For use with `id-Kyber768-RSA-KMAC256`, the `keyDerivationFunction` SHALL be `id-sha3-384` and `keyLength` SHALL be `384`.

EDNOTE: I'm borrowing `id-sha3-384` from draft-turner-lamps-adding-sha3-to-pkix-00, which looks ilke was abandoned. Do we have PKIX OIDs for SHA3?

EDNOTE: Since the crypto is fixed, we could omit the parameters entirely and expect implementations to re-constitute the params structures as necessary in order to call into lower-level crypto libraries.

TODO: there must be a way to put all this the ASN.1 Module rather than just specifying it as text?



# ASN.1 Module {#sec-asn1-module}

~~~ ASN.1

<CODE STARTS>

{::include Composite-KEM-2023.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}
The following need to be assigned by IANA:

* The OID for the ASN.1 module `Composite-KEM-2023`

TODO

<!-- End of IANA Considerations section -->


# Security Considerations


## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), it is obvious that structures using that algorithm are implicitly revoked.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key, certificate, signature, or ciphertext may contain a mixture of deprecated and non-deprecated algorithms.

Specifying behaviour in these cases is beyond the scope of this document, but should be considered by Implementers and potentially in additional standards.

EDNOTE: Max is working on a CRL mechanism to accomplish this.

## OR Modes

TODO -- we'll need security consideration analysis of whatever OR modes we choose.


## KEM Combiner

This document uses directly the KEM Combiner defined in {{I-D.ounsworth-cfrg-kem-combiners}} and therefore inherits all of its security considerations, which the authors believe have all been addressed in the concrete choices for explicit composites.

<!-- End of Security Considerations section -->

--- back

# Samples {#appdx-samples}

TBD


# Implementation Considerations {#sec-in-pract}

This section addresses practical issues of how this draft affects other protocols and standards.


EDNOTE 10: Possible topics to address:

  - The size of these certs and cert chains.
  - In particular, implications for (large) composite keys / signatures / certs on the handshake stages of TLS and IKEv2.
  - If a cert in the chain is a composite cert then does the whole chain need to be of composite Certs?
  - We could also explain that the root CA cert does not have to be of the same algorithms. The root cert SHOULD NOT be transferred in the authentication exchange to save transport overhead and thus it can be different than the intermediate and leaf certs.
  - We could talk about overhead (size and processing).
  - We could also discuss backwards compatibility.
  - We could include a subsection about implementation considerations.



## Backwards Compatibility {#sec-backwards-compat}

As noted in the introduction, the post-quantum cryptographic migration will face challenges in both ensuring cryptographic strength against adversaries of unknown capabilities, as well as providing ease of migration. The composite mechanisms defined in this document primarily address cryptographic strength, however this section contains notes on how backwards compatibility may be obtained.

The term "ease of migration" is used here to mean that existing systems can be gracefully transitioned to the new technology without requiring large service disruptions or expensive upgrades. The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.

These migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to key establishment and content encryption, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] encrypted structures.

### K-of-N modes

~~~ BEGIN EDNOTE ~~~
In the context of encryption, K-of-N modes could mean one of two things:

Type 1: sender uses a subset

This would mean the sender (encrypter) uses a subset of K the N component keys within the receiver's public key. The obvious way to combine them is with skipping the unused keys / algorithms and emitting a NULL ciphertext in their place. This mechanism is straight-forward and allows ease of migration where a sender encounters a composite encryption public key where it does not support all component algorithms. It also supports performance optimization where, for example, a receiver can be issued a key with many component keys and a sender can choose the highest-performance subset that are still considered safe.


Type 2: receiver uses a subset

This would mean that the sender (encrypter) uses all N of the component keys within the receiver's public key in such a way that the receiver (decrypter) only needs to use K private keys to decrypt the message. This implies the need for some kind of Shamir's-like secret splitting scheme. This is a reasonably complex mechanism and it's currently unclear if there are any use-cases that require such a mechanism.

~~~ END EDNOTE ~~~


### Parallel PKIs

We present the term "Parallel PKI" to refer to the setup where a PKI end entity possesses two or more distinct public keys or certificates for the same identity (name), but containing keys for different cryptographic algorithms. One could imagine a set of parallel PKIs where an existing PKI using legacy algorithms (RSA, ECC) is left operational during the post-quantum migration but is shadowed by one or more parallel PKIs using pure post quantum algorithms or composite algorithms (legacy and post-quantum).

Equipped with a set of parallel public keys in this way, a client would have the flexibility to choose which public key(s) or certificate(s) to use in a given signature operation.

For negotiated protocols, the client could choose which public key(s) or certificate(s) to use based on the negotiated algorithms.

For non-negotiated protocols, the details for obtaining backwards compatibility will vary by protocol, but for example in CMS [RFC5652].

EDNOTE: I copied and pruned this text from {{I-D.ounsworth-pq-composite-sigs}}. It probably needs to be fleshed out more as we better understand the implementation concerns around composite encryption.

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
