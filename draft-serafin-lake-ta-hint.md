---
title: "Trust Anchor Hints in EDHOC"
abbrev: "TA Hints in EDHOC"
category: std

docname: draft-serafin-lake-ta-hint-latest
submissiontype: IETF
consensus: true
v: 3
area: "Security"
workgroup: "Lightweight Authenticated Key Exchange"
kw: Internet-Draft
coding: utf-8
venue:
  group: "Lightweight Authenticated Key Exchange"
  type: "Working Group"
  mail: "lake@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/lake/"
  github: "gselander/lake-ta-hint"
  latest: "https://gselander.github.io/lake-ta-hint/draft-serafin-lake-ta-hint.html"

author:
-
    ins: M. Serafin
    name: Marek Serafin
    organization: ASSA ABLOY
    email: marek.serafin@assaabloy.com
-
    ins: G. Selander
    name: Göran Selander
    org: Ericsson
    email: goran.selander@ericsson.com

normative:
  RFC2119:
  RFC8126:
  RFC8174:
  RFC9528:

informative:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

TODO Abstract


--- middle

# Introduction

Ephemeral Diffie-Hellman Over COSE (EDHOC) {{RFC9528}} is a  lightweight security handshake protocol with low processing and message overhead especially suitable for constrained devices and low-power networks.

Authentication and authorization, in addition to excuting a handshake protocol, typically requires the validation of certificates or assertions using Trust Anchors (TAs) established out-of-band. For this machinery to work, an endpoint thus needs to know and have credentials issued by a TA of the other endpoint. Moreover, the validation of credentials against TAs is a significant contribution to the processing in embedded devices, so it is desirable to provide hints about which TAs are supported, and which should be used to verify specific credentials.

EDHOC allows the inclusion of authorization-related information in the External Authorization Data (EAD) message fields, see {{Section 3.8 of RFC9528}}. EAD can be included in any of the four EDHOC messages (EAD_1, EAD_2, EAD_3, EAD_4), providing flexibility and extensibility to the protocol. Its main purpose is to embed authorization-related information directly into the key exchange process, reducing the need for additional message exchanges and simplifying the overall protocol flow. Information about TAs is explicitly mentioned as one example, see {{Appendix E of RFC9528}}.

The primary motivation for this specification are TAs for authentication, typically Certificate Authorities, but the same mechanism can be applied to other trusted third parties, such as verifiers of remote attestation evidence or network time servers. This draft defines an EAD item containing hints about these kind of TAs, and enables extensions to other kind of trust roots through registration of appropriate IANA parameters.


## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

# EAD Item

{{table-edhoc-ta-hint}} provides a summary of the EDHOC Trust Anchor hints defined in this section.

| Name                      | CBOR label | CBOR type   | Description                                   | Reference                        |
| authentication_authority  | 1          | ta_hints    | Trust anchor of authentication credential     | [RFC-XXXX]                       |
| attestation_verifier      | 2          | ta_hints    | Trust anchor of remote attestation verifier   | [RFC-XXXX]                       |
| time_authority            | 3          | ta_hints    | Trust anchor of time server                   | [RFC-XXXX]                      |
{: #table-edhoc-ta-hint title="EDHOC Trust Anchor hints" align="center"}

* authentication\_authority: This parameter hints at which TA to use for authentication credentials used in EDHOC. The positive CBOR label (+1) in the EAD item indicates trust anchor to use for verifying the authentication credentials from the sender. The negative CBOR label (-1) indicates what trust anchors are supported by the sender and SHOULD be used in authentication credentials sent to the sender.
* attestation\_verifier: TODO
* time\_authority: TODO



## CDDL Specification

The following CDDL defines the EAD item for Trust Anchor hints:

~~~~~~~~~~~~~~~~~~~~ CDDL
ead_ta_hint = (
    ead_label: ta_hint_ead_label,  ; A predefined constant that identifies this particular EAD structure
    ead_value: bstr .cbor ta_hint_map ; The value is a byte string containing CBOR-encoded TA hints
)

ta_hint_map = {
  * int => ta_hints
},
ta_hints = (ta_hint / [2* ta_hint]),
; ta_hints definitions with one required and several optional implementations.
;REQUIRED to implement:
; A required TA hint type using 'kid' (Key ID).
ta_hint //= (ta_hint-type-kid, -24...23 / bstr)
;OPTIONAL to implement:
; An optional TA hint type using 'x5t' (X.509 CA/ICA Certificate SHA-1 thumbprint).
ta_hint //= (ta_hint-type-x5t, COSE_CertHash)
; An optional TA hint type using 'x5u' (X.509 CA/ICA Certificate URL).
ta_hint //= (ta_hint-type-x5u, uri)
; An optional TA hint type using 'c5t' (CBOR CA/ICA Certificate SHA-1 thumbprint).
ta_hint //= (ta_hint-type-c5t, COSE_CertHash)
; An optional TA hint type using 'c5u' (CBOR CA/ICA Certificate URL).
ta_hint //= (ta_hint-type-c5u, uri)
; An optional TA hint type using 'uuid', represented as a binary UUID.
ta_hint //= (ta_hint-type-uuid, buuid)
; Trust type identifiers used to specify the type of trust hint in ta_hint.
;REQUIRED to implement:
; Identifier for 'kid' TA hint type.
ta_hint-type-kid = 1
;OPTIONAL to implement:
; Identifier for 'x5t' TA hint type.
ta_hint-type-x5t = 2
; Identifier for 'x5u' TA hint type.
ta_hint-type-x5u = 3
; Identifier for 'c5t' TA hint type.
ta_hint-type-c5t = 4
; Identifier for 'c5u' TA hint type.
ta_hint-type-c5u = 5
; Identifier for 'uuid' TA hint type.
ta_hint-type-uuid = 6
; Defined in [RFC9360]
COSE_CertHash = [
    hashAlg: (int / tstr),  ; Hash algorithm identifier corresponding to the Value column of the algorithm
registered in the "COSE Algorithms" registry.
    hashValue: bstr         ; The hash value itself as a byte string.
]
; Binary UUID (universally unique identifier) tagged with specific CBOR tag to ensure proper encoding.
buuid = #6.37(bstr)
; The label for the EAD item containing TA hints
ta_hint_ead_label = TBD
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}


# Processing

In EDHOC message_2, where the responder sends its credentials, the ead_ta_hint format is used to include trust anchor hints in the EAD_2 field. This hint informs the initiator about which trust roots to prioritize when verifying the responder's credentials. For example, if the initiator’s trust store contains multiple CA/intermediate CA certificates, the responder can include a hint indicating that the credentials should be verified using a specific trust root identified by kid, x5t, x5u, c5t, c5u or UUID.

The hint structure is designed as follows:

* ead_label: A predefined constant that identifies this EAD structure.
* ead_value: A byte string containing CBOR map of CBOR encoded trust anchor hints (ta_hints).

ta_hints can contain one or more ta_hint entries, where each entry provides a hint on which trust root to use. The hints can include:

* kid: A key identifier for a specific trust root.
* x5t: A SHA-1 thumbprint of an X.509 certificate.
* x5u: A URL pointing to an X.509 certificate.
* c5t: A SHA-1 thumbprint of a CBOR certificate.
* c5u: A URL pointing to a CBOR certificate.
* aeid: A binary UUID representing an Assa Abloy Entity Identifier

## Example Scenario
Consider a scenario where the initiator trusts five CA/intermediate certificates. The responder, when sending message_2, knows that the initiator should use the trust root identified by kid=`edhoc-noc-ica-2` for verification. The responder includes this hint in EAD_2:

~~~~~~~~~~~~~~~~~~~~
{TBD}, << 1, h'6564686F632D6E6F632D6963612D32' >>
~~~~~~~~~~~~~~~~~~~~

When the initiator receives message_2, it will prioritize validating the responder’s credentials using the trust root associated with the provided kid.


If the validation against the trust anchors specified with the EAD item defined in this specification fails or is not recognized, then the receiver SHOULD fall back to the default validation process using available trust anchors. If all validation against trust anchors fail, then an error SHOULD be sent.


# Security Considerations

TODO Security


# IANA Considerations {#iana}

## EDHOC External Authorization Data Registry

IANA is requested to register the following entry to the "EDHOC External Authorization Data" registry defined in Section 10.5 of {{RFC9528}}.

The ead_label = TBD and the ead_value define a TA hint transferred in an EAD item of an EDHOC message, with processing specified in Section TODO.

Name: Trust Anchor Hint

Label: TBD (from the unsigned range)

Description: A hint for determination of Trust Anchors used for verifying authentication credentials in EDHOC {{RFC9528}} or of other assertions used with External Authorization Data of EDHOC.

Reference: [RFC-XXXX]

## EDHOC Trust Anchor Hint Registry

IANA has created a new registry entitled "EDHOC Trust Anchor Hint Registry". The registration procedure depends on the range of CBOR label values, following {{RFC8126}}. Guidelines for the experts are provided in TODO.

The columns of the registry are:

Name:
    The name indicates the type of authority for which a hint is provided.

CBOR Label:
    The value to be used to identify this type of authority. Map key labels MUST be unique. The registry contains only positive integers, but negative integers MAY be used in the EAD item for the same type of authority but with separate semantics. Integer values between 1 and 23 are designated as Standards Track document required. Integer values from 24 to 255 are designated as Specification Required. Integer values from 256 to 65535 are designated as Expert Review. Integer values greater than 65535 are marked as Private Use.

CBOR Type:
    This field contains the CBOR type for the field.

Description:
    This field contains a brief description for the field.

Reference:
    This contains a pointer to the public specification for the field, if one exists.

This registry has been initially populated by the values in {{table-edhoc-ta-hint}}. The Reference column for all of these entries is this document.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
