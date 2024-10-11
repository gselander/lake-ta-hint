---
title: "Trust Anchor Hints in Ephemeral Diffie-Hellman Over COSE (EDHOC)"
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
  RFC5905:
  RFC8126:
  RFC8174:
  RFC9052:
  RFC9528:
  RFC9334:
  RFC9390:
  RFC9562:

informative:
  I-D.ietf-cose-cbor-encoded-cert:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document defines a format for hints about Trust Anchors of trusted third parties for use with Ephemeral Diffie-Hellman Over COSE (EDHOC).

--- middle

# Introduction

Ephemeral Diffie-Hellman Over COSE (EDHOC) {{RFC9528}} is a lightweight security handshake protocol with low processing and message overhead, especially suited for constrained devices and low-power networking.

In addition to excuting a handshake protocol, to perform authentication and authorization typically involves the validation of certificates or assertions using Trust Anchors (TAs) established by other means. For this machinery to work, an endpoint thus needs to use  credentials issued by a TA of the other endpoint. Moreover, the validation of credentials against TAs can be a significant contribution to processing or time to completion, for example in embedded devices. Performance can be gained by providing the other endpoint with hints about which TAs are supported, or which TAs should be used to verify specific credentials. This document specifies how to transport hints of TAs between EDHOC peers.

EDHOC allows the inclusion of authorization-related information in the External Authorization Data (EAD) message fields, see {{Section 3.8 of RFC9528}}. EAD can be included in any of the four EDHOC messages (EAD_1, EAD_2, EAD_3, EAD_4), providing flexibility and extensibility to the protocol. Its main purpose is to embed authorization-related information directly into the key exchange process, reducing the need for additional message exchanges and simplifying the overall protocol flow. Information about TAs is explicitly mentioned as one example of such authorization-related information, see {{Appendix E of RFC9528}}.

The primary motivation for this specification is to provide hints of TAs for authentication, typically related to Certificate Authorities (CAs), where the TA includes the public key of the CA. The hint is a COSE header parameter intended to facilitate the retrieval of the TA, for example a key identifier (kid) or a hash of an X.509 certificate containing the CA root public key (x5t), see {{ead-item}}. However, the same scheme can be applied to hints about other trusted third parties, such as Verifiers of remote attestation evidence {{RFC9334}} or Time Servers for network time synchronization {{RFC5905}}. This document defines an EDHOC EAD item containing hints about certain type of TAs, and enables the extension to other kind of hints and TAs through the registration of the appropriate IANA parameters.


## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

# Trust Anchor Hints

## Trust Anchor Purpose

The EAD item defined in {{ead-item}} provides hints to trust anchors for different purposes. {{table-edhoc-ta-hint}} provides the currently defined list of purposes, which is extensible through IANA registry defined in {{iana}}.

| Label      |  Purpose                                         | Reference    |
| 1          | Trust anchor of EDHOC authentication credential  | [RFC-XXXX]   |
| 2          | Trust anchor of remote attestation verifier      | [RFC-XXXX]   |
| 3          | Trust anchor of time server                      | [RFC-XXXX]   |
{: #table-edhoc-ta-hint title="EDHOC Trust Anchor purposes" align="center"}

* EDHOC authentication credential: This parameter hints at which TA to use for authentication credentials in EDHOC. The positive of the CBOR label (+1) in the EAD item indicates trust anchor to use for verifying the authentication credentials from the sender. The negative of the CBOR label (-1) indicates what trust anchors are supported by the sender and SHOULD be used in authentication credentials sent to the sender.
* Remote attestation verifier: TODO
* Time server: TODO


## EAD Item {#ead-item}

This section defines the EAD item ead_ta_hint used to carry TA hints.

Like all EAD items, ead_ta_hint consists of the ead_label, a predefined constant that identifies this particular EAD structure; and the ead_value, which in this case is a byte string containing a CBOR map with the CBOR-encoded TA hints.

The following CDDL defines the EAD item, where header_map is defined in {{Section 3 of RFC9052}}, and contain one or more COSE header parameters.

~~~~~~~~~~~~~~~~~~~~ CDDL
ead_ta_hint = (
    ead_label: TBD1,
    ead_value: bstr .cbor ta_hint_map,
),

ta_hint_map = {
  * int => header_map
}
~~~~~~~~~~~~~~~~~~~~
{: #fig-ead-item title="EAD item" artwork-align="left"}

{{table-ta-hint-types}} provides examples COSE header_maps used as TA hint types.


| TA hint type | CBOR label | CBOR type       | Description                                | Reference                           |
| kid          | 4          | bstr            | Key identifier                             | [RFC-9052]                       |
| short kid    | TBD2       | bstr / -24..23  | Short key id, bstr or 1-byte integer       | [RFC-9528]                       |
| c5t          | 22         | COSE_CertHash   | C509 certificate thumbprint                | [draft-ietf-cose-cbor-encoded-cert] |
| c5u          | 23         | uri             | C509 certificate URI                       | [draft-ietf-cose-cbor-encoded-cert] |
| x5t          | 34         | COSE_CertHash   | X.509 certificate thumbprint               | [RFC-9360]                          |
| x5u          | 35         | uri             | X.509 certificate URI                      | [RFC-9360]                          |
| uuid         | TBD3       | #6.37(bstr)     |  Binary CBOR-encoded UUID                  | [RFC-9562]                          |
{: #table-ta-hint-types title="EDHOC Trust Anchor hint types" align="center"}

The TA hint type 'short kid' is REQUIRED to be implemented.

Editor's note: Need to register 'short kid' and 'uuid'.

# Processing {#proc}

In EDHOC message_2, where the Responder sends its credentials, the ead_ta_hint format is used to include TA hints in the EAD_2 field. This hint informs the Initiator about which TAs to prioritize when verifying the Responder's credentials. For example, if the Initiator’s trust store contains multiple CA/intermediate CA certificates, the Responder can include a hint indicating that the credentials should be verified using a specific TA identified by kid, x5t, x5u, c5t, c5u or UUID.

## Example 1

Consider a scenario where the Initiator trusts five CA/intermediate certificates. The Responder, when sending message_2, knows that the Initiator should use the TA identified by kid=`edhoc-noc-ica-2` for verification. The responder includes this hint in EAD_2:

~~~~~~~~~~~~~~~~~~~~
TBD1, << { 1: { 4: h'6564686F632D6E6F632D6963612D32'}} >>
~~~~~~~~~~~~~~~~~~~~

When the Initiator receives message_2, it will prioritize validating the Responder’s credentials using the TA associated with the provided kid.

If the validation against the TAs specified with the EAD item defined in this specification fails or is not recognized, then the receiver SHOULD fall back to the default validation process using available TAs. If all validation against TAs fail, then an error SHOULD be sent.

## Example 2

An EDHOC peer may include hints about its supported TAs to inform the other peer about what credentials it can validate. In this example ead_ta_hint contains hints about a TA used with an authentication credential (-1) which is identified by its SHA-256/64 hash (-15) and can be retrieved from a given URI.

~~~~~~~~~~~~~~~~~~~~
TBD1, << { -1: { 34: [-15, h'79f2a41b510c1f9b'],
                 35: "http://certs.tech.com"}} >>
~~~~~~~~~~~~~~~~~~~~

## Example 3

If both the information about TAs to use for validating the Responder's authentication credential (Example 1) and what TAs to use by the Initiator in its authentication credential (Example 2), then the EAD item ead_ta_hint in the EAD_2 field could look like this:

~~~~~~~~~~~~~~~~~~~~
TBD1, << { 1: { 4: h'6564686F632D6E6F632D6963612D32'}
          -1: { 34: [-15, h'79f2a41b510c1f9b'],
                 35: "http://certs.tech.com"}} >>
~~~~~~~~~~~~~~~~~~~~

Editor's note: Add examples using intermediate CAs


# Security Considerations

TODO


# IANA Considerations {#iana}

## EDHOC External Authorization Data Registry

IANA is requested to register the following entry to the "EDHOC External Authorization Data" registry defined in Section 10.5 of {{RFC9528}}.

The ead_label = TBD1 and the ead_value define TA hints transferred in an EAD item of an EDHOC message, with processing specified in {{proc}}.

Name: Trust Anchor Hint

Label: TBD1 (from the unsigned range)

Description: A hint for determination of Trust Anchors used for verifying authentication credentials in EDHOC {{RFC9528}} or of other assertions used with External Authorization Data of EDHOC.

Reference: [RFC-XXXX]

## EDHOC Trust Anchor Hint Registry

IANA has created a new registry entitled "EDHOC Trust Anchor Hint Registry". The registration procedure depends on the range of CBOR label values, following {{RFC8126}}. Guidelines for the experts are provided in TODO.

The columns of the registry are:

Label:
    The value to be used to identify this type of authority. Map key labels MUST be unique. The registry contains only positive integers, but negative integers MAY be used in the EAD item for the same type of authority but with separate semantics. Integer values between 1 and 23 are designated as Standards Track document required. Integer values from 24 to 255 are designated as Specification Required. Integer values from 256 to 65535 are designated as Expert Review. Integer values greater than 65535 are marked as Private Use.

Purpose:
    This field contains a brief description for the field.

Reference:
    This contains a pointer to the public specification for the field, if one exists.

This registry has been initially populated by the values in {{table-edhoc-ta-hint}}. The Reference column for all of these entries is this document.



--- back

# Acknowledgments
{:numbered="false"}

TODO
