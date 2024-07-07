---
title: "Semi-Private Messages in the Messaging Layer Security (MLS) Protocol"
abbrev: "MLS SemiPrivateMessage"
category: info

docname: draft-mahy-mls-semiprivatemessage-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: SEC
workgroup: MLS WG
keyword:
 - SemiPrivateMessage
venue:
  group: MLS WG
  type: Working Group
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "rohanmahy/mls-semiprivatemessage"
  latest: "https://rohanmahy.github.io/mls-semiprivate/draft-mahy-semiprivatemessage.html"

author:
 -
  fullname: Rohan Mahy
  organization: Rohan Mahy Consulting Services
  email: rohan.ietf@gmail.com

normative:

informative:

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction

# Syntax and Usage

This document defines the `SemiPrivateMessage`, a new Safe Extension
Wire Format as described in {{Section 2.1.7.1 of !I-D.ietf-mls-extensions}}.

~~~ tls
extension_type = TBD1 /* IANA-registered extension number */
SemiPrivateMessage extension_data;

struct {
  opaque key<V>;
  opaque nonce<V>;
} DecryptionPair;

DecryptionPair decryption_pair;

encrypted_decryption_pair = EncryptWithLabel(
  external_receiver_pulic_key,
  "SemiPrivateMessageReceiver",
  private_message, decryption_pair)

decryption_pair = DecryptWithLabel(
  external_receiver_private_key,
  "SemiPrivateMessageReceiver",
  private_message,
  encrypted_decryption_pair.kem_output,
  encrypted_decryption_pair.ciphertext)

struct {
  HPKEPublicKey external_receiver_public_key;
  Credential credential;
  HPKECiphertext encrypted_decryption_pair;
} ExternalReceiver;

struct {
  PrivateMessage private_message;
  ExternalReceiver external_receivers<V>;
} SemiPrivateMessageTBS;

struct {
  PrivateMessage private_message;
  ExternalReceiver external_receivers<V>;
  opaque envelope_signature<V>;
} SemiPrivateMessage;

~~~

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

The `semi_private_message` MLS Extension Type is used to signal support
for the `SemiPrivateMessage` Wire Format (a Safe Extension).

- Value: TBD1 (to be assigned by IANA)
- Name: semi_private_message
- Recommended: Y
- Reference: RFC XXXX

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
