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
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - SemiPrivateMessage
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "rohanmahy/mls-semiprivatemessage"
  latest: "https://rohanmahy.github.io/mls-semiprivatemessage/draft-mahy-mls-semiprivatemessage.html"

author:
 -
  fullname: Rohan Mahy
  organization: Rohan Mahy Consulting Services
  email: rohan.ietf@gmail.com

normative:

informative:

--- abstract

This document defines a SemiPrivateMessage for the Messaging Layer
Security (MLS) protocol. It allows members to share otherwise private
commits and proposals with a designated list of external receivers
rather than send these handshakes in a PublicMessage.

--- middle

# Introduction

This document defines two extensions of MLS {{!RFC9420}}. The first is the
`SemiPrivateMessage` wire format Safe Extension (see {{Section 2.1.7.1 of
!I-D.ietf-mls-extensions}}, which allows an otherwise PrivateMessage
to be shared with a predefined list of external receivers. It is restricted
for use only with commits or proposals. The second is the
`external_receivers` GroupContext extension that contains the list of
external receivers and allows members to agree on that list.

SemiPrivateMessages are expected to be useful in federated environments
where messages routinely cross multiple administrative domains, but the MLS
Distribution Service needs to see the content of commits and proposals where
group members would otherwise send handshakes using PublicMessage.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terminology extensively from MLS {{!RFC9420}} and
the Safe Extensions framework, defined in {{Section 2 of !I-D.ietf-mls-extensions}}.

# Syntax and Usage

The `external_receivers` GroupContext extension is used for all members
to agree on the list of external receivers in the current epoch. Its
construction mirrors the syntax of the `external_senders` extension in
{{!RFC9420}}.

~~~ tls
struct {
  HPKEPublicKey external_receiver_public_key;
  Credential credential;
} ExternalReceiver;
~~~

The `SemiPrivateMessage` wire format Safe Extension also has an
extension type which is carried in the GroupContext to indicate use
of the wire format in a group (and in the Capabilities of LeafNodes).
SemiPrivateMessage substantially reuses the construction of PrivateMessage,
but like a Welcome message also contains information (`keys_and_nonces`)
necessary to decrypt the `SemiPrivateMessage` struct's `ciphertext` and
`encrypted_sender_data`, encrypted once for each external receiver in the
`external_receivers` extension.

The snippet below shows the syntax and encryption and decryption construction of `keys_and_nonces` into `encrypted_keys_and_nonces`

~~~ tls
struct {
  opaque sender_data_key<V>;
  opaque sender_data_nonce<V>;
  opaque key<V>;
  opaque nonce<V>;
} PerMessageKeysAndNonces;

PerMessageKeysAndNonces keys_and_nonces;

encrypted_keys_and_nonces = EncryptWithLabel(
  external_receiver_public_key,
  "SemiPrivateMessageReceiver",
  SemiPrivateMessage.ciphertext,   /* context */
  keys_and_nonces)

keys_and_nonces = DecryptWithLabel(
  external_receiver_private_key,
  "SemiPrivateMessageReceiver",
  SemiPrivateMessage.ciphertext,  /* context */
  encrypted_keys_and_nonces.kem_output,
  encrypted_keys_and_nonces.ciphertext)
~~~

The `KeyForExternalReceiver` structure contains a hash of the
`ExternalReceiver` as a reference and the `encrypted_keys_and_nonces`.

~~~ tls
/* Using the hash function of the group ciphersuite */
ExternalReceiverRef = hash(ExternalReceiver)

struct {
  ExternalReceiverRef external_receiver_ref;
  HPKECiphertext encrypted_keys_and_nonces;
} KeyForExternalReceiver;
~~~

The `SemiPrivateMessage` and `SemiPrivateContentAAD` structs mirror
the `PrivateMessage` and `PrivateContentAAD` structs and add the
`keys_for_external_receivers` list. The `SemiPrivateMessageContent`
struct is the same as `PrivateMessageContent` except for the addition
of `keys_for_external_receivers`, and that application messages are
not included.

Encryption of the `ciphertext` and `encrypted_sender_data` proceed in the
same way for `SemiPrivateMessage` as for `PrivateMessage`. Finally, the
`SemiPrivateMessage` is wrapped in an `ExtensionContent` struct.

~~~ tls
struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    KeyForExternalReceiver keys_for_external_receivers<V>;
    opaque encrypted_sender_data<V>;
    opaque ciphertext<V>;
} SemiPrivateMessage;

struct {
    select (PrivateMessage.content_type) {
        case proposal:
          Proposal proposal;
        case commit:
          Commit commit;
    };
    KeyForExternalReceiver keys_for_external_receivers<V>;
    FramedContentAuthData auth;
    opaque padding[length_of_padding];
} SemiPrivateMessageContent;

struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    KeyForExternalReceiver keys_for_external_receivers<V>;
} SemiPrivateContentAAD;

/* IANA-registered value for semi_private_message */
extension_type = TBD2
SemiPrivateMessage extension_data;
~~~

# Security Considerations

These two extensions provide a privacy improvement over sending
handshake messages using PublicMessage. The handshake is shared
with a specific list of receivers, and that list is visible as
part of the GroupContext.

TODO More Security.

# IANA Considerations

## SemiPrivateMessage Wire Format

The `semi_private_message` MLS Extension Type is used to signal support
for the `SemiPrivateMessage` Wire Format (a Safe Extension).

- Value: TBD1 (to be assigned by IANA)
- Name: semi_private_message
- Recommended: Y
- Reference: RFC XXXX

## External Receivers Extension Type

The `external_receivers` extension contains a list of external receivers
targeted in a SemiPrivateMessage.

- Value: TBD2 (to be assigned by IANA)
- Name: external_receivers
- Message(s): GC. This extension may appear in GroupContext objects.
- Recommended: Y
- Reference: RFC XXXX

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
