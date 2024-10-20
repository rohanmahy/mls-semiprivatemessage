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

Whenever a hash function is mentioned, it refers to the hash function
defined in the cipher suite in use for the relevant MLS group.

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
extension type which is carried in the GroupContext `required_capabilities`
to indicate use of the wire format in a group, and in the Capabilities of
LeafNodes)

SemiPrivateMessage substantially reuses the construction of PrivateMessage,
but like a Welcome message also contains information (`key_and_nonces`)
necessary to identify the sender leaf node and decrypt the
`SemiPrivateMessage` struct's `ciphertext`.  Note that the
`encrypted_sender_data` cannot be decrypted by an external receiver,
but the `sender_leaf_index` is included with `key_and_nonces` and is
verified in another step. `key_and_nonces` is encrypted once for each
external receiver in the `external_receivers` extension.

## Encryption of a SemiPrivateMessage

As with a `PrivateMessage`, the sending client chooses an unused generation
in its own handshake ratchet and derives a `key` and `nonce`. It also
generates a fresh random four-byte `reuse_guard`.
The snippet below shows the syntax and encryption and decryption
construction of `keys_and_nonces` into `encrypted_keys_and_nonces`
for each external receiver.

~~~ tls
struct {
  opaque key<V>;
  opaque nonce<V>;
  opaque reuse_guard[4];
  uint32 sender_leaf_index;
} PerMessageKeyAndNonces;

partial_context_hash = hash(sender_leaf_index || nonce)

struct {
  opaque group_id<V>;
  uint64 epoch;
  opaque partial_context_hash<V>;
} SemiPrivateMessageContext;

PerMessageKeyAndNonces key_and_nonces;
SemiPrivateMessageContext semi_private_message_context;

encrypted_key_and_nonces = EncryptWithLabel(
  external_receiver_public_key,
  "SemiPrivateMessageReceiver",
  semi_private_message_context,   /* context */
  keys_and_nonces)

key_and_nonces = DecryptWithLabel(
  external_receiver_private_key,
  "SemiPrivateMessageReceiver",
  semi_private_message_context,  /* context */
  encrypted_keys_and_nonces.kem_output,
  encrypted_keys_and_nonces.ciphertext)
~~~

The `KeyForExternalReceiver` structure contains a hash of the
`ExternalReceiver` as a reference and the `encrypted_key_and_nonces`.

~~~ tls
ExternalReceiverRef = hash(ExternalReceiver)

struct {
  ExternalReceiverRef external_receiver_ref;
  HPKECiphertext encrypted_keys_and_nonces;
} KeyForExternalReceiver;
~~~

The `SemiPrivateMessage` struct extends the `PrivateMessage` struct, adding
the `keys_for_external_receivers` list, the `partial_context_hash` needed
for its decryption context, and the hash of the `FramedContentTBS` to insure
that the sender cannot encrypt content to the external receivers that is
different from the other members, without detection.

The `SemiPrivateContentAAD` struct likewise extends the `PrivateContentAAD`
struct, adding the `keys_for_external_receivers` list, the
`partial_context_hash` and the `framed_content_tbs_hash`.

The `SemiPrivateMessageContent` struct is the same as
`PrivateMessageContent` except application messages are not included.

~~~ tls
framed_content_tbs_hash = hash(FramedContentTBS)

struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    opaque partial_context_hash<V>;
    KeyForExternalReceiver keys_for_external_receivers<V>;
    opaque framed_content_tbs_hash<V>;
    opaque encrypted_sender_data<V>;
    opaque ciphertext<V>;
} SemiPrivateMessage;

struct {
    select (SemiPrivateMessage.content_type) {
        case proposal:
          Proposal proposal;
        case commit:
          Commit commit;
    };
    FramedContentAuthData auth;
    opaque padding[length_of_padding];
} SemiPrivateMessageContent;

struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    opaque partial_context_hash<V>;
    KeyForExternalReceiver keys_for_external_receivers<V>;
    opaque framed_content_tbs_hash<V>;
} SemiPrivateContentAAD;

/* IANA-registered value for semi_private_message */
extension_type = TBD2
SemiPrivateMessage extension_data;
~~~

Encryption of the `ciphertext` uses the cipher suite's AEAD algorithm using
the `key`, `nonce` xored with the `reuse_guard`, the
`SemiPrivateMessageContent` as the plaintext, and the
`SemiPrivateContentAAD` as the authenticated data.

Encryption of the `encrypted_sender_data` proceeds in the
same way for `SemiPrivateMessage` as for `PrivateMessage`.

Finally, as a safe wire format extension, the `SemiPrivateMessage` is
wrapped in an `ExtensionContent` struct.

## Decryption of SemiPrivateMessage as a member

After stripping off the the `ExtensionContent` struct, a member
receiver derives the `sender_data_key` and `sender_data_nonce` and decrypts the `encrypted_sender_data`, just as for a `PrivateMessage`.

The receiver uses the `SenderData` to lookup the `key` and `nonce` for
the correct `generation` in the (non-blank) sender's handshake ratchet.
The receiver verifies the `partial_context_hash`.

After xoring the `nonce` with the `reuse_guard`, the member decrypts the
`ciphertext`. It verifies the padding consists of the appropriate number of
zero bytes, and verifies that the `framed_content_tbs_hash` is correct.
Finally, it verifies that the signature in the FramedContentAuthData is
valid.

## Decryption of SemiPrivateMessage as an external receiver

After stripping off the the `ExtensionContent` struct, an external receiver
looks in the `keys_for_external_receivers` field for its
`external_receiver_ref`. It calculates the `semi_private_message_context`
and uses HPKE to decrypt the `encrypted_keys_and_nonces`. Using the `nonce`
and `sender_leaf_node` it verifies the `partial_context_hash`.

After xoring the `nonce` with the `reuse_guard`, the member decrypts the
`ciphertext`. It verifies the padding consists of the appropriate number of
zero bytes, and verifies that the `framed_content_tbs_hash` is correct.
If the external receiver has a copy of the `GroupContext`, it verifies that
the signature in the FramedContentAuthData is valid.

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

# Change log

## Changes from draft-mahy-mls-semiprivatemessage-03 to -04

- corrected a typo in SemiPrivateMessageContent

## Changes from draft-mahy-mls-semiprivatemessage-02 to -03

- do not attempt to decrypt `SenderData` for external receivers; instead also encrypt the `sender_leaf_index` and `reuse_guard`.
- make the `encrypted_key_and_nonces` context include the `group_id`, `epoch`, and a the hash of the `sender_leaf_index` and `nonce`. include that `partial_context_hash` in the AAD.
- add a hash of the FramedContentTBS to the AAD to make sure the content encrypted to the external receiver is the same as that sent to members.
- add explicit instructions about encryption and decryption.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
