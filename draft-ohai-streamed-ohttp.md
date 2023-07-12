---
title: "Streamed Oblivious HTTP Messages"
abbrev: "Streamed OHTTP"
category: std

docname: draft-ohai-streamed-ohttp-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: ART
workgroup: OHAI Working Group
venue:
  group: OHAI
  type: Working Group
  mail: ohai@ietf.org

author:
 -
    fullname: Tommy Pauly
    organization: Apple
    email: tpauly@apple.com

--- abstract

This document defines a variant of the Oblivious HTTP message format that allows
chunks of requests and responses to be encrypted and decrypted before an entire
message is processed. This allows "streaming" of Oblivious HTTP messages, which
is particularly useful for handling very large messages or systems that process
messages slowly.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.ietf-ohai-ohttp}} defines a system for sending HTTP requests
and responses as encrypted messages. Clients send requests via a relay to a gateway, which
is able to decrypt and forward the request to a target server. Responses are encrypted
with an ephemeral symmetric key by the gateway and sent back to the client via the relay.
The messages are protected with Hybrid Public Key Encryption (HPKE; {{!HPKE=RFC9180}}),
and are intended to prevent the gateway from linking any two independent requests to the
same client.

The definition of Oblivious HTTP in {{OHTTP}} encrypts messages such that entire request
and response bodies need to be received before any of the content can be decrypted. This
is well-suited for many of the use cases of Oblivious HTTP, such as DNS queries or metrics
reporting.

However, some applications of Oblivious HTTP can benefit from being able to encrypt and
decrypt parts of the messages in chunks. If a request or response can be processed by a
receiver in separate parts, and is particularly large or will be generated slowly, then
sending a stream of encrypted chunks can improve the performance of applications.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Request Format {#request}

Streamed OHTTP requests start with key and algorithm IDs, followed by chunks of data
protected with HPKE. The final chunk is indicated with a length of 0, which means it
extends to the end of the outer stream.

~~~
Streamed Encapsulated Request {
  Key Identifier (8),
  HPKE KEM ID (16),
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
  Encapsulated KEM Shared Secret (8 * Nenc),
  HPKE-Protected Request Data (..),
}

HPKE-Protected Request Data {
  Non-Final Chunk (..),
  Final Chunk Indicator (i) = 0,
  HPKE-Protected Final Chunk (..),
}

Non-Final Chunk {
  Length (i) = 1..,
  HPKE-Protected Chunk (..),
}
~~~
{: #fig-enc-request title="Streamed Encapsulated Request Format"}

# Response Format {#response}

Streamed OHTTP responses start with a nonce, followed by chunks of data protected with
an AEAD. The final chunk is indicated with a length of 0, which means it extends to
the end of the outer stream.

~~~
Streamed Encapsulated Response{
  Nonce (Nk),
  AEAD-Protected Request Data (..),
}

AEAD-Protected Request Data {
  Non-Final Chunk (..),
  Final Chunk Indicator (i) = 0,
  AEAD-Protected Final Chunk (..),
}

Non-Final Chunk {
  Length (i) = 1..,
  AEAD-Protected Chunk (..),
}
~~~
{: #fig-enc-response title="Streamed Encapsulated Response Format"}

# Encapsulation of Chunks

The encapsulation of streamed Oblivious HTTP requests and responses uses
the same approach as the non-streamed variant, with the difference that
the body of requests and responses are sealed and opened in chunks, instead
of as a whole.

Besides the chunks being individually encrypted and authenticated, the chunks
protect two other pieces of information:

1. the order of the chunks (the sequence number of each chunk), which is
included in the nonce of each chunk.
1. which chunk is the final chunk, which is indicated by a sentinel in the AAD
of the final chunk.

The format of the outer packaging that carries the chunks (the length fields,
specifically) is not explicitly authenticated. AEADs already prevent truncation
attacks on individual chunks. This also allows the chunks to be transported with
different structures, and still be valid as long as the order and finality
are preserved.

## Request encapsulation

For requests, the setup of the HPKE context and the encrypted request header
is the same as the non-streamed variant.

~~~
hdr = concat(encode(1, key_id),
             encode(2, kem_id),
             encode(2, kdf_id),
             encode(2, aead_id))
info = concat(encode_str("message/bhttp request"),
              encode(1, 0),
              hdr)
enc, sctxt = SetupBaseS(pkR, info)
enc_request_hdr = concat(hdr, enc)
~~~

Each chunk is sealed using the HPKE context. For non-final chunks, the AAD
is empty. The final chunk in a request uses an AAD of the string "final".
HPKE already maintains a sequence number for sealing operations as part of
the context, so the order of chunks is protected.

~~~
sealed_chunk = sctxt.Seal("", chunk)
...
sealed_final_chunk = sctxt.Seal("final", final_chunk)
~~~

## Response encapsulation

For responses, the first piece of data sent back is the response nonce,
as in the non-streamed variant.

~~~
response_nonce = random(max(Nn, Nk))
~~~

Each chunk is sealed using the same AEAD key and AEAD nonce that are
derived for the non-streamed variant. The nonce additionally is XORed
with a counter to indicate the order of the chunks. For non-final chunks,
the AAD is empty. The final chunk in a response uses an AAD of the string
"final".

~~~
secret = context.Export("message/bhttp response", Nk)
response_nonce = random(max(Nn, Nk))
salt = concat(enc, response_nonce)
prk = Extract(salt, secret)
aead_key = Expand(prk, "key", Nk)
aead_nonce = Expand(prk, "nonce", Nn)

counter = 0

nonce = aead_nonce XOR encode(Nn, counter)
sealed_chunk = Seal(aead_key, nonce, "", chunk)
counter++
...
nonce = aead_nonce XOR encode(Nn, counter)
sealed_final_chunk = Seal(aead_key, nonce, "final", final_chunk)
~~~

# Security Considerations {#security}

TODO Security


# IANA Considerations

This document updates the "Media Types" registry at
<https://iana.org/assignments/media-types> to add the media types
"message/ohttp-streamed req" ({{iana-req}}), and
"message/ohttp-streamed-res" ({{iana-res}}), following the procedures of
{{!RFC6838}}.

## message/ohttp-streamed-req Media Type {#iana-req}

The "message/ohttp-streamed-req" identifies an encrypted binary HTTP request
that is transmitted using streamed chunks. This is a binary format that is
defined in {{request}}.

Type name:

: message

Subtype name:

: ohttp-streamed-req

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Oblivious HTTP and applications that use Oblivious HTTP use this media type to
  identify encapsulated binary HTTP requests sent in streamed chunks.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}


## message/ohttp-streamed-res Media Type {#iana-res}

The "message/ohttp-res" identifies an encrypted binary HTTP response
that is transmitted using streamed chunks. This is a binary format that
is defined in {{response}}.

Type name:

: message

Subtype name:

: ohttp-streamed-res

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Oblivious HTTP and applications that use Oblivious HTTP use this media type to
  identify encapsulated binary HTTP responses sent in streamed chunks.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
