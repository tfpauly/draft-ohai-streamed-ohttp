---
title: "Streamed Oblivious HTTP Messages"
abbrev: "Streamed OHTTP"
category: std

docname: draft-ohai-streamed-http-latest
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
{: #fig-enc-request title="Streamed Encapsulated Response Format"}

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
