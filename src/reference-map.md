# Reference map

The SSH specifications are a family, not one linear document. Use this map to
find the authoritative field layout or behavior behind a guide explanation.

## Core documents

- [RFC 4251 — SSH Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251):
  layers, terminology, data types, algorithm naming, and security model.
- [RFC 4252 — SSH Authentication Protocol](https://www.rfc-editor.org/rfc/rfc4252):
  the `ssh-userauth` service and core authentication methods.
- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253):
  identification, packet framing, KEXINIT, original key exchanges, key
  derivation, service negotiation, and rekeying.
- [RFC 4254 — SSH Connection Protocol](https://www.rfc-editor.org/rfc/rfc4254):
  global requests, channels, flow control, sessions, and TCP forwarding.
- [RFC 4250 — SSH Protocol Assigned Numbers](https://www.rfc-editor.org/rfc/rfc4250)
  and the live
  [IANA SSH Protocol Parameters registries](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml):
  message numbers, disconnect reasons, service names, and algorithm names.

## Algorithms and extensions used in this guide

- [RFC 4419 — Diffie-Hellman Group Exchange](https://www.rfc-editor.org/rfc/rfc4419)
- [RFC 4344 — SSH Transport-Layer Encryption Modes](https://www.rfc-editor.org/rfc/rfc4344)
- [RFC 5656 — Elliptic Curve Algorithms for SSH](https://www.rfc-editor.org/rfc/rfc5656)
- [RFC 5647 — AES-GCM for SSH](https://www.rfc-editor.org/rfc/rfc5647)
- [RFC 6668 — SHA-2 Data Integrity Verification](https://www.rfc-editor.org/rfc/rfc6668)
- [RFC 8268 — SHA-2 with finite-field DH](https://www.rfc-editor.org/rfc/rfc8268)
- [RFC 8308 — Extension Negotiation](https://www.rfc-editor.org/rfc/rfc8308)
- [RFC 8332 — RSA Keys with SHA-2 Signatures](https://www.rfc-editor.org/rfc/rfc8332)
- [RFC 8709 — Ed25519 and Ed448 Host Keys](https://www.rfc-editor.org/rfc/rfc8709)
- [RFC 8731 — Curve25519 and Curve448 Key Exchange](https://www.rfc-editor.org/rfc/rfc8731)
- [RFC 9142 — Updated KEX Recommendations](https://www.rfc-editor.org/rfc/rfc9142)
- [RFC 9941 — Hybrid sntrup761/X25519 Key Exchange](https://www.rfc-editor.org/rfc/rfc9941)
- [RFC 10042 — ML-KEM Hybrid Key Exchange for SSH](https://www.rfc-editor.org/rfc/rfc10042)

## Authentication and key representation

- [RFC 4256 — Keyboard-Interactive Authentication](https://www.rfc-editor.org/rfc/rfc4256)
- [RFC 4716 — SSH Public Key File Format](https://www.rfc-editor.org/rfc/rfc4716)
- [RFC 6187 — X.509v3 Certificates for SSH](https://www.rfc-editor.org/rfc/rfc6187)

## Reading rules

Core RFCs are old enough that later documents update parts of them. Read the
“Updates” and “Updated by” metadata on the RFC Editor page, and separate three
questions:

1. Is the wire format assigned and understood?
2. Is the algorithm recommended for a new implementation today?
3. Is it allowed by this client's deployment policy?

Those answers can differ. IANA registration records interoperability names; it
does not by itself make an algorithm secure or appropriate.

The OpenSSH project also documents widely deployed extensions on its
[specifications page](https://www.openssh.com/specs.html). Treat an active
Internet-Draft or vendor extension as such until it is published as an RFC.
