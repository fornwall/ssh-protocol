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

- [RFC 4335 — Session Channel Break Extension](https://www.rfc-editor.org/rfc/rfc4335)
- [RFC 4419 — Diffie-Hellman Group Exchange](https://www.rfc-editor.org/rfc/rfc4419)
- [RFC 5656 — Elliptic Curve Algorithms for SSH](https://www.rfc-editor.org/rfc/rfc5656)
- [RFC 5647 — AES-GCM for SSH](https://www.rfc-editor.org/rfc/rfc5647)
- [RFC 6668 — SHA-2 Data Integrity Verification](https://www.rfc-editor.org/rfc/rfc6668)
- [RFC 8268 — SHA-2 with finite-field DH](https://www.rfc-editor.org/rfc/rfc8268)
- [RFC 8270 — 2048-bit Minimum for DH Group Exchange](https://www.rfc-editor.org/rfc/rfc8270)
- [RFC 8308 — Extension Negotiation](https://www.rfc-editor.org/rfc/rfc8308)
- [RFC 8332 — RSA Keys with SHA-2 Signatures](https://www.rfc-editor.org/rfc/rfc8332)
- [RFC 8709 — Ed25519 and Ed448 Public Key Algorithms](https://www.rfc-editor.org/rfc/rfc8709)
- [RFC 8731 — Curve25519 and Curve448 Key Exchange](https://www.rfc-editor.org/rfc/rfc8731)
- [RFC 9142 — Updated KEX Recommendations](https://www.rfc-editor.org/rfc/rfc9142)
- [RFC 9519 — Updated SSH Registry Requirements](https://www.rfc-editor.org/rfc/rfc9519)
- [RFC 9941 — Hybrid sntrup761/X25519 Key Exchange](https://www.rfc-editor.org/rfc/rfc9941)
- [RFC 10042 — ML-KEM Hybrid Key Exchange for SSH](https://www.rfc-editor.org/rfc/rfc10042)

## Authentication and key representation

- [RFC 4255 — SSHFP: Host-Key Fingerprints in DNS](https://www.rfc-editor.org/rfc/rfc4255),
  extended by [RFC 6594](https://www.rfc-editor.org/rfc/rfc6594) (SHA-256,
  ECDSA) and [RFC 7479](https://www.rfc-editor.org/rfc/rfc7479) (Ed25519).
- [RFC 4256 — Keyboard-Interactive Authentication](https://www.rfc-editor.org/rfc/rfc4256)
- [RFC 4462 — GSS-API Authentication and Key Exchange](https://www.rfc-editor.org/rfc/rfc4462):
  the `gssapi-with-mic` user-authentication method.
- [RFC 4716 — SSH Public Key File Format](https://www.rfc-editor.org/rfc/rfc4716)
- [RFC 6187 — X.509v3 Certificates for SSH](https://www.rfc-editor.org/rfc/rfc6187)
- [RFC 9987 — SSH Agent Protocol](https://www.rfc-editor.org/rfc/rfc9987):
  the protocol behind `ssh-agent`, including the standard `agent-req` and
  `agent-connect` forwarding names alongside OpenSSH's `auth-agent@openssh.com`.
- [OpenSSH `PROTOCOL.agent`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent)
  and [SSH agent restriction](https://www.openssh.com/agent-restrict.html):
  `session-bind@openssh.com` and destination-constrained agent keys.

## Deployed extensions and draft specifications

- [OpenSSH `PROTOCOL`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL):
  encrypt-then-MAC, delayed compression, forwarding extensions, and host-bound
  public-key authentication, with links to their specifications.
- [SSH certificate format draft](https://datatracker.ietf.org/doc/draft-miller-ssh-cert/):
  OpenSSH host and user certificates, formerly documented in OpenSSH's
  `PROTOCOL.certkeys`; this format is separate from RFC 6187's X.509 support.
- [ChaCha20-Poly1305 for SSH draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-chacha20-poly1305/):
  the `chacha20-poly1305@openssh.com` packet construction, formerly OpenSSH's
  `PROTOCOL.chacha20poly1305`.
- [OpenSSH `PROTOCOL.u2f`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f):
  `sk-` security-key formats and their signature encoding.
- [Strict KEX draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/02/):
  initial-exchange ordering and sequence-number resets that address Terrapin.
- [AES-GCM draft](https://datatracker.ietf.org/doc/draft-miller-sshm-aes-gcm/):
  documents the deployed negotiation rules that differ from RFC 5647.
- [Host-key update draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-hostkey-update/):
  learning replacement host keys through an authenticated connection.
- [SSH File Transfer Protocol, draft-ietf-secsh-filexfer-02](https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt):
  SFTP version 3, the subsystem OpenSSH implements.
- [X11 SECURITY extension](https://xorg.freedesktop.org/archive/X11R7.7/doc/xextproto/security.html):
  the untrusted-client restrictions behind OpenSSH's default X11 forwarding.
- [OpenSSH release notes](https://www.openssh.com/releasenotes.html) and
  [post-quantum cryptography page](https://www.openssh.com/pq.html): when
  algorithms, defaults, and warnings changed.
- [Terrapin attack paper](https://arxiv.org/abs/2312.12422) (CVE-2023-48795):
  the prefix-truncation attack that motivated strict KEX.

## Cryptographic primitives

SSH method names select these primitives; their own specifications define the
mathematics and test vectors.

- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final):
  SHA-1 and the SHA-2 family used in exchange hashes, key derivation, and MACs.
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104): the keyed-hash
  construction behind the `hmac-*` MAC names.
- [FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final):
  the AES block cipher.
- [RFC 4344 — SSH Transport-Layer Encryption Modes](https://www.rfc-editor.org/rfc/rfc4344):
  the `aes*-ctr` modes and rekeying guidance based on cipher block size.
- [NIST SP 800-38D — Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final):
  AES-GCM authenticated encryption.
- [RFC 5116 — An Interface and Algorithms for Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5116):
  the general AEAD interface.
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439):
  the stream cipher and one-time authenticator; SSH's construction differs
  from the RFC's AEAD mode in detail.
- [RFC 3526 — More MODP Diffie–Hellman Groups](https://www.rfc-editor.org/rfc/rfc3526):
  the 2048-bit and larger groups used by the `diffie-hellman-group*` methods.
- [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748):
  X25519 and X448.
- [FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final):
  ECDSA, EdDSA, and RSA signatures.
- [RFC 8017 — PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017): RSA and
  the PKCS #1 v1.5 signature encoding used by `rsa-sha2-*`.
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final):
  comparable security strengths of symmetric and public-key algorithms.
- [RFC 6979 — Deterministic DSA and ECDSA](https://www.rfc-editor.org/rfc/rfc6979):
  deriving the per-signature nonce without a random generator.
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032):
  Ed25519 and Ed448.
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final): the
  module-lattice KEM in the `mlkem*` hybrid methods.
- [NTRU Prime](https://ntruprime.cr.yp.to/): the Streamlined NTRU Prime KEM
  behind `sntrup761x25519-sha512`.
- [RFC 4086 — Randomness Requirements for Security](https://www.rfc-editor.org/rfc/rfc4086):
  why cookies, ephemeral secrets, and padding need a strong random source.

## Learning cryptography

These free resources go further than the guide's Go deeper sections:

- [*The Joy of Cryptography*](https://joyofcryptography.com/) by Mike
  Rosulek: an undergraduate textbook that builds security definitions
  step by step.
- [*A Graduate Course in Applied Cryptography*](https://toc.cryptobook.us/)
  by Dan Boneh and Victor Shoup: a thorough treatment of symmetric
  encryption, MACs, key exchange, and signatures.
- [*Crypto 101*](https://www.crypto101.io/): an introductory book aimed at
  programmers.
- [*Handbook of Applied Cryptography*](https://cacr.uwaterloo.ca/hac/): a
  classic 1996 reference whose chapters are freely available, including the
  number theory behind classical public-key algorithms.
- [*Understanding Cryptography*](https://www.crypto-textbook.com/) by Christof
  Paar and colleagues: the companion site links free lecture videos.
- [Dan Boneh's Cryptography I](https://www.coursera.org/learn/crypto): an
  online course from stream ciphers and MACs to basic key exchange.
- [A relatively easy to understand primer on elliptic curve cryptography](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/):
  an illustrated introduction to the curves used by ECDH and ECDSA.
- [The Cryptopals challenges](https://cryptopals.com/): exercises that break
  real constructions, useful for building intuition about misuse.

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
