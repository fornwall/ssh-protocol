# Glossary

Short definitions of terms that recur in this guide, grouped by first letter.
Each entry links to the section that explains the term in context.

## A

**AEAD** — Authenticated encryption with associated data: one algorithm that
encrypts and authenticates together, returning either verified plaintext or
failure. In SSH, an AEAD cipher replaces the separately negotiated MAC. See
[Three ways to combine encryption and integrity](./crypto-symmetric.md#three-ways-to-combine-encryption-and-integrity).

**AES-GCM** — The AES block cipher in Galois/Counter Mode, an AEAD mode
deployed in SSH as `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com`. See
[AES-GCM](./crypto-symmetric.md#aes-gcm).

**Agent forwarding** — Letting programs on the server use the client's
signing agent over agent channels, enabled by a session request. The remote
host gets a signing oracle, not private-key bytes. See
[Agent forwarding](./other-channels.md#agent-forwarding).

**Application string** — The `ssh:`-prefixed name, usually just `ssh:`, that
an `sk-` key is created for. It is part of the public key and is hashed into
every signature the authenticator makes. See
[Enrollment](./fido-security-keys.md#enrollment).

**Attestation** — A signature, made at enrollment by a key built into a FIDO
authenticator, showing that a new credential was created in genuine hardware.
OpenSSH discards it unless asked to save it. See
[Enrollment](./fido-security-keys.md#enrollment).

## B

**Banner** — `SSH_MSG_USERAUTH_BANNER`: server text, such as a legal notice,
shown before authentication completes. It needs no reply and is untrusted
display text. See
[Banners and other server text](./user-authentication.md#banners-and-other-server-text).

**Binary packet** — The SSH transport's framing unit: a length, a padding
length, one message payload, random padding, and, once keys are active, a MAC
or tag. See [The base packet layout](./binary-packets.md#the-base-packet-layout).

**Birthday bound** — Among about 2^(n/2) random n-bit values, two are likely to
coincide. It sets the collision resistance of an n-bit hash and the data limit
for one block-cipher key. See
[Hash functions as a black box](./crypto-hashes.md#hash-functions-as-a-black-box)
and [Usage limits and rekeying](./crypto-symmetric.md#usage-limits-and-rekeying).

## C

**Certificate** — In OpenSSH, a public key plus metadata such as principals
and a validity interval, signed by a certification authority (CA) key. Host
certificates let clients trust a CA instead of each host key; user
certificates do the same for servers. See
[Certificates](./crypto-signatures.md#certificates),
[Certification authority](./server-authentication.md#certification-authority),
and [User certificates](./user-authentication.md#user-certificates).

**ChaCha20-Poly1305** — An AEAD construction combining the ChaCha20 stream
cipher and the Poly1305 authenticator, deployed as
`chacha20-poly1305@openssh.com`. See
[ChaCha20-Poly1305](./crypto-symmetric.md#chacha20-poly1305).

**Channel** — One logical, flow-controlled byte stream inside the connection
protocol, such as a session or a forwarded TCP connection. Each peer names
the channel with its own local number. See
[Channels and flow control](./channels.md).

**Clamping** — Adjusting a few bits of a random X25519 private key so that it
is a multiple of 8 with a fixed top bit. This neutralizes small-order inputs
and gives every scalar the same length. See
[X25519](./crypto-key-agreement.md#x25519).

**Collision resistance** — The infeasibility of finding any two inputs with
the same hash digest. A signature over a digest is only as strong as this
property. See
[Hash functions as a black box](./crypto-hashes.md#hash-functions-as-a-black-box).

**Cookie** — The 16 random bytes at the start of every `KEXINIT` payload.
Because the payload is hashed into `H`, the cookies ensure neither side alone
can fully determine the keys and session identifier. See
[`SSH_MSG_KEXINIT` carries proposals](./version-and-negotiation.md#ssh_msg_kexinit-carries-proposals).

**credProtect** — A FIDO 2.1 extension that makes an authenticator require
user verification before a credential can be discovered or, at its strictest
level, used. OpenSSH sets it for resident and `verify-required` keys. See
[Resident and non-resident keys](./fido-security-keys.md#resident-and-non-resident-keys).

**CSPRNG** — Cryptographically secure pseudorandom number generator: a source
of bytes an attacker cannot predict. SSH needs one for cookies, ephemeral
private values, padding, and some signatures. See
[Randomness](./cryptography-primer.md#randomness).

## D

**Destination constraint** — An `ssh-add -h` restriction naming the hosts, and
forwarding hops, where an agent key may be used. The agent learns each hop's
host key through the `session-bind@openssh.com` extension. See
[Narrowing the delegation](./other-channels.md#narrowing-the-delegation).

**Diffie–Hellman (DH)** — Key agreement in which each side publishes a value
derived from a private secret, and both compute the same shared secret that an
observer cannot. See
[Diffie–Hellman as a black box](./crypto-key-agreement.md#diffiehellman-as-a-black-box).

**`direct-tcpip`** — The channel type a client opens to ask the server to
connect to a TCP target, used by local and dynamic forwarding. See
[Direct TCP channels](./forwarding.md#direct-tcp-channels).

**Disconnect reason code** — The number in `SSH_MSG_DISCONNECT`, registered in
RFC 4250. It is coarse evidence; the description text usually says more. See
[Read disconnects in context](./testing-and-debugging.md#read-disconnects-in-context).

**Discrete logarithm** — The problem of recovering a secret exponent `x` from
`g^x` in a group. Its presumed difficulty underlies classical Diffie–Hellman
and elliptic-curve key agreement. See
[Key agreement](./crypto-key-agreement.md).

**Downgrade attack** — An attempt to make the peers select a weaker algorithm
than both support, for example by editing `KEXINIT`. The signed exchange hash
detects this. See
[Algorithm negotiation and downgrade resistance](./robustness-and-security.md#algorithm-negotiation-and-downgrade-resistance).

## E

**ECDH** — Elliptic-curve Diffie–Hellman: Diffie–Hellman in an
elliptic-curve group, with shorter public values than finite-field DH. See
[Elliptic curves](./crypto-key-agreement.md#elliptic-curves) and
[Elliptic-curve Diffie–Hellman](./key-exchange-methods.md#elliptic-curve-diffiehellman).

**ECDSA** — The elliptic-curve digital signature algorithm, used by the
`ecdsa-sha2-nistp*` key types. See [ECDSA](./crypto-signatures.md#ecdsa).

**Ed25519** — An Edwards-curve signature scheme with deterministic signatures,
used by the `ssh-ed25519` key type. See
[Ed25519](./crypto-signatures.md#ed25519).

**Encrypt-and-MAC** — The original RFC 4253 packet protection: the MAC is
computed over the sequence number and plaintext packet, and sent unencrypted
beside the ciphertext. See
[Packet-protection families](./binary-packets.md#packet-protection-families).

**Encrypt-then-MAC (EtM)** — Packet protection in which the MAC covers the
ciphertext, so the receiver verifies before decrypting. OpenSSH names these
MACs with an `-etm@openssh.com` suffix. See
[Packet-protection families](./binary-packets.md#packet-protection-families).

**Ephemeral key** — A key pair generated for one key exchange and discarded
afterwards. Ephemeral keys provide forward secrecy. See
[The basic signed key-exchange flow](./key-exchange.md#the-basic-signed-key-exchange-flow).

**Exchange hash (`H`)** — The hash of the key-exchange transcript: both
identification strings, both `KEXINIT` payloads, the host key, the ephemeral
values, and the shared secret. The server signs it. See
[The exchange hash](./key-exchange.md#the-exchange-hash-authenticate-the-whole-decision).

**Extended data** — Channel data tagged with a type number; in sessions, type
1 carries standard error. It shares the channel's window with ordinary data.
See [Data and extended data](./sessions.md#data-and-extended-data).

**`EXT_INFO`** — The RFC 8308 message that carries extension name-value pairs,
such as `server-sig-algs`, after `NEWKEYS`. See
[Extension negotiation](./version-and-negotiation.md#extension-negotiation-with-ext-info-).

## F

**FIDO authenticator** — A hardware device, often called a security key, that
holds a private key and signs only after a local check such as a touch.
OpenSSH uses one through the `sk-` key types. See
[Hardware-backed security keys](./user-authentication.md#hardware-backed-security-keys)
and [FIDO security keys](./fido-security-keys.md).

**Fingerprint** — A short hash of a public-key blob, displayed for human
comparison, such as OpenSSH's `SHA256:` form. Compare the whole value. See
[Fingerprints](./crypto-hashes.md#fingerprints) and
[Fingerprints and key formats](./server-authentication.md#fingerprints-and-key-formats).

**Forward secrecy** — The property that later theft of a long-term key does
not reveal traffic from earlier connections, because traffic keys came from
discarded ephemeral secrets. See
[Forward secrecy](./crypto-key-agreement.md#forward-secrecy).

**`forwarded-tcpip`** — The channel type a server opens for each connection
accepted on a remote-forwarding listener. See
[Requesting a remote listener](./forwarding.md#requesting-a-remote-listener).

## G

**GHASH** — The polynomial authenticator inside AES-GCM, evaluated at a secret
point derived from the key. See [AES-GCM](./crypto-symmetric.md#aes-gcm).

**Grover's algorithm** — A quantum search algorithm that roughly halves the
bit strength of symmetric keys. It weakens, but does not break, AES and
SHA-2. See
[Why quantum computers matter](./crypto-post-quantum.md#why-quantum-computers-matter).

**`gssapi-with-mic`** — The RFC 4462 user-authentication method that runs a
GSS-API mechanism, usually Kerberos, and ends with an integrity check over
session-bound data. See
[Host-based and GSS-API authentication](./user-authentication.md#host-based-and-gss-api-authentication).

## H

**Harvest now, decrypt later** — Recording encrypted traffic today in the hope
of breaking its key exchange with a future quantum computer. Hybrid
post-quantum key exchange is the defense. See
[Why quantum computers matter](./crypto-post-quantum.md#why-quantum-computers-matter).

**Hash function** — A function mapping any input to a fixed-size digest, such
that finding two inputs with the same digest is infeasible. SSH uses SHA-2
hashes for `H`, key derivation, and MACs. See
[Hashes, MACs, and key derivation](./crypto-hashes.md).

**HMAC** — A standard way to build a MAC from a hash function, used by the
`hmac-sha2-*` MAC names. See
[Message authentication codes](./crypto-hashes.md#message-authentication-codes).

**Host key** — The server's long-term key pair. Its private half signs the
exchange hash; the client decides whether its public half is trusted for the
destination. See [Server authentication](./server-authentication.md).

**Host-based authentication** — The `hostbased` method: the client host signs
with its own host key, and the server trusts that host to vouch for the local
user name. See
[Host-based and GSS-API authentication](./user-authentication.md#host-based-and-gss-api-authentication).

**Host-bound authentication** — OpenSSH's
`publickey-hostbound-v00@openssh.com` method, which adds the server's host key
to the signed user-authentication data so an agent can restrict where a key
is used. See
[Host-bound public-key authentication](./user-authentication.md#host-bound-public-key-authentication).

**Host-key rotation** — OpenSSH's `hostkeys-00@openssh.com` extension: after
user authentication the server lists all its host keys, and the client records
new ones only after the server proves possession of each. Controlled by
`UpdateHostKeys`. See
[Host-key rotation](./server-authentication.md#host-key-rotation).

**Hybrid key exchange** — A key exchange that combines a post-quantum KEM with
classical ECDH, so the result stays secret if either component holds. RFC
10042 calls this a PQ/T hybrid. See
[Hybrid key exchange in SSH](./crypto-post-quantum.md#hybrid-key-exchange-in-ssh)
and [Hybrid post-quantum exchange](./key-exchange-methods.md#hybrid-post-quantum-exchange).

## I

**Identification string** — The `SSH-2.0-…` line each side sends first,
without its CR LF. It is later hashed into `H`. See
[The identification line](./identification.md#the-identification-line).

**Implicit rejection** — ML-KEM's response to a malformed ciphertext: it
returns a pseudorandom secret instead of an error, so the key exchange simply
fails later. See
[ML-KEM and Streamlined NTRU Prime](./crypto-post-quantum.md#ml-kem-and-streamlined-ntru-prime).

**Invalid-curve attack** — Sending a point that is not on the agreed curve so
the victim computes in a weak group and leaks its secret. Point validation, or
a curve design such as X25519's, prevents it. See
[Elliptic curves](./crypto-key-agreement.md#elliptic-curves).

## K

**KDF** — Key derivation function: turns the shared secret and exchange hash
into separate keys and IVs for each purpose and direction. See
[Key derivation in SSH](./crypto-hashes.md#key-derivation-in-ssh).

**Keepalive** — A request sent only to get a reply, proving the peer is still
processing messages. OpenSSH uses a global request for this. See
[Keepalives and evidence of liveness](./channels.md#keepalives-and-evidence-of-liveness).

**KEM** — Key-encapsulation mechanism: one side publishes a public key, the
other encapsulates a fresh secret into a ciphertext, and only the key holder
can decapsulate it. ML-KEM is one. See
[Key encapsulation as a black box](./crypto-post-quantum.md#key-encapsulation-as-a-black-box).

**`KEXINIT`** — `SSH_MSG_KEXINIT`, the message in which each peer lists its
supported algorithms in preference order and starts a key exchange. See
[Algorithm negotiation](./version-and-negotiation.md#ssh_msg_kexinit-carries-proposals).

**Key handle** — The credential identifier, stored in an `sk-` key's private
key file, that a FIDO authenticator needs in order to use the private key. It
is not itself secret key material. See
[Why the file on disk is not the secret](./fido-security-keys.md#why-the-file-on-disk-is-not-the-secret).

**Keyboard-interactive** — A user-authentication method in which the server
sends arbitrary prompts and the client returns answers. See
[Keyboard-interactive authentication](./user-authentication.md#keyboard-interactive-authentication).

**`known_hosts`** — OpenSSH's local database mapping host names to trusted
host keys or host CAs. See
[The `known_hosts` database](./server-authentication.md#the-known_hosts-database).

**KRL** — Key revocation list: OpenSSH's compact format for revoking keys,
certificate serial numbers, or key IDs, loaded with `RevokedKeys` or
`RevokedHostKeys`. See [Certificates](./crypto-signatures.md#certificates).

## L

**LWE** — Learning with errors: recovering a secret from linear equations
that each carry a small random error. Its presumed hardness, even for quantum
computers, underlies ML-KEM. See
[ML-KEM and Streamlined NTRU Prime](./crypto-post-quantum.md#ml-kem-and-streamlined-ntru-prime).

## M

**MAC** — Message authentication code: a tag computed with a secret key that
lets the receiver detect any change to a packet. See
[Message authentication codes](./crypto-hashes.md#message-authentication-codes).

**ML-KEM** — The module-lattice key-encapsulation mechanism standardized in
FIPS 203, used in the `mlkem*` hybrid key-exchange methods. See
[ML-KEM hybrids](./key-exchange-methods.md#ml-kem-hybrids) and
[Post-quantum key exchange](./crypto-post-quantum.md).

**`mpint`** — SSH's encoding of a signed integer as a length-prefixed,
minimal two's-complement byte string. See
[Why `mpint` is different](./binary-packets.md#why-mpint-is-different-from-an-arbitrary-string).

## N

**Name-list** — An SSH string containing comma-separated names, used for
algorithm proposals and method lists. See
[Integers, strings, and name-lists](./binary-packets.md#integers-strings-and-name-lists).

**`NEWKEYS`** — `SSH_MSG_NEWKEYS`, the message after which its sender uses the
newly derived keys for that direction. See
[Activating keys](./key-exchange.md#activating-keys-with-ssh_msg_newkeys).

**Nonce** — A value that must never repeat under the same key. SSH's AEAD
modes derive it from a counter or the packet sequence number. ECDSA also
needs a secret, never-repeated nonce for each signature. See
[Symmetric encryption and packet protection](./crypto-symmetric.md) and
[ECDSA](./crypto-signatures.md#ecdsa).

## P

**Partial success** — A flag in `SSH_MSG_USERAUTH_FAILURE` meaning the last
method succeeded but the server requires another. See
[The server drives policy](./user-authentication.md#the-server-drives-policy).

**Poly1305** — A one-time authenticator that evaluates the message as a
polynomial at a secret point; SSH's ChaCha20-Poly1305 derives a fresh
Poly1305 key for every packet. See
[ChaCha20-Poly1305](./crypto-symmetric.md#chacha20-poly1305).

**Pre-identification lines** — Text lines a server may send before its `SSH-`
line. They are unauthenticated, not part of the exchange hash, and distinct
from the authentication banner. See
[Server lines before identification](./identification.md#server-lines-before-identification).

**Principal** — A name, such as a user or host name, that a certificate is
valid for. See [User certificates](./user-authentication.md#user-certificates).

**PTY** — Pseudo-terminal: a server-side terminal device requested with
`pty-req`, which changes how input and output bytes are processed. See
[A PTY changes the byte-stream environment](./sessions.md#a-pty-changes-the-byte-stream-environment).

**Public-key authentication** — User authentication by signing
session-bound data with a private key whose public half the server
authorizes. See
[Public-key authentication](./user-authentication.md#public-key-authentication).

## R

**Rekey** — A new key exchange on a live connection that replaces traffic keys
but keeps the session identifier and authentication. See
[Rekeying a live connection](./key-exchange.md#rekeying-a-live-connection).

**Resident key** — An `sk-` key whose key handle is stored on the FIDO
authenticator, so it can be loaded on a new computer with the device and its
PIN. FIDO calls it a discoverable credential. See
[Resident and non-resident keys](./fido-security-keys.md#resident-and-non-resident-keys).

**RSA** — A signature scheme based on the difficulty of factoring. In SSH, one
`ssh-rsa` key can sign with `rsa-sha2-256` or `rsa-sha2-512`. See
[RSA](./crypto-signatures.md#rsa).

## S

**Security level** — The approximate work to break a primitive, in bits: an
n-bit level means about 2ⁿ operations. See
[What "secure" means for a black box](./cryptography-primer.md#what-secure-means-for-a-black-box).

**Sequence number** — A per-direction packet counter that is never sent but is
included in integrity checks. See
[Sequence numbers](./binary-packets.md#sequence-numbers).

**`server-sig-algs`** — An `EXT_INFO` extension listing the signature
algorithms the server accepts for public-key user authentication. See
[Discovering acceptable signature algorithms](./user-authentication.md#discovering-acceptable-signature-algorithms).

**Session channel** — A channel that runs one shell, command, or subsystem.
See [Sessions](./sessions.md).

**Session identifier** — The exchange hash from the first key exchange,
fixed for the life of the connection and signed in public-key user
authentication. See
[Session identifier versus exchange hash](./key-exchange.md#session-identifier-versus-exchange-hash).

**Shor's algorithm** — A quantum algorithm that factors integers and computes
discrete logarithms efficiently, breaking RSA, DH, ECDH, and classical
signatures on a large enough quantum computer. See
[Why quantum computers matter](./crypto-post-quantum.md#why-quantum-computers-matter).

**Signature** — A value only the private-key holder can produce, which anyone
with the public key can verify over a specific message. See
[Signatures as a black box](./crypto-signatures.md#signatures-as-a-black-box).

**Signing oracle** — Anything that returns signatures on caller-chosen data
without revealing the key, such as an agent, a hardware token, or a forwarded
agent. See [Hardware-backed keys](./crypto-signatures.md#hardware-backed-keys).

**SSHFP** — A DNS record publishing a digest of an SSH host key under the
host's name. A client may trust it only when DNSSEC authenticates the answer.
See [DNS fingerprints (SSHFP)](./server-authentication.md#dns-fingerprints-sshfp).

**Streamlocal forwarding** — OpenSSH's forwarding of Unix-domain sockets, using
the `direct-streamlocal@openssh.com` and `forwarded-streamlocal@openssh.com`
channel types. See
[Unix-domain socket forwarding](./other-channels.md#unix-domain-socket-forwarding).

**Strict KEX** — An extension that forbids unexpected messages during the
initial exchange and resets sequence numbers at each `NEWKEYS`, closing the
Terrapin gap. See
[Strict key exchange](./version-and-negotiation.md#strict-key-exchange).

**Subsystem** — A named service, such as `sftp`, started on a session channel
instead of a shell or command. See [Subsystems](./sessions.md#subsystems).

## T

**Terminal modes** — The opcode-and-value list in `pty-req` that sets the
remote terminal's line discipline, such as echo and the interrupt character.
See [A PTY changes the byte-stream environment](./sessions.md#a-pty-changes-the-byte-stream-environment).

**Terrapin** — A prefix-truncation attack published in 2023
(CVE-2023-48795) that manipulated sequence numbers during the handshake to
delete early protected packets undetected.
See
[Terrapin](./crypto-symmetric.md#terrapin-when-implicit-state-is-not-authenticated).

**TOFU** — Trust on first use: accepting and recording a host key on the first
connection, then requiring the same key afterwards. See
[Trust on first use](./server-authentication.md#trust-on-first-use).

## U

**User presence (UP)** — A FIDO flag, set by the authenticator and covered by
its signature, showing that someone touched the device for this operation.
OpenSSH servers require it by default. See
[What the server verifies](./fido-security-keys.md#what-the-server-verifies).

**User verification (UV)** — A FIDO flag showing that the authenticator also
checked the user, with a PIN or biometric. Servers require it only when
configured with `verify-required`. See
[What the server verifies](./fido-security-keys.md#what-the-server-verifies).

## W

**Window** — The per-channel, per-direction credit, in bytes, that a receiver
grants for channel data. See
[Windows and flow control](./channels.md#windows-and-flow-control).

## X

**X11 forwarding** — Carrying X11 connections from remote programs to the
client's display in `x11` channels, enabled by `x11-req`. The client replaces
a fake authentication cookie with the real one; OpenSSH's default untrusted
mode limits what remote clients can do. See
[X11 forwarding](./other-channels.md#x11-forwarding).

**X25519** — Diffie–Hellman on Curve25519 with 32-byte public values, used by
`curve25519-sha256` and the `x25519` hybrids. See
[X25519](./crypto-key-agreement.md#x25519).
