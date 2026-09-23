# Hashes, MACs, and key derivation

Three of SSH's black boxes are closely related, and in SSH all three are
usually built from the same hash, such as SHA-256 or SHA-512:

- a **hash function** condenses any bytes into a short, fixed-size digest,
  with no secret involved;
- a **message authentication code** (MAC) uses a shared secret key to
  produce a tag that detects modification; and
- a **key derivation function** (KDF) turns one shared secret into many
  independent keys.

## Hash functions as a black box

```mermaid
flowchart LR
    M["Any number of bytes<br/>a transcript, a public key,<br/>a packet"] --> HASH["HASH<br/>public, no key"]
    HASH --> D["Fixed-size digest<br/>32 bytes for SHA-256<br/>64 bytes for SHA-512"]
```

```text
HASH(bytes) -> digest
```

A cryptographic hash is deterministic: the same input gives the same digest
on any machine, and a small change to the input gives an unrelated digest:

```text
SHA-256("ssh") = 7f5a55cf3f88be936fb9440249cb449f3067ccee4b525d0027dc9278a29c32c1
SHA-256("ssi") = 5eb50a4eaeac628268d07200700fad13e5e539f696a9d9483f57a6736197c6ec
```

The box has no failure result. What makes it *cryptographic* is that three
kinds of search are infeasible:

| Property | Attacker is given | Attacker must find | Generic cost, n-bit digest | SSH relies on it for |
| --- | --- | --- | --- | --- |
| Preimage resistance | a digest `d` | any `m` with `HASH(m) = d` | about 2ⁿ | derived keys not revealing `K`; one output of the KDF not revealing another |
| Second-preimage resistance | a specific input `m₁` | a different `m₂` with the same digest | about 2ⁿ | fingerprints: a fake key must match a *particular* real key's digest |
| Collision resistance | nothing; free choice | any pair `m₁ ≠ m₂` with the same digest | about 2^(n/2) | signatures over digests: exchange hash, certificates, `rsa-sha2-256` |

Collision resistance, where the attacker controls both inputs, is the first
property to fail as a hash ages: MD5 and SHA-1 have both lost practical
collision resistance, while no practical second-preimage attack is known for
either.

A hash does **not**:

- involve a secret, so an attacker who modifies the input can recompute the
  digest;
- authenticate anything by itself, since a digest sent over the same channel
  as the data can be replaced along with it; or
- hide low-entropy inputs: hashing a four-digit PIN leaves only 10,000
  candidates to try.

Authentication needs a key (a MAC) or a private key (a signature).

## Where SSH uses hashes

```mermaid
flowchart LR
    HASH["Negotiated HASH<br/>for example SHA-256"] --> EH["Exchange hash H<br/>commitment to the transcript"]
    HASH --> KDF["Key derivation<br/>six directional values"]
    HASH --> COMB["Hybrid combiner<br/>K = HASH(K_PQ ‖ K_CL)"]
    FP["SHA-256"] --> FING["Fingerprints<br/>for human comparison"]
    SH["Hash inside a signature scheme"] --> SIGS["rsa-sha2-256, ecdsa-sha2-nistp256,<br/>Ed25519 (SHA-512 internally)"]
    MH["Hash inside HMAC"] --> MAC["hmac-sha2-256, hmac-sha2-512"]
```

The key-exchange method fixes one hash, called `HASH` in the RFCs, for the
exchange hash, the key derivation
([RFC 4253, section 7.2](https://www.rfc-editor.org/rfc/rfc4253#section-7.2)),
and any hybrid combiner. The method name usually says which:

| KEX method | `HASH` | Digest size |
| --- | --- | ---: |
| `curve25519-sha256` | SHA-256 | 32 bytes |
| `ecdh-sha2-nistp384` | SHA-384 | 48 bytes |
| `mlkem768x25519-sha256` | SHA-256 | 32 bytes |
| `sntrup761x25519-sha512` | SHA-512 | 64 bytes |

The hashes inside signature and MAC names are separate choices: a
connection can use SHA-256 for its exchange hash, sign it with
`rsa-sha2-512`, and protect packets with `hmac-sha2-512`.

### The exchange hash commits to the transcript

The [exchange hash](./key-exchange.md#the-exchange-hash-authenticate-the-whole-decision)
`H` condenses the version strings, both `KEXINIT` payloads, the host key,
the ephemeral public values, and the shared secret `K`. As a hash, it is a
*commitment*: any change to any input gives a different `H`, so a client
that recomputes `H` from its own copy of the transcript detects tampering
once it verifies the server's signature over `H`.

Signing the digest rather than the transcript itself is called
*hash-then-sign*: the signature algorithm handles one short, fixed-size
input that covers the whole transcript. The price is that the signature is
only as trustworthy as the hash's collision resistance. If an attacker can
make two transcripts with the same `H`, a signature on one is a signature
on the other.

<details>
<summary>Go deeper: collisions, birthdays, and the retirement of SHA-1</summary>

**The birthday paradox.** In a room of 23 people, the chance that two share
a birthday is about 50.7%. That seems high because we instinctively compare
each person with *ourselves*—a second-preimage search—when the question is
about *any* of the 23·22/2 = 253 pairs.

An n-bit hash has 2ⁿ possible digests. After k random inputs there are
about k²/2 pairs, and a repeat becomes likely once k²/2 approaches 2ⁿ,
around

```text
k ≈ 2^(n/2)          (about 1.18 · 2^(n/2) for a 50% chance)
```

So a 256-bit hash offers about 128-bit collision resistance but about
256-bit second-preimage resistance.

**A toy you can run.** Truncate SHA-256 to its first 16 bits and hash the
strings `"0"`, `"1"`, `"2"`, … The inputs `"157"` and `"251"` collide on
`c75d` after only 252 tries, close to the expected 2⁸·√(π/2) ≈ 321. A
*second preimage* of `"ssh"` (truncated digest `7f5a`) takes until input
`"83647"`, roughly 2¹⁶ tries.

```text
python3 -c "import hashlib,itertools;s={};print(next((s[h],i) for i in itertools.count() if (h:=hashlib.sha256(str(i).encode()).digest()[:2]) in s or s.setdefault(h,i)<0))"
```

The toy only shows the square-root gap between the two searches.

**SHA-1's decline.** SHA-1 has a 160-bit digest, so its generic collision
cost is about 2⁸⁰. Cryptanalysis cut that far lower:

- In 2017, [SHAttered](https://shattered.io/) published the first SHA-1
  collision, two different PDF files with the same digest, after about 2⁶³
  SHA-1 computations.
- In 2020, [SHA-1 is a Shambles](https://sha-mbles.github.io/) produced a
  *chosen-prefix* collision: the attacker picks two different starting
  messages and then finds suffixes that make the digests equal. The authors
  built two PGP keys with different user IDs whose certificates collide, so
  one signature transfers between them, at an estimated cost of about
  USD 45,000.

Chosen-prefix collisions are the dangerous kind for signatures, because
both colliding messages can be meaningful. The
[OpenSSH 8.8 release notes](https://www.openssh.com/txt/release-8.8)
(September 2021) cite this attack when disabling the `ssh-rsa` (RSA with
SHA-1) signature algorithm by default. RSA *keys* still work, signing with
`rsa-sha2-256` or `rsa-sha2-512`; see [RSA](./crypto-signatures.md#rsa).

Learn more:

- [Wikipedia: Birthday problem](https://en.wikipedia.org/wiki/Birthday_problem)
  and [Birthday attack](https://en.wikipedia.org/wiki/Birthday_attack)
- [Wikipedia: Cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
  (SHA-1 and SHA-2)

</details>

## Fingerprints

A fingerprint is a short, human-comparable digest of a public key. OpenSSH
hashes the SSH public-key *blob*—the binary encoding sent in protocol
messages—with SHA-256 and displays the digest in base64 without `=`
padding, prefixed by the hash name.

```mermaid
flowchart LR
    B["Public-key blob<br/>string 'ssh-ed25519' + string key<br/>51 bytes for Ed25519"] --> HASH["SHA-256"]
    HASH --> D["32-byte digest"]
    D --> ENC["base64, no padding<br/>43 characters"]
    ENC --> FP["SHA256:X8vAg3tk...YnisK0Q"]
```

For a freshly generated Ed25519 key:

```text
$ ssh-keygen -lf demokey.pub
256 SHA256:X8vAg3tkZaJFhPVIjcDeOEf50Wnak3wGWVLWYnisK0Q demo (ED25519)

$ ssh-keygen -E md5 -lf demokey.pub
256 MD5:0c:d6:cc:6a:02:6a:36:1d:26:74:df:ca:6b:5d:de:e0 demo (ED25519)
```

The leading `256` is the key size in bits, followed by the fingerprint, the
comment, and the key type. The colon-separated MD5 hex form was OpenSSH's
default until version 6.8 (2015)
([release notes](https://www.openssh.com/txt/release-6.8)) and still
appears in old documentation and other tools. Compare fingerprints only when
they use the same hash.

OpenSSH can also draw a fingerprint as "randomart", a small ASCII picture
(`ssh-keygen -lv`, or `VisualHostKey yes` in
[`ssh_config`](https://man.archlinux.org/man/ssh_config.5#VisualHostKey)). It helps
notice a change at a glance, but does not replace comparing the text when
trust depends on it.

The fingerprint identifies the *key*, not the signature algorithm: an RSA
key has the same fingerprint whether it signs with `rsa-sha2-256` or
`rsa-sha2-512`. Nor does it say *which host* the key belongs to; that
binding is a trust decision, covered in
[Server authentication](./server-authentication.md#fingerprints-and-key-formats).

### Compare the whole fingerprint

People often check only the first and last few characters. An attacker who
wants a lookalike key need not break SHA-256: they generate key pairs until
one matches the characters people check. That is a second-preimage search
against the *checked part* only, at 6 bits per base64 character.

| Characters matched | Bits | Keys to try (expected) | Time at 10⁹ keys per second |
| ---: | ---: | ---: | --- |
| 4 | 24 | 1.7 × 10⁷ | about 0.02 seconds |
| 6 | 36 | 6.9 × 10¹⁰ | about 69 seconds |
| 8 | 48 | 2.8 × 10¹⁴ | about 3.3 days |
| 11 | 66 | 7.4 × 10¹⁹ | about 2,300 years |
| all 43 | 256 | 1.2 × 10⁷⁷ | infeasible |

Matching the first four and last four characters is about 46 bits, because
the final character carries only 4 bits (43 × 6 = 258, two more than the
digest has): under a day at the table's rate. Matching the full fingerprint
requires a real second preimage of SHA-256. Compare the entire string,
preferably by machine, for example by searching for the expected value or
letting `known_hosts` do the comparison.

## Message authentication codes

A MAC is a hash-like function with a secret key. Only key holders can
compute a valid tag, so a valid tag shows that the data came from a key
holder unmodified.

```text
MAC(key, data)            -> tag
VERIFY(key, data, tag)    -> valid | invalid
```

```mermaid
sequenceDiagram
    participant C as Client (holds key)
    participant N as Network attacker
    participant S as Server (holds key)
    C->>N: packet ‖ tag = MAC(key, seq ‖ packet)
    N->>S: packet' ‖ tag (one byte changed)
    S->>S: VERIFY(key, seq ‖ packet', tag)
    Note over S: invalid → discard the packet<br/>and end the connection
```

Unlike a signature, a MAC is symmetric: both endpoints hold the same key.
The server knows a valid tag came from the client only because it did not
make the tag itself, which directional keys guarantee. A MAC cannot convince
a third party, since either key holder could have made it, and it provides
no confidentiality.

### What an SSH MAC covers

In the base construction of
[RFC 4253, section 6.4](https://www.rfc-editor.org/rfc/rfc4253#section-6.4),
the sender computes, for every packet:

```text
mac = MAC(key, uint32 sequence_number || unencrypted_packet)
```

where `unencrypted_packet` is the length fields, payload, and padding. The
[sequence number](./binary-packets.md#sequence-numbers) is never sent; each
side counts packets in each direction. The `-etm@openssh.com` variants
cover the ciphertext instead, and AEAD modes produce their tag during
encryption; see
[Three ways to combine encryption and integrity](./crypto-symmetric.md#three-ways-to-combine-encryption-and-integrity).

The implicit sequence number turns a per-packet check into a check on the
*stream*:

| Attacker action | Why verification fails |
| --- | --- |
| Replay an earlier packet | Its tag was computed with an older sequence number. |
| Swap two packets | Each arrives at a position whose sequence number differs from the one it was tagged with. |
| Delete a packet | The next packet was tagged with a sequence number one higher than the receiver expects. |
| Reflect a packet back to its sender | The other direction uses a different MAC key. |

The sequence number authenticates only the order of packets that were
*counted*, so a gap between the signed handshake and the counter's starting
state is a weakness. The
[Terrapin attack](./crypto-symmetric.md#terrapin-when-implicit-state-is-not-authenticated)
exploited that gap, and
[strict key exchange](./version-and-negotiation.md#strict-key-exchange)
closes it.

### MAC algorithms in SSH

| Name | Construction | Tag / key size | Notes |
| --- | --- | --- | --- |
| `hmac-sha2-256` | HMAC with SHA-256 | 32 / 32 bytes | [RFC 6668](https://www.rfc-editor.org/rfc/rfc6668) |
| `hmac-sha2-512` | HMAC with SHA-512 | 64 / 64 bytes | [RFC 6668](https://www.rfc-editor.org/rfc/rfc6668) |
| `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` | Same HMACs | same | Encrypt-then-MAC packet layout ([OpenSSH `PROTOCOL`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)) |
| `umac-64@openssh.com`, `umac-128@openssh.com` | UMAC ([RFC 4418](https://www.rfc-editor.org/rfc/rfc4418)) | 8 or 16 / 16 bytes | Fast universal-hash MAC; `-etm` variants exist |
| `hmac-sha1` | HMAC with SHA-1 | 20 / 20 bytes | Required by RFC 4253; legacy today |

HMAC-SHA-1 is not broken the way SHA-1 signatures are, because HMAC's
security does not rest on collision resistance; it is retired as hygiene in
favor of SHA-2. When an AEAD cipher such as `chacha20-poly1305@openssh.com`
is selected, no separate MAC is negotiated for that direction; see
[Algorithm negotiation](./version-and-negotiation.md#the-selection-rule-client-preference-wins).

A receiver compares tags in constant time: an early-exit comparison would
leak, through timing, how many leading bytes of a forged tag were correct.

<details>
<summary>Go deeper: how HMAC works, and why not just HASH(key ‖ message)</summary>

**The obvious construction is broken.** It is tempting to define
`MAC(K, m) = HASH(K || m)`. SHA-1 and SHA-2 are *Merkle–Damgård* hashes:
they process the input in fixed-size blocks, carrying an internal state
from block to block, and for SHA-1, SHA-256, and SHA-512 the digest *is* the
final state. Anyone who knows `HASH(K || m)` can therefore keep hashing from
that state and compute `HASH(K || m || padding || m')` without learning
`K`: a *length-extension attack*.

**A toy.** Use a toy "hash" that reads one number per block and updates its
state as `s ← (s · 31 + block) mod 257`, starting from `s = 0`. Let the
secret key be the blocks `42, 7` and the message `3, 9`:

```text
s = 0
s = (0   · 31 + 42) mod 257 = 42
s = (42  · 31 + 7)  mod 257 = 24
s = (24  · 31 + 3)  mod 257 = 233
s = (233 · 31 + 9)  mod 257 = 36      ← tag = 36
```

An attacker who sees the tag 36 appends a block `5` without knowing the key:
`(36 · 31 + 5) mod 257 = 93`. Recomputing from scratch with the key gives
the same 93, so the forged message `3, 9, 5` carries a valid tag. The toy
omits real padding and has only 257 states, but the weakness is structural.

**HMAC's fix.** [HMAC](https://www.rfc-editor.org/rfc/rfc2104) hashes twice
with two derived keys:

```text
HMAC(K, m) = HASH( (K ⊕ opad) || HASH( (K ⊕ ipad) || m ) )

ipad = the byte 0x36 repeated to the hash's block size (64 bytes for SHA-256)
opad = the byte 0x5c repeated to the block size
K    = the key, zero-padded to the block size (hashed first if longer)
```

`⊕` is bitwise XOR. The inner hash may be extendable, but the attacker
cannot extend the outer hash without knowing `K ⊕ opad`. Bellare's 2006
proof shows that HMAC is a secure MAC mainly on the assumption that the
hash's compression function behaves like a pseudo-random function, without
needing collision resistance. That is why HMAC-SHA-1 stayed sound after
SHA-1 collisions appeared.

Learn more:

- [RFC 2104 — HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- [Wikipedia: HMAC](https://en.wikipedia.org/wiki/HMAC)
- [Wikipedia: Length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Wikipedia: Merkle–Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)
- Mihir Bellare,
  [New Proofs for NMAC and HMAC: Security Without Collision-Resistance](https://eprint.iacr.org/2006/043)

</details>

## Key derivation in SSH

[Key exchange](./key-exchange.md#from-k-and-h-to-traffic-keys) produces one
shared secret `K` and one exchange hash `H`, but packet protection needs up
to six values: an initial IV, an encryption key, and an integrity key for
each direction. The SSH KDF produces all six from the same inputs,
separated by a one-letter label:

```text
KDF(K, H, letter, session_id) -> as many key bytes as the algorithm needs
```

```mermaid
flowchart LR
    K["K<br/>shared secret"] --> KDF["SSH KDF<br/>using the KEX method's HASH"]
    H["H<br/>this exchange's hash"] --> KDF
    SID["session_id<br/>first exchange's H"] --> KDF
    KDF -->|"A"| A["Initial IV<br/>client → server"]
    KDF -->|"B"| B["Initial IV<br/>server → client"]
    KDF -->|"C"| C["Encryption key<br/>client → server"]
    KDF -->|"D"| D["Encryption key<br/>server → client"]
    KDF -->|"E"| E["Integrity key<br/>client → server"]
    KDF -->|"F"| F["Integrity key<br/>server → client"]
```

The client *sends* with A, C, and E and *receives* with B, D, and F; the
server does the opposite.

### The exact inputs

[RFC 4253, section 7.2](https://www.rfc-editor.org/rfc/rfc4253#section-7.2)
defines the first block of output for letter `X` as:

```text
K1 = HASH(K || H || X || session_id)
```

The encodings are part of the definition:

- `K` is an `mpint` for traditional DH and ECDH methods, but a `string` for
  the post-quantum hybrid methods; see
  [Hybrid post-quantum exchange](./key-exchange-methods.md#hybrid-post-quantum-exchange).
  The wrong encoding produces different, unusable keys.
- `H` is the raw digest bytes, with no length prefix.
- `X` is a single byte: ASCII `A` (65) through `F` (70).
- `session_id` is the raw first-exchange `H`, so it equals `H` until the
  first [rekey](./key-exchange.md#session-identifier-versus-exchange-hash).

### Expanding to the needed length

When one hash output is too short, the RFC hashes again, feeding back
everything produced so far:

```mermaid
flowchart LR
    IN1["K ‖ H ‖ X ‖ session_id"] --> H1["HASH"] --> K1["K1"]
    K1 --> IN2["K ‖ H ‖ K1"]
    IN2 --> H2["HASH"] --> K2["K2"]
    K1 --> IN3["K ‖ H ‖ K1 ‖ K2"]
    K2 --> IN3
    IN3 --> H3["HASH"] --> K3["K3"]
    K1 --> OUT["key = first N bytes of<br/>K1 ‖ K2 ‖ K3 ‖ ..."]
    K2 --> OUT
    K3 --> OUT
```

```text
K1 = HASH(K || H || X || session_id)
K2 = HASH(K || H || K1)
K3 = HASH(K || H || K1 || K2)
...
key = K1 || K2 || K3 || ...   truncated to the length needed
```

Only `K1` contains the letter and the session identifier; later blocks
inherit the separation by chaining from `K1`. Key bytes are taken from the
beginning.

### Worked example: how much is needed

Each negotiated algorithm fixes how many bytes it takes from each letter.
With a 32-byte SHA-256 `HASH`:

| Packet protection | IV (A, B) | Encryption key (C, D) | Integrity key (E, F) | Blocks per letter |
| --- | ---: | ---: | ---: | --- |
| `chacha20-poly1305@openssh.com` | unused | 64 bytes | unused | C, D need `K1 ‖ K2` |
| `aes128-gcm@openssh.com` | 12 bytes | 16 bytes | unused | one block each |
| `aes256-gcm@openssh.com` | 12 bytes | 32 bytes | unused | one block each |
| `aes128-ctr` + `hmac-sha2-256-etm@openssh.com` | 16 bytes | 16 bytes | 32 bytes | one block each |
| `aes256-ctr` + `hmac-sha2-512-etm@openssh.com` | 16 bytes | 32 bytes | 64 bytes | E, F need `K1 ‖ K2` |

`chacha20-poly1305@openssh.com` takes two 32-byte ChaCha20 keys, one for
the payload and one for the packet length; with a SHA-512 method such as
`sntrup761x25519-sha512`, `K1` alone suffices. It uses the sequence number
as its nonce, and AEAD modes produce their own tag, so those letters go
unused. The derivation itself is unchanged: OpenSSH, for example, still
derives all six values at one common length. See
[ChaCha20-Poly1305](./crypto-symmetric.md#chacha20-poly1305) and
[AES-GCM](./crypto-symmetric.md#aes-gcm) for how the values are used.

The calculator below runs the derivation with real SHA-256. It starts from
the toy inputs used under "why derive separate keys" below, `K = 5` and `H`
= 32 bytes of `0x11`: pick a row of the table to see which letters need a
second block, select a letter to see exactly which bytes are hashed, and
switch to "After a rekey" to see every value change while `session_id`
stays the same.

<div class="ssh-widget" data-widget="kdf">
<p class="w-fallback">Interactive figure: an SSH key-derivation calculator
that derives the six values A–F from K, H, and session_id with SHA-256,
shows the bytes hashed for each block, and simulates a rekey. It needs
JavaScript; the toy example below lists the same values.</p>
</div>

<details>
<summary>Go deeper: why derive separate keys at all</summary>

**Key separation.** A single secret should serve a single purpose. If both
directions used the same stream-cipher key, they would share a keystream:
XOR-ing the two ciphertexts would cancel it and leave the XOR of two
plaintexts, a classic break. With a shared MAC key, an attacker could
reflect a client's packet back to the client and it would verify. Six
independent values rule out such cross-purpose attacks without analyzing
each one.

**Domain separation.** The letters make that independence cheap. A good
hash behaves like a random function, so inputs that differ in one byte give
unrelated outputs. A toy run with `K = 5` (the `mpint` bytes
`00 00 00 01 05`), `H` = 32 bytes of `0x11`, and `session_id = H` gives
these first 8 bytes of each `K1`:

```text
A  9f99cfe72d65d414
B  6a478aa920f6ea0e
C  73246b38d48df1bc
D  1007efa4e0b2d5a9
E  aad006897deca4de
F  d28555f00601d096
```

The C chain continues with `K2` beginning `f098ea134e42da66`. Learning one
direction's key from another's would require inverting the hash. With
`K = 5`, of course, anyone could redo the calculation; a real `K` has at
least 128 bits of entropy.

**The modern general pattern.** SSH's KDF predates
[HKDF (RFC 5869)](https://www.rfc-editor.org/rfc/rfc5869), which formalizes
the same idea in two steps: *extract* a uniformly random key from an uneven
secret, then *expand* it with a context label into as many keys as needed.
SSH's KDF folds both steps into one chained hash; it is not HKDF. RFC 4253
notes that it loses entropy if `K` holds more than the hash's internal
state, a non-issue for SHA-256 and SHA-512 at today's key sizes.

Learn more:

- [RFC 4253, section 7.2](https://www.rfc-editor.org/rfc/rfc4253#section-7.2)
- [RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869)
- [Wikipedia: Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function)

</details>

## Check your understanding

1. Why can a hash of the transcript not, by itself, authenticate the
   transcript?
2. Which hash property must hold for a fingerprint to be safe to compare,
   and which for a signature over the exchange hash?
3. Why does SHA-256 give about 128-bit collision resistance rather than
   256-bit?
4. A user checks only the first eight characters of a `SHA256:` fingerprint.
   Roughly how much work must an attacker do to produce a lookalike key?
5. Why is the sequence number included in the MAC input even though it is
   never transmitted?
6. With `curve25519-sha256` and `chacha20-poly1305@openssh.com`, how many
   hash blocks does the client-to-server encryption key need, and which
   letters are unused?
7. After a rekey, which of the KDF inputs change?

<details>
<summary>Answers</summary>

1. A hash has no secret. An attacker who alters the transcript can
   recompute its hash. Only a signature (or a MAC under a shared key) binds
   the digest to a key holder.
2. A fingerprint needs second-preimage resistance: the attacker must match
   one specific key's digest. A signature over a digest needs collision
   resistance, because an attacker who controls both inputs could have one
   signed and use the signature for the other.
3. The birthday bound: among about 2¹²⁸ random inputs, two are likely to
   share a 256-bit digest.
4. Eight base64 characters are 48 bits, so about 2⁴⁸ ≈ 2.8 × 10¹⁴ key
   generations—days of work for a well-resourced attacker.
5. It binds each packet to its position in the stream, so replayed,
   reordered, or deleted packets fail verification. Both sides count packets
   independently, so it need not be sent.
6. Two blocks, `K1 ‖ K2`, because the cipher needs 64 bytes and SHA-256
   gives 32. The IV letters A and B and the integrity letters E and F are
   unused.
7. `K` and `H` change; `session_id` stays the first exchange's hash.

</details>

## References

- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253),
  section 6.4 (data integrity) and section 7.2 (key derivation).
- [RFC 6668 — SHA-2 Data Integrity Verification for SSH](https://www.rfc-editor.org/rfc/rfc6668).
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104).
- [RFC 4418 — UMAC](https://www.rfc-editor.org/rfc/rfc4418).
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869).
- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
- [OpenSSH `PROTOCOL`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
  (encrypt-then-MAC, UMAC, AEAD modes).
- [OpenSSH 8.8 release notes](https://www.openssh.com/txt/release-8.8)
  (RSA/SHA-1 signatures disabled by default) and
  [OpenSSH 6.8 release notes](https://www.openssh.com/txt/release-6.8)
  (SHA-256 fingerprints).
- [`ssh-keygen(1)`](https://man.archlinux.org/man/ssh-keygen.1) — `-l`, `-E`, and
  `-v` for fingerprints and randomart.
- [SHAttered](https://shattered.io/) and
  [SHA-1 is a Shambles](https://sha-mbles.github.io/).
