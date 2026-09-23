# Symmetric encryption and packet protection

After each direction's `SSH_MSG_NEWKEYS`, every packet in that direction is
protected with symmetric keys derived from the key exchange. The
[binary-packet chapter](./binary-packets.md#packet-protection-families)
introduced the three protection families at the protocol level. This chapter
opens them up: what a cipher actually does, why encryption alone is not
enough, how each deployed construction binds packets together, and how the
Terrapin attack exploited state that none of them authenticated.

The key material itself comes from the
[SSH key derivation](./crypto-hashes.md#key-derivation-in-ssh): letters `A`
and `B` produce initial IVs, `C` and `D` encryption keys, and `E` and `F`
integrity keys, one of each per direction. How much of that material a
cipher consumes, and for what, is defined by the negotiated algorithm name.

## Ciphers as a black box

A symmetric cipher takes a secret key, a per-message value that must not
repeat (called a nonce, IV, or counter depending on the construction), and
plaintext. It outputs ciphertext of the same length. Decryption with the same
key and nonce inverts the transformation.

```mermaid
flowchart LR
    K["secret key"] --> E["ENCRYPT"]
    N["nonce / IV / counter<br/>(must not repeat)"] --> E
    P["plaintext"] --> E
    E --> C["ciphertext<br/>same length as plaintext"]
    C --> D["DECRYPT"]
    K2["same key"] --> D
    N2["same nonce"] --> D
    D --> P2["plaintext, or random-looking bytes<br/>if anything was changed<br/>(never an error)"]
```

What a cipher guarantees, given a secret key and a never-repeated nonce, is
**confidentiality**: an observer learns nothing about the plaintext beyond
its length. What it does *not* guarantee matters just as much:

- **No integrity.** Decryption has no failure output. Every ciphertext
  decrypts to *something*, and a receiver cannot tell modified ciphertext
  from the original by decrypting it.
- **No length hiding.** Ciphertext length tracks plaintext length. SSH padding
  blurs this only slightly.
- **No safety under nonce reuse.** Encrypting two messages with the same key
  and nonce breaks confidentiality for both, as shown below.

In SSH, the cipher is selected from the `encryption_algorithms` name-lists in
[`KEXINIT`](./version-and-negotiation.md#ssh_msg_kexinit-carries-proposals),
independently for each direction.

## Stream ciphers, block ciphers, and modes

A **stream cipher** generates a long pseudorandom *keystream* from the key and
nonce, and encryption is a byte-wise XOR (`⊕`) of that keystream with the
plaintext. ChaCha20 is a stream cipher.

A **block cipher** is a keyed permutation on fixed-size blocks. AES, specified
in [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), maps a 16-byte
input block to a 16-byte output block under a 128-, 192-, or 256-bit key.
Without the key, the mapping looks like a random shuffle of all 2¹²⁸ possible
blocks. A block cipher alone encrypts exactly one block; a **mode of
operation** says how to use it for longer messages.

SSH has used two block-cipher modes:

- **CTR (counter) mode**, names such as `aes128-ctr` and `aes256-ctr` from
  [RFC 4344](https://www.rfc-editor.org/rfc/rfc4344.html). AES encrypts
  successive counter values to make a keystream, turning the block cipher
  into a stream cipher. SSH's variant keeps one counter per direction that
  starts at the KDF-derived IV and continues across packets rather than
  restarting for each one.
- **CBC (cipher block chaining)**, names such as `aes128-cbc` and `3des-cbc`
  from RFC 4253. Each plaintext block is XORed with the previous ciphertext
  block before encryption. The chaining also continues across packets. CBC is
  legacy in SSH: current OpenSSH does not include any CBC cipher in its
  default [`Ciphers`](https://man.openbsd.org/ssh_config#Ciphers) list.

```mermaid
flowchart TB
    X0["counter X"] --> A0["AES with key K"]
    X1["X + 1"] --> A1["AES with key K"]
    X2["X + 2"] --> A2["AES with key K"]
    A0 --> S0["keystream block 1"]
    A1 --> S1["keystream block 2"]
    A2 --> S2["keystream block 3"]
    P0["plaintext block 1"] --> R0(("⊕"))
    S0 --> R0
    P1["plaintext block 2"] --> R1(("⊕"))
    S1 --> R1
    P2["plaintext block 3"] --> R2(("⊕"))
    S2 --> R2
    R0 --> C0["ciphertext block 1"]
    R1 --> C1["ciphertext block 2"]
    R2 --> C2["ciphertext block 3"]
```

Because the counter never repeats within one key's lifetime, no keystream
block is ever reused. That property is the whole security argument for CTR,
ChaCha20, and the CTR part of AES-GCM. The next deep dive shows why.

<details>
<summary>Go deeper: XOR, keystream reuse, and malleability</summary>

**XOR as encryption.** XOR (`⊕`) compares bits: the result is 1 where the
inputs differ and 0 where they agree. It is its own inverse, because
`x ⊕ k ⊕ k = x`. For one byte of `l` (`0x6c`) and keystream byte `0x3a`:

```text
  0110 1100   plaintext  0x6c ('l')
⊕ 0011 1010   keystream  0x3a
= 0101 0110   ciphertext 0x56
```

For whole messages, `C = P ⊕ KS` to encrypt and `P = C ⊕ KS` to decrypt.
If the keystream `KS` looks random and is never reused, the ciphertext reveals
nothing about `P` except its length.

**Keystream reuse.** Encrypt two commands with the *same* keystream:

```text
P1          6c 73 20 2d 6c 61   "ls -la"
P2          72 6d 20 2d 72 66   "rm -rf"
KS          3a 91 5c e7 08 6d   (reused!)
C1 = P1⊕KS  56 e2 7c ca 64 0c
C2 = P2⊕KS  48 fc 7c ca 7a 0b
C1 ⊕ C2     1e 1e 00 00 1e 07
P1 ⊕ P2     1e 1e 00 00 1e 07   identical
```

The keystream cancels: `C1 ⊕ C2 = P1 ⊕ P2`. An eavesdropper learns where the
two plaintexts agree (the `00` bytes) without knowing any key. If one
plaintext is guessed, XORing the guess into `C1 ⊕ C2` yields the other
plaintext exactly. This is why every SSH construction ties its nonce or
counter to something that cannot repeat under one key.

**Malleability.** Flipping a ciphertext bit flips the same plaintext bit after
decryption, and nothing in the cipher notices. Suppose an attacker knows or
guesses that a packet carries `ls\n`:

```text
P             6c 73 0a      "ls\n"
KS            9e 42 17
C             f2 31 1d
Δ = "ls\n" ⊕ "rm\n"  1e 1e 00
C' = C ⊕ Δ    ec 2f 1d
C' ⊕ KS       72 6d 0a      "rm\n"
```

The attacker changed the command without learning the key. A stream cipher
or CTR mode is *malleable* by design. The receiver needs a separate
integrity check computed with a key the attacker lacks; that is the job of a
[MAC](./crypto-hashes.md#message-authentication-codes) or an AEAD tag.

The toy uses six bytes of made-up keystream; real keystreams come from
ChaCha20 or AES and are unpredictable without the key. The arithmetic of
reuse and bit-flipping is exactly the same, however.

Try it yourself:
`python3 -c 'print(bytes(a^b for a,b in zip(bytes.fromhex("f2311d"),bytes.fromhex("1e1e00"))).hex())'`

Learn more:
[Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation),
[Stream cipher attacks](https://en.wikipedia.org/wiki/Stream_cipher_attacks),
[Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography)).

</details>

<details>
<summary>Go deeper: how CBC chains blocks</summary>

CBC encrypts block `i` as

```text
C_i = AES_K(P_i ⊕ C_(i−1))
```

and decrypts it as

```text
P_i = AES⁻¹_K(C_i) ⊕ C_(i−1)
```

where `C_0` is the IV. In SSH the "previous block" for the first block of a
packet is the last ciphertext block of the previous packet in the same
direction; RFC 4253 treats all packets in one direction as a single stream.

Two consequences matter to the protocol:

- **Predictable IVs.** Because the next packet's IV is the last ciphertext
  block already seen on the wire, an attacker who can influence plaintext
  knows the IV in advance. RFC 4344 cites this as a chosen-plaintext weakness
  of the original SSH CBC usage.
- **Self-synchronization.** Decrypting `P_i` needs only `C_i` and `C_(i−1)`.
  If a receiver uses the wrong previous block, only one block decrypts to
  garbage; the following blocks decrypt correctly. The Terrapin section below
  shows why that matters.

Learn more:
[Cipher block chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)),
[RFC 4344 section 1](https://www.rfc-editor.org/rfc/rfc4344#section-1).

</details>

## Three ways to combine encryption and integrity

Since ciphertext can be altered undetectably, every SSH packet carries an
integrity tag. The question is *what* the tag covers and *when* the receiver
checks it. An authenticated-encryption-with-associated-data (AEAD) algorithm
packages both jobs into one black box:

```mermaid
flowchart LR
    K["key"] --> SEAL["SEAL"]
    N["nonce"] --> SEAL
    AD["associated data<br/>(authenticated, not encrypted)"] --> SEAL
    P["plaintext"] --> SEAL
    SEAL --> CT["ciphertext ‖ tag"]
    CT --> OPEN["OPEN<br/>same key, nonce, AD"]
    OPEN --> Q{"tag valid?"}
    Q -->|yes| OK["plaintext"]
    Q -->|no| FAIL["failure only:<br/>no plaintext released"]
```

Unlike a bare cipher, `OPEN` has a failure result. SSH reached this shape in
three steps, each changing the order in which a receiver handles bytes:

- **Encrypt-and-MAC** (RFC 4253). The sender computes
  `MAC(key, seq ‖ plaintext packet)` and separately encrypts the whole packet,
  including `packet_length`. The receiver must decrypt the first block to learn
  how long the packet is before any integrity check is possible.
- **Encrypt-then-MAC** (`hmac-*-etm@openssh.com` MAC names, documented in
  [OpenSSH `PROTOCOL`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)).
  `packet_length` travels in the clear and the MAC covers
  `seq ‖ packet_length ‖ ciphertext`. The receiver verifies before decrypting
  anything.
- **AEAD** (`chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`,
  `aes256-gcm@openssh.com`). One algorithm defines encryption, tag, and
  length handling, and separate MAC negotiation is
  [skipped](./version-and-negotiation.md#the-selection-rule-client-preference-wins).

```mermaid
flowchart TB
    subgraph EAM["Encrypt-and-MAC"]
        direction LR
        a1["decrypt first block"] --> a2["use length<br/>(not yet authenticated)"]
        a2 --> a3["read and decrypt rest"]
        a3 --> a4{"MAC over<br/>seq ‖ plaintext OK?"}
        a4 -->|yes| a5["accept plaintext"]
    end
    subgraph ETM["Encrypt-then-MAC"]
        direction LR
        b1["read clear length"] --> b2["read ciphertext and MAC"]
        b2 --> b3{"MAC over seq ‖ length<br/>‖ ciphertext OK?"}
        b3 -->|yes| b4["decrypt"]
    end
    subgraph AEAD["AEAD"]
        direction LR
        c1["obtain length<br/>(clear, or separately<br/>decrypted)"] --> c2["read ciphertext and tag"]
        c2 --> c3{"OPEN succeeds?"}
        c3 -->|yes| c4["plaintext"]
    end
    EAM ~~~ ETM
    ETM ~~~ AEAD
```

| Construction | How the receiver learns the length | What the tag covers | Decrypts before verifying? |
| --- | --- | --- | --- |
| Encrypt-and-MAC | Decrypts the first cipher block | `seq ‖` plaintext packet | Yes, the whole packet |
| Encrypt-then-MAC | Reads it in the clear | `seq ‖ length ‖` ciphertext | No |
| AES-GCM | Reads it in the clear, as associated data | Length and ciphertext | No |
| ChaCha20-Poly1305 | Decrypts 4 bytes with a separate length key | Encrypted length and ciphertext | Only the length |

The encrypt-and-MAC order was not just inelegant. In 2009 Albrecht, Paterson,
and Watson ("Plaintext Recovery Attacks Against SSH", IEEE Symposium on
Security and Privacy) showed that with CBC mode an attacker could inject a
ciphertext block into the length position. By observing how the receiver
reacted to the decrypted but unauthenticated length (how many more bytes
it waited for before failing), the attacker learned some plaintext bits of
that block. The issue is tracked as
[CVE-2008-5161](https://nvd.nist.gov/vuln/detail/CVE-2008-5161).
[OpenSSH 5.2](https://www.openssh.com/txt/release-5.2) responded by preferring
CTR mode and by making failures look alike. Encrypt-then-MAC and AEAD remove
the underlying problem: data is not acted on before it is authenticated,
except for ChaCha20-Poly1305's separately keyed length, discussed next.

## ChaCha20-Poly1305

`chacha20-poly1305@openssh.com` is OpenSSH's AEAD construction built from
Daniel Bernstein's ChaCha20 stream cipher and Poly1305 one-time MAC. It is
being standardized under the name `chacha20-poly1305` in the
[IETF draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-chacha20-poly1305/),
which specifies it as identical to the deployed `@openssh.com` name. It is the
first entry in OpenSSH's default cipher list. It is **not** the same byte
layout as the ChaCha20-Poly1305 AEAD of
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) used in TLS; the
primitives are shared but the SSH construction differs.

Per the draft:

- The KDF supplies **64 bytes** of key material, split into two 256-bit keys.
  The draft calls the first half `K_1` and uses it for the packet body and the
  Poly1305 key. The second half, `K_2`, encrypts only the four-byte
  `packet_length`. (Older OpenSSH documentation labeled the halves the other
  way round; the byte positions are what matter.)
- The ChaCha20 **nonce is the packet sequence number**, encoded as a 64-bit
  big-endian integer. No IV is taken from the KDF.
- **Length:** `ChaCha20(K_2, seq, block counter 0)`, first 4 bytes, XORed into
  `packet_length`.
- **Poly1305 one-time key:** the first 32 bytes of
  `ChaCha20(K_1, seq, block counter 0)`.
- **Body:** `padding_length ‖ payload ‖ padding` XORed with
  `ChaCha20(K_1, seq)` starting at block counter 1.
- **Tag:** 16-byte Poly1305 over `encrypted length ‖ encrypted body`,
  appended to the packet. Offered MAC algorithms are ignored.

```mermaid
flowchart TB
    KM["64 bytes from the KDF"] --> K1["first 32 bytes: K_1"]
    KM --> K2["last 32 bytes: K_2"]
    SEQ["packet sequence number<br/>= ChaCha20 nonce"] --> LS
    SEQ --> MK
    SEQ --> BS
    K2 --> LS["ChaCha20 block 0<br/>length keystream"]
    K1 --> MK["ChaCha20 block 0<br/>first 32 bytes"]
    K1 --> BS["ChaCha20 blocks 1, 2, …<br/>body keystream"]
    LEN["packet_length"] --> X1(("⊕"))
    LS --> X1
    BODY["padding_length ‖ payload ‖ padding"] --> X2(("⊕"))
    BS --> X2
    X1 --> EL["encrypted length"]
    X2 --> EB["encrypted body"]
    MK --> PK["Poly1305 key (r, s)"]
    EL --> MAC["Poly1305"]
    EB --> MAC
    PK --> MAC
    MAC --> TAG["16-byte tag"]
```

A receiver decrypts the length with `K_2` as soon as four bytes arrive, waits
for the rest of the packet and the tag, verifies the tag in constant time,
and only then decrypts the body. The length is used before it is
authenticated, but because it has its own independent key, a length oracle
reveals nothing about the keystream that protects the body. The draft cites
this separation as a mitigation for the CVE-2008-5161 family.

Two protocol consequences follow from the sequence number being the nonce:

- **Every packet stands alone.** Nothing carries over from one packet's
  keystream to the next except the counter. The Terrapin section shows why
  that independence was dangerous.
- **The 32-bit sequence number must not wrap under one key.** A wrap would
  repeat a `(key, nonce)` pair. RFC 4344 already recommends rekeying before
  2³² packets; for this construction it is a hard requirement.

Appendix A of the draft walks through one packet byte by byte, from the
64-byte key to the final tag, and is worth reading alongside this section.

<details>
<summary>Go deeper: ChaCha20 as add-rotate-XOR</summary>

ChaCha20's state is a 4 × 4 grid of sixteen 32-bit words: four constants
(the ASCII string `expand 32-byte k`), eight key words, a 64-bit block
counter, and a 64-bit nonce. Twenty rounds scramble the grid, the original
grid is added back, and the 64-byte result is one keystream block.

Each round is built from a **quarter-round** on four words `a, b, c, d`. It
uses only three operations, all fast in software and free of secret-dependent
table lookups: addition modulo 2³² (`+`), XOR (`⊕`), and left rotation
(`<<<`). This design style is called ARX.

```text
a += b;  d ⊕= a;  d <<<= 16
c += d;  b ⊕= c;  b <<<= 12
a += b;  d ⊕= a;  d <<<= 8
c += d;  b ⊕= c;  b <<<= 7
```

The test vector from RFC 8439 section 2.1.1, in hexadecimal:

| Step | a | b | c | d |
| --- | --- | --- | --- | --- |
| input | `11111111` | `01020304` | `9b8d6f43` | `01234567` |
| after `a += b` | `12131415` | | | |
| after `d ⊕= a; d <<<= 16` | | | | `51721330` |
| after all four lines | `ea2a92f4` | `cb1cf8ce` | `4581472e` | `5881c4bb` |

Addition mixes bits upward through carries; XOR mixes without carries;
rotation moves bits between positions. Mixing the two kinds of arithmetic is
what makes the result hard to analyze. ChaCha20 applies eighty
quarter-rounds (twenty rounds of four). Each one is invertible, so the
rounds alone could be run backwards from output to input, key included.
Adding the original grid back at the end is what prevents that.

Learn more:
[RFC 8439 section 2](https://www.rfc-editor.org/rfc/rfc8439#section-2),
[Salsa20 and ChaCha](https://en.wikipedia.org/wiki/Salsa20).

</details>

<details>
<summary>Go deeper: Poly1305 as a polynomial</summary>

Poly1305 treats the message as the coefficients of a polynomial and evaluates
that polynomial at a secret point `r`, working modulo the prime
`p = 2¹³⁰ − 5`. Each 16-byte message block, with a `01` byte appended, is read
as a little-endian number `c_1, c_2, …, c_n`. Then:

```text
tag = ((c_1·r^n + c_2·r^(n−1) + … + c_n·r) mod p  +  s) mod 2¹²⁸
```

The one-time key is the pair `(r, s)`; a few bits of `r` are cleared first.
Implementations compute the polynomial with Horner's rule: start with
`A = 0` and for each block set `A = (A + c_i)·r mod p`.

**Toy version.** Use the small prime `p = 101`, `r = 37`, `s = 58`, and a
two-block message `c = (12, 34)`. Skip the final `mod 2¹²⁸` since the toy
values are already small:

```text
A = (0  + 12)·37 = 444  ≡ 40  (mod 101)
A = (40 + 34)·37 = 2738 ≡ 11  (mod 101)
tag = (11 + 58) mod 101 = 69
```

Check: `12·37² + 34·37 + 58 = 17 744 ≡ 69 (mod 101)`.

**Why the key must be one-time.** Take one-block messages, so
`tag = (c·r + s) mod p`. If the same `(r, s)` authenticates two messages:

```text
m1 = 20  →  t1 = (20·37 + 58) mod 101 = 91
m2 = 55  →  t2 = (55·37 + 58) mod 101 = 73
t1 − t2 ≡ (m1 − m2)·r      →  18 ≡ 66·r  (mod 101)
r = 18 · 66⁻¹ = 18 · 75 ≡ 37 (mod 101)
s = t1 − m1·r ≡ 58 (mod 101)
```

The attacker subtracts the two equations, `s` cancels, and simple modular
division reveals `r`, then `s`. With both, the attacker can compute a valid
tag for any message, for example `90 → 55`. Real Poly1305 has the same
algebra with longer polynomials. That is why SSH derives a fresh `(r, s)` for
every packet from ChaCha20 keyed by `K_1` with the sequence number as the
nonce.

The toy prime is small enough to try every `r` by hand. The real prime is
about 2¹³⁰, and Bernstein's analysis bounds a forger who does not know the
key to a success probability of at most `8·⌈ℓ/16⌉ / 2¹⁰⁶` per attempt on an
`ℓ`-byte message.

Try it yourself: `python3 -c 'print(18*pow(66,-1,101)%101)'`

Learn more:
[Poly1305](https://en.wikipedia.org/wiki/Poly1305),
[RFC 8439 section 2.5](https://www.rfc-editor.org/rfc/rfc8439#section-2.5),
[ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

</details>

## AES-GCM

`aes128-gcm@openssh.com` and `aes256-gcm@openssh.com` use AES in
Galois/Counter Mode, following the packet construction of
[RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html). OpenSSH and most
other implementations negotiate them differently from that RFC: the name
appears only in the encryption list and MAC negotiation is skipped. The
[negotiation chapter](./version-and-negotiation.md#the-selection-rule-client-preference-wins)
explains the difference and links the
[draft](https://datatracker.ietf.org/doc/draft-miller-sshm-aes-gcm/) that
standardizes it.

From RFC 5647 section 7:

- **Key:** 16 bytes (`aes128-gcm`) or 32 bytes (`aes256-gcm`) from the KDF
  encryption-key output. The KDF integrity key is not used.
- **Nonce:** the 12-byte KDF IV, split into a 4-byte fixed field and an 8-byte
  *invocation counter*. The counter is treated as a 64-bit integer and
  incremented after every packet.
- **Associated data:** the 4-byte `packet_length`, sent in the clear and
  authenticated but not encrypted.
- **Plaintext:** `padding_length ‖ payload ‖ padding`, padded to a multiple of
  16 bytes.
- **Tag:** the full 16 bytes; truncated tags are not allowed.

```mermaid
flowchart TB
    IV["12-byte IV from the KDF"] --> FX["fixed field<br/>4 bytes"]
    IV --> IC["invocation counter<br/>8 bytes, +1 per packet"]
    FX --> NON["this packet's nonce"]
    IC --> NON
    KEY["AES key<br/>16 or 32 bytes"] --> G["AES-GCM SEAL"]
    NON --> G
    LEN["packet_length<br/>in the clear"] -->|associated data| G
    PT["padding_length ‖ payload ‖ padding"] --> G
    G --> CT["ciphertext"]
    G --> TAG["16-byte tag"]
    LEN --> W["wire: length ‖ ciphertext ‖ tag"]
    CT --> W
    TAG --> W
```

The protocol-relevant difference from ChaCha20-Poly1305 is the nonce source.
GCM's nonce comes from its own counter, seeded by the KDF, not from the SSH
sequence number. In an undisturbed connection the two advance in lockstep. An
attacker who shifts the sequence number without shifting the invocation
counter just produces packets that fail authentication.

The price of sending the length in the clear is that a passive observer sees
exact SSH packet boundaries; see
[Length hiding and traffic analysis](#length-hiding-and-traffic-analysis).

<details>
<summary>Go deeper: GHASH, and why GCM nonce reuse is catastrophic</summary>

GCM is **CTR mode plus a polynomial MAC** called GHASH.

1. **Hash key.** `H = AES_K(0¹²⁸)`, the encryption of an all-zero block.
2. **Encryption.** With a 12-byte nonce `N`, the first counter block is
   `J_0 = N ‖ 00 00 00 01`. The plaintext is encrypted in CTR mode starting
   from the *next* counter block, `N ‖ 00 00 00 02`.
3. **GHASH.** The associated data, the ciphertext, and a final block holding
   both of their bit lengths are split into 16-byte blocks `X_1 … X_m` and
   evaluated as a polynomial at `H`:
   `GHASH = X_1·H^m ⊕ X_2·H^(m−1) ⊕ … ⊕ X_m·H`.
4. **Tag.** `T = GHASH ⊕ AES_K(J_0)`.

The arithmetic happens in GF(2¹²⁸), a field of 128-bit strings where
"addition" is XOR and multiplication is polynomial multiplication reduced by
`x¹²⁸ + x⁷ + x² + x + 1`. The structure is the same as Poly1305: a secret
evaluation point (`H` instead of `r`) and a one-time mask (`AES_K(J_0)`
instead of `s`).

The difference is that `H` stays fixed for the life of the key. Only the mask
depends on the nonce. That makes nonce reuse fatal twice over:

- **Confidentiality:** the same nonce gives the same CTR keystream, so
  `C1 ⊕ C2 = P1 ⊕ P2` as in the XOR deep dive.
- **Integrity:** with the same nonce, XORing two tags cancels the mask and
  leaves a polynomial in `H` whose coefficients the attacker knows from the
  ciphertexts. Solving it, as in the Poly1305 toy, narrows `H` to a small
  set of candidates. With `H` and one observed tag, the attacker recovers the
  mask for that nonce and can forge valid tags for altered ciphertexts.

SSH avoids this by deriving the nonce from a counter that increments on every
packet and by rekeying long before the 64-bit invocation counter could wrap.

Learn more:
[Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode),
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[RFC 5116](https://www.rfc-editor.org/rfc/rfc5116.html) (the AEAD interface).

</details>

## Comparing the common choices

| Name | Construction | Cipher key | Nonce or IV source | Tag | `packet_length` on the wire |
| --- | --- | --- | --- | --- | --- |
| `aes*-ctr` + `hmac-sha2-*` | CTR, encrypt-and-MAC | 16 or 32 bytes | KDF IV as initial counter, continuous across packets | HMAC | Encrypted |
| `aes*-ctr` + `hmac-sha2-*-etm@openssh.com` | CTR, encrypt-then-MAC | 16 or 32 bytes | Same as above | HMAC | Clear, covered by MAC |
| `aes*-cbc` + `*-etm@openssh.com` | CBC, encrypt-then-MAC | 16–32 bytes | KDF IV, then previous ciphertext block | MAC | Clear, covered by MAC |
| `aes*-gcm@openssh.com` | AEAD | 16 or 32 bytes | 12-byte KDF IV, invocation counter +1 per packet | 16 bytes | Clear, associated data |
| `chacha20-poly1305@openssh.com` | AEAD | 64 bytes | Packet sequence number | 16 bytes | Encrypted with a separate key, covered by tag |

HMAC key and tag sizes depend on the MAC name: `hmac-sha2-256` uses 32-byte
keys and tags, `hmac-sha2-512` 64-byte ones.

## Terrapin: when implicit state is not authenticated

Terrapin ([CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795);
Bäumer, Brinkmann, and Schwenk,
[terrapin-attack.com](https://terrapin-attack.com/)) is a *prefix-truncation*
attack. An active on-path attacker deletes the first protected packets in one
direction, and neither endpoint notices. The
[security chapter](./robustness-and-security.md#what-the-network-attacker-can-do)
places it among the network attacker's capabilities; this section shows the
cryptographic mechanism.

Two facts about the original protocol combine:

1. **Sequence numbers are implicit and survive `NEWKEYS`.** Each direction's
   counter starts at zero with the first *unprotected* packet and keeps
   counting into the protected phase. Every tag depends on it.
2. **The exchange hash does not cover every pre-key packet.** It covers the
   version strings, the `KEXINIT` payloads, and the key-exchange values, but
   not an `SSH_MSG_IGNORE` that arrives in between, and not the sequence-number
   state at `NEWKEYS`.

So an attacker can inject an unauthenticated `IGNORE` before keys are active,
advancing the receiver's counter by one, and later delete one protected packet
to bring the counter back into step:

```mermaid
sequenceDiagram
    participant C as Client
    participant A as On-path attacker
    participant S as Server
    S->>A: KEXINIT (server seq 0)
    A->>C: KEXINIT (client receive seq 0)
    A->>C: injected IGNORE (client receive seq 1)
    Note over C: Legal during KEX in the base protocol<br/>Counter is now one ahead
    S->>A: KEX reply (server seq 1)
    A->>C: KEX reply (client receive seq 2)
    S->>A: NEWKEYS (server seq 2)
    A->>C: NEWKEYS (client receive seq 3)
    Note over C,S: Server-to-client packets are now protected
    S->>A: EXT_INFO (server seq 3)
    Note over A: Deletes EXT_INFO
    S->>A: next packet (server seq 4)
    A->>C: next packet (client expects seq 4)
    Note over C: Sequence numbers agree again<br/>Tag verifies, EXT_INFO is never seen
```

Whether the forwarded packet actually verifies depends on how the construction
carries state from one protected packet to the next:

| Construction | What happens to the packet after the deleted one | Result |
| --- | --- | --- |
| ChaCha20-Poly1305 | Nonce is the sequence number, which matches again; each packet is keyed independently | Decrypts and verifies perfectly |
| CBC + encrypt-then-MAC | MAC over ciphertext verifies; CBC's wrong previous block garbles only the first block | Exploitable when that garbled block happens to be acceptable |
| CTR + encrypt-then-MAC | MAC verifies, but the continuous keystream is out of step, so the whole packet decrypts to random bytes | Not practically exploitable |
| Encrypt-and-MAC (any mode) | Decryption yields at least one random block, and the MAC over plaintext fails | Not affected |
| AES-GCM | The nonce counter counts only protected packets, so after the deletion the receiver's nonce is one behind and the tag fails | Not affected |

**Why a client cares.** The deleted packet is typically the server's
`SSH_MSG_EXT_INFO`, and its absence is indistinguishable from a server that
sends no extensions. The Terrapin authors showed this can:

- remove `server-sig-algs`, so the client may make a weaker or failing choice
  of [RSA signature algorithm](./user-authentication.md#discovering-acceptable-signature-algorithms)
  for user authentication; and
- remove `ping@openssh.com`, which OpenSSH 9.5's client needs before it sends
  the chaff packets of its
  [keystroke-timing obfuscation](#length-hiding-and-traffic-analysis),
  silently turning that defense off.

They also combined the truncation with implementation state-machine bugs in
one SSH library to achieve worse outcomes. The general lesson is that *any*
security decision based on "the peer did not send X" early in the protected
channel is weakened when X can be deleted.

**The fix.** [Strict KEX](./version-and-negotiation.md#strict-key-exchange)
attacks both facts above: it forbids unexpected messages such as `IGNORE`
during the initial exchange, and it resets each direction's sequence number to
zero at `NEWKEYS`, so pre-key packets can no longer influence protected-phase
state. The ChaCha20-Poly1305 draft requires implementations to support both
countermeasures. Strict KEX takes effect only when **both** peers support it;
a patched client talking to an unpatched server is still exposed with an
affected construction.

## Length hiding and traffic analysis

Encryption hides content, not shape. Whether an observer sees exact SSH packet
boundaries depends on the construction (see the last column of
[Comparing the common choices](#comparing-the-common-choices)):
encrypt-then-MAC and AES-GCM send `packet_length` in the clear, while
encrypt-and-MAC and ChaCha20-Poly1305 encrypt it.

Hiding the length field helps less than it seems. TCP segment sizes and
timing remain visible, and a single small packet in a quiet connection has an
obvious size. Random padding, up to 255 bytes, blurs sizes only a little. The
[binary-packet chapter](./binary-packets.md#the-base-packet-layout) notes that
padding is not traffic-flow confidentiality.

Timing is the larger leak for interactive sessions. Each keystroke in a
terminal typically produces one small packet, and inter-keystroke intervals
carry information about what is typed, as Song, Wagner, and Tian showed for
SSH in 2001. [OpenSSH 9.5](https://www.openssh.com/txt/release-9.5) added
client-side keystroke timing obfuscation, controlled by
[`ObscureKeystrokeTiming`](https://man.openbsd.org/ssh_config#ObscureKeystrokeTiming).
When enabled, and it is by default with a 20 ms interval, the client sends
interactive traffic at fixed intervals and continues sending fake keystroke
packets for a while after typing stops. As the Terrapin section shows, that
defense depends on an extension learned from `EXT_INFO`.

## Usage limits and rekeying

Keys wear out. Not because the key leaks, but because security bounds for
every construction degrade with the amount of data processed under one key.
SSH has three separate limits to respect:

- **Sequence-number space.** RFC 4344 section 3.1 recommends rekeying at
  least once every 2³² packets, because tags computed with the same 32-bit
  sequence number can collide and leak information. For ChaCha20-Poly1305,
  where the sequence number *is* the nonce, exceeding it would reuse a nonce.
- **Block-cipher birthday bound.** RFC 4344 section 3.2 recommends that for a
  block cipher with block length `L ≥ 128` bits, an implementation should not
  encrypt more than 2^(L/4) blocks before rekeying. For AES, `L = 128`, so
  the limit is 2³² blocks of 16 bytes: **64 GiB**. For 64-bit block ciphers
  such as 3DES and Blowfish the formula would require very frequent
  rekeying, and the RFC falls back to RFC 4253's once-per-gigabyte advice.
- **ChaCha20's stream limit.** The ChaCha20-Poly1305 draft notes a
  2⁷⁰-byte limit per `(key, nonce)`, far beyond any SSH packet, and defers
  to RFC 4253's 1 GB recommendation.

OpenSSH's [`RekeyLimit`](https://man.openbsd.org/ssh_config#RekeyLimit)
option sets a data volume and an optional time interval. By default the
volume depends on the cipher and time-based rekeying is off. In current
source, the default follows RFC 4344: rekey after 2³¹ packets in either
direction, after 2³² blocks (64 GiB) with AES, and after 1 GiB with ciphers
that OpenSSH treats as having 8-byte blocks, which include 3DES and
`chacha20-poly1305@openssh.com`.
The mechanics of a rekey, which renews the keys without disturbing the
session, are in
[Rekeying a live connection](./key-exchange.md#rekeying-a-live-connection).

<details>
<summary>Go deeper: birthday bounds for 64-bit and 128-bit blocks</summary>

**The birthday bound.** The
[hashes chapter](./crypto-hashes.md#the-exchange-hash-commits-to-the-transcript)
explains the birthday paradox. In one formula: drawing `n` random values
from `N` equally likely possibilities, the probability that at least two
coincide is

```text
P(collision) ≈ 1 − e^(−n²/2N)  ≈  n² / (2N)   when that is small
```

so collisions become likely around `n ≈ √N`.

**Why block ciphers care.** A block cipher is a permutation: under one key,
distinct inputs always give distinct outputs. In CBC mode the cipher inputs
behave like random blocks, so after about 2^(L/2) blocks two inputs collide.
The matching outputs then reveal the XOR of two plaintext blocks. CTR mode
never repeats an input, but its keystream *also never repeats a block*, and
that absence of collisions is itself a detectable deviation from true
randomness at the same scale.

Using `N = 2^L`, with `L` the block size in bits:

| Block size | Data under one key | Blocks `n` | Collision probability |
| ---: | ---: | ---: | ---: |
| 64 bits | 1 GiB | 2²⁷ | ≈ 2⁻¹¹ (1 in 2048) |
| 64 bits | 32 GiB | 2³² | ≈ 0.39 |
| 128 bits | 64 GiB | 2³² | ≈ 2⁻⁶⁵ |

For a 64-bit cipher, 32 GiB is enough to expect a collision. The
[Sweet32](https://sweet32.info/) attack turned this into practical plaintext
recovery against 3DES in TLS with around 785 GB of captured traffic. SSH's
`3des-cbc` and Blowfish ciphers have the same 64-bit block, which is one
reason they have been removed from modern defaults.

For AES, RFC 4344's 2^(L/4) limit keeps the collision probability around
2⁻⁶⁵. The birthday bound itself, 2⁶⁴ blocks, is 256 EiB of data.

Try it yourself: `python3 -c 'n=2**27; print(n*n/2**65)'`

Learn more:
[Birthday problem](https://en.wikipedia.org/wiki/Birthday_problem),
[RFC 4344 section 6.1](https://www.rfc-editor.org/rfc/rfc4344#section-6.1).

</details>

## Check your understanding

1. A receiver decrypts a CTR-mode packet and gets bytes that parse as a valid
   SSH message. Why is that not evidence that the packet is authentic?
2. Two packets were accidentally encrypted with the same keystream. What does
   an eavesdropper learn without the key?
3. Why does encrypt-and-MAC force the receiver to act on data before checking
   its integrity, and how does encrypt-then-MAC avoid that?
4. In `chacha20-poly1305@openssh.com`, which half of the 64-byte key material
   encrypts `packet_length`, and why is it a separate key?
5. Why must the Poly1305 key change for every packet, and what input makes it
   change?
6. An attacker injects one `IGNORE` before `NEWKEYS` and deletes the first
   protected server packet. Why does the next packet verify under
   ChaCha20-Poly1305 but fail under AES-GCM?
7. How much data may be encrypted under one `aes128-ctr` key according to
   RFC 4344, and why is the advice for `3des-cbc` so different?
8. Which constructions let a passive observer read `packet_length` directly?

<details>
<summary>Answers</summary>

1. Decryption has no failure result: any ciphertext decrypts to some bytes,
   and CTR is malleable, so a targeted bit flip yields a different valid-looking
   message. Only a verified MAC or AEAD tag establishes integrity.
2. The XOR of the two plaintexts. That reveals where they are equal, and if
   either plaintext is known or guessed, it reveals the other.
3. The length is encrypted with the packet and the MAC covers plaintext, so the
   receiver must decrypt the first block and use the unauthenticated length to
   find the packet's end. Encrypt-then-MAC sends the length in the clear and
   verifies a MAC over the ciphertext before decrypting anything.
4. The second 32 bytes (the draft's `K_2`). An independent key means that
   anything learned by manipulating the length reveals nothing about the body
   keystream.
5. Two tags under the same Poly1305 key `(r, s)` let an attacker solve for the
   key and forge tags. The key comes from ChaCha20 block 0 with the packet
   sequence number as nonce, so it differs for every packet.
6. ChaCha20-Poly1305 derives the nonce from the sequence number, which the
   injection and deletion have brought back into agreement. AES-GCM uses its
   own invocation counter, which counts only protected packets and is not
   moved by the unprotected `IGNORE`. After the deletion the receiver's nonce
   is one packet behind the sender's, so the tag fails.
7. At most 2³² blocks, 64 GiB, for a 128-bit block cipher. `3des-cbc` has
   64-bit blocks, so birthday collisions become likely after about 32 GiB;
   RFC 4344 falls back to rekeying at least every gigabyte.
8. Encrypt-then-MAC modes and AES-GCM.

</details>

## References

- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253.html),
  sections 6.3–6.4 (encryption, MAC, sequence numbers).
- [RFC 4344 — SSH Transport Layer Encryption Modes](https://www.rfc-editor.org/rfc/rfc4344.html)
  (CTR mode and rekeying limits).
- [RFC 5647 — AES Galois Counter Mode for the Secure Shell Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc5647.html)
  and the [revised AES-GCM negotiation draft](https://datatracker.ietf.org/doc/draft-miller-sshm-aes-gcm/).
- [SSH chacha20-poly1305 Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-chacha20-poly1305/),
  including its worked example in Appendix A.
- [OpenSSH `PROTOCOL`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL),
  section 1.5 (encrypt-then-MAC).
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html).
- [FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
  and [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- Bäumer, Brinkmann, Schwenk, [Terrapin Attack: Breaking SSH Channel Integrity
  By Sequence Number Manipulation](https://arxiv.org/abs/2312.12422), and
  [terrapin-attack.com](https://terrapin-attack.com/).
- Albrecht, Paterson, Watson, "Plaintext Recovery Attacks Against SSH", IEEE
  Symposium on Security and Privacy 2009.
- [Sweet32: Birthday attacks on 64-bit block ciphers](https://sweet32.info/).
