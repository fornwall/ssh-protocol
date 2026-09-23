# Post-quantum key exchange

The key agreement in
[Key agreement: Diffie–Hellman and elliptic curves](./crypto-key-agreement.md)
assumes that discrete logarithms are infeasible to compute. A large enough
quantum computer would break that assumption, and with it the secrecy of SSH
traffic recorded *today*. SSH's answer is hybrid key exchange: classical
Diffie–Hellman plus a post-quantum key-encapsulation mechanism (KEM).

## Why quantum computers matter

A quantum computer is not a faster ordinary computer: it speeds up certain
problems dramatically and most others not at all. Two quantum algorithms
matter for SSH:

| Algorithm | What it does | Affected SSH cryptography | Effect |
| --- | --- | --- | --- |
| Shor's algorithm | Factors integers and computes discrete logarithms efficiently | RSA, finite-field DH, ECDH, X25519, ECDSA, Ed25519 | Broken outright |
| Grover's algorithm | Speeds up brute-force search quadratically | AES, ChaCha20, SHA-2, MACs | Security margin reduced, not broken |

Shor's algorithm makes factoring and discrete logarithms tractable for a
large, reliable quantum computer, and larger keys do not meaningfully help.
Every classical SSH key-exchange method and signature algorithm depends on
one of these problems.

Grover's algorithm is far weaker. Searching `2^n` keys takes about `2^(n/2)`
quantum steps, which must largely run one after another, so parallel search
gains much less than it does classically. NIST's post-quantum security
categories are benchmarked against key search on AES-128, AES-192, and
AES-256; 256-bit keys leave a wide margin, and AES-128 is still generally
considered adequate. The symmetric parts of SSH are not the urgent problem.

No quantum computer can yet run Shor's algorithm at cryptographic sizes, and
estimates of when one might vary widely. The urgency comes from elsewhere.

### Harvest now, decrypt later

The confidentiality of an SSH session depends entirely on the shared secret
`K`. An attacker need not break the key exchange while the connection is
open. It can record the handshake and the encrypted traffic now and compute
`K` later:

```mermaid
timeline
    title Harvest now, decrypt later
    Today : Client and server run curve25519-sha256
          : Attacker records the public values Q_C and Q_S
          : Attacker records all encrypted packets
    Years later : A cryptographically relevant quantum computer exists
                : Shor's algorithm recovers a private scalar from Q_C or Q_S
                : Attacker recomputes K, H, and every traffic key
                : Recorded commands, output, files, and typed passwords are exposed
```

[Forward secrecy](./crypto-key-agreement.md#forward-secrecy) does not help.
It protects against a *stolen* key, but Shor's algorithm steals nothing: it
derives the ephemeral private value directly from the recorded public value.

### Why SSH changed key exchange first

Authentication is different. A host-key or user signature proves something
to a peer *during* the handshake. Forging one later is useless: the attacker
cannot go back and impersonate the server in a connection that is already
over.

| Protection | When an attacker must break it | Recorded traffic at risk today? |
| --- | --- | --- |
| Session confidentiality (key exchange) | Any time after recording | **Yes** |
| Server authentication (host-key signature) | While the victim's connection is being set up | No |
| User authentication (user signature) | While the victim's connection is being set up | No |

Long-lived host and user keys must be replaced before a capable quantum
computer exists, but recorded sessions cannot be protected retroactively.
That asymmetry is why SSH deployed post-quantum key exchange first and treats
post-quantum signatures as a later, separate migration.

<details>
<summary>Go deeper: what Shor's algorithm finds</summary>

Shor's algorithm finds the *period* of a repeating function. Classical
computers cannot do this efficiently for huge periods; a quantum computer can,
using the quantum Fourier transform.

**Periods break factoring.** Take `N = 15` and the number 7. Its powers
mod 15 repeat with period 4:

```text
k             1   2   3   4   5   6   7   8
7^k mod 15    7   4  13   1   7   4  13   1
```

Since `7^4 ≡ 1`, the number `7^2 = 49 ≡ 4` satisfies `4² ≡ 1 (mod 15)`, so
`15` divides `(4 − 1)(4 + 1) = 3·5`. Taking `gcd(4 − 1, 15) = 3` and
`gcd(4 + 1, 15) = 5` recovers the factors. For a 2048-bit RSA modulus `N`,
no classical method can find such a period in any reasonable time.

**Periods break discrete logarithms.** In the
[toy Diffie–Hellman group](./crypto-key-agreement.md), the powers of 5 mod 23
repeat every 22 steps. Given `A = 5^a mod 23`, the two-input function
`f(x, y) = 5^x · A^y mod 23` repeats along a direction that depends on `a`,
so finding that hidden period reveals `a`. The elliptic-curve version works
the same way with point addition in place of multiplication.

The toy numbers are trivial by hand; the point is that Shor's algorithm finds
the period in time polynomial in the number of bits, not exponential.

Learn more:
[Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm),
[Grover's algorithm](https://en.wikipedia.org/wiki/Grover%27s_algorithm),
[Post-quantum cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography),
[OpenSSH: Post-Quantum Cryptography](https://www.openssh.com/pq.html).

</details>

## Key encapsulation as a black box

Post-quantum key establishment is standardized as a *key-encapsulation
mechanism* (KEM) rather than as Diffie–Hellman. A KEM has three operations:

```text
KEYGEN()          -> public key pk, secret key sk
ENCAPS(pk)        -> ciphertext ct, shared secret ss
DECAPS(sk, ct)    -> shared secret ss
```

`ENCAPS` generates a fresh random secret and "locks" it with the public key;
only the holder of `sk` can unlock it with `DECAPS`. Unlike Diffie–Hellman,
the roles are **asymmetric**: only the client generates a key pair, and the
server encapsulates to it and returns a ciphertext:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    Note over C: KEYGEN → pk, sk (fresh per connection)
    C->>S: Public key pk
    Note over S: Check pk<br/>ENCAPS(pk) → ct, ss
    S->>C: Ciphertext ct
    Note over C: DECAPS(sk, ct) → ss
    Note over C,S: Both hold ss, which never crossed the wire
```

| Property | Diffie–Hellman | KEM |
| --- | --- | --- |
| Client sends | Its public value | Its public key |
| Server sends | Its public value | A ciphertext |
| Who generates a key pair | Both sides | Client only |
| Who chooses the secret | Neither alone; it emerges from both | Server's `ENCAPS` randomness |

What the black box guarantees: an observer who sees `pk` and `ct` cannot learn
`ss`, and this is believed to hold even against quantum computers. ML-KEM is
also designed for *chosen-ciphertext* security: feeding `DECAPS` manipulated
ciphertexts reveals nothing useful about `sk`.

What it does **not** guarantee: like Diffie–Hellman, a KEM authenticates no
one. An attacker in the middle can replace `pk` with its own. SSH still
relies on the host-key signature over the exchange hash and on the client's
host-key trust decision.

### ML-KEM and Streamlined NTRU Prime

Two KEMs appear in SSH:

- **ML-KEM**, standardized by NIST in
  [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (2024) and derived
  from the Kyber submission. Of its three parameter sets, SSH's
  `mlkem768x25519-sha256` uses ML-KEM-768, which FIPS 203 places in NIST
  security category 3.
- **sntrup761**, an instance of
  [Streamlined NTRU Prime](https://ntruprime.cr.yp.to/). NIST did not select
  it, but it was the first post-quantum KEM deployed by default in OpenSSH,
  in `sntrup761x25519-sha512`.

Both are *lattice-based*: their public keys are built from secrets with small
coefficients, and recovering those secrets amounts to finding unusually short
vectors in a high-dimensional lattice (a regular grid of points). No
efficient classical or quantum algorithm for that problem is known.

Sizes, from FIPS 203 Table 3 and, for sntrup761, RFC 9941:

| KEM | Public key | Ciphertext | Shared secret |
| --- | --- | --- | --- |
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1184 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | 1568 bytes | 1568 bytes | 32 bytes |
| sntrup761 | 1158 bytes | 1039 bytes | 32 bytes |

Before running `ENCAPS`, the server must perform FIPS 203's encapsulation-key
check (correct length, and every encoded coefficient below the modulus), as
[RFC 10042](https://www.rfc-editor.org/rfc/rfc10042.html#section-2.1)
requires.

<details>
<summary>Go deeper: learning with errors</summary>

**Linear equations are easy.** Suppose a secret vector `s` has four numbers,
and you are given `b = A·s (mod q)`: each row of the matrix `A` dotted with
`s` gives one entry of `b`. With four independent equations, *Gaussian
elimination* (the school substitution method, done mod `q`) recovers `s`
quickly.

**Add a little noise, and it becomes hard.** *Learning with errors* (LWE)
publishes instead

```text
b = A·s + e   (mod q)
```

where each entry of the error vector `e` is small, such as −1, 0, or 1.
Elimination now amplifies the errors until the answer is garbage. For large
dimensions, no known classical or quantum algorithm recovers `s` efficiently.

**A toy public key.** Take `q = 97`, dimension `n = 4`, and five equations:

```text
secret  s = (3, 14, 59, 26)
errors  e = (1, −1, 0, 1, −1)

        A                     A·s mod 97    + e    = b
row 0:  (12, 71,  5, 33)          49          +1      50
row 1:  (40,  8, 91, 17)          29          −1      28
row 2:  (66, 29, 50,  2)          17           0      17
row 3:  ( 9, 83, 24, 61)          20          +1      21
row 4:  (77, 45, 13, 38)          94          −1      93
```

The public key is `(A, b)`; the secret key is `s`.

**Encrypting one bit.** To encrypt bit `m`, pick a random subset of rows, say
rows 0, 2, and 3. Add those rows of `A` to get `u`, add the matching entries
of `b`, and add `m · ⌊q/2⌋ = m · 48`:

```text
u = row0 + row2 + row3 = (87, 183, 79, 96) ≡ (87, 86, 79, 96)  (mod 97)
v = 50 + 17 + 21 + 48·m = 88 + 48·m                              (mod 97)
```

Bit 0 gives `v = 88`, and bit 1 gives `v = 136 ≡ 39`. The ciphertext is
`(u, v)`.

**Decrypting.** The secret-key holder computes `v − u·s`. Here
`u·s = 87·3 + 86·14 + 79·59 + 96·26 = 8622 ≡ 86 (mod 97)`. The `A·s` parts
cancel, leaving the sum of the chosen errors plus the message:

```text
bit 0:  88 − 86 =  2          → close to 0  → decrypt 0
bit 1:  39 − 86 = −47 ≡ 50    → close to 48 → decrypt 1
```

The leftover 2 is `e0 + e2 + e3 = 1 + 0 + 1`. As long as the accumulated noise
stays below `q/4`, rounding to the nearer of 0 and 48 recovers the bit;
larger noise would decrypt to the wrong bit, and real parameters make that
vanishingly unlikely.

**From toy to ML-KEM.** Four unknowns mod 97 can be brute-forced instantly.
ML-KEM keeps the idea with three refinements from FIPS 203:

- **Module lattices.** Each entry of `A` and `s` is a polynomial with 256
  coefficients in the ring `Z_q[X]/(X^256 + 1)`, with `q = 3329`. ML-KEM-768
  uses a 3×3 matrix of such polynomials (`k = 3`), which packs many bits per
  operation and keeps keys around a kilobyte.
- **Key encapsulation.** Instead of one bit, the encryptor locks a random
  32-byte message, and both sides hash it, with a hash of the public key,
  into the shared secret.
- **Fujisaki–Okamoto transform.** `DECAPS` decrypts, re-encrypts the result,
  and checks that it reproduces the received ciphertext exactly. If not, it
  returns a pseudorandom value derived from a secret and the ciphertext
  instead of an error. This *implicit rejection* gives an attacker who sends
  modified ciphertexts nothing to learn from. In SSH, the mismatched secret
  makes the exchange hash differ, so the server's signature fails to verify.

Learn more:
[Learning with errors](https://en.wikipedia.org/wiki/Learning_with_errors),
[Kyber](https://en.wikipedia.org/wiki/Kyber),
[FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final),
[NTRU Prime](https://ntruprime.cr.yp.to/).

</details>

## Hybrid key exchange in SSH

Post-quantum KEMs are young compared with elliptic curves, and a new attack
or implementation flaw could weaken them. SSH therefore runs X25519
*alongside* a KEM and hashes both secrets together:

```mermaid
flowchart LR
    subgraph PQ["Post-quantum part"]
        PK["Client ML-KEM public key"] --> ENC["Server ENCAPS"]
        ENC --> CT["Ciphertext to client"]
        CT --> DEC["Client DECAPS"]
        DEC --> KPQ["K_PQ<br/>(32 bytes)"]
    end
    subgraph CLS["Classical part"]
        QC["Client X25519 public"] --> X["X25519 agreement"]
        QS["Server X25519 public"] --> X
        X --> KCL["K_CL<br/>(32 bytes)"]
    end
    KPQ --> CAT["K_PQ ‖ K_CL"]
    KCL --> CAT
    CAT --> HASH["SHA-256"]
    HASH --> K["K (32 bytes)<br/>encoded as SSH string"]
    K --> USE["Exchange hash H<br/>and key derivation"]
    classDef secret fill:#ffe066,stroke:#8a6d00,color:#000
    class KPQ,KCL,K secret
```

`K` stays secret as long as **either** component holds. A quantum attacker
who recovers `K_CL` still lacks `K_PQ`; an attacker who breaks ML-KEM
classically still faces X25519. RFC 10042 calls this a *post-quantum/
traditional (PQ/T) hybrid* and states that it "will always be at least as
secure as the most secure key exchange scheme executed as part of the
exchange," citing published security proofs.

### The wire view of `mlkem768x25519-sha256`

[RFC 10042](https://www.rfc-editor.org/rfc/rfc10042.html) keeps the familiar
two-message shape and message numbers 30 and 31, named
`SSH_MSG_KEX_HYBRID_INIT` and `SSH_MSG_KEX_HYBRID_REPLY`. Each side
concatenates its post-quantum and classical values into one SSH `string`,
post-quantum part first:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    Note over C: ML-KEM-768 KEYGEN<br/>X25519 GENERATE
    C->>S: SSH_MSG_KEX_HYBRID_INIT (30)<br/>string C_INIT = ML-KEM pk (1184) ‖ X25519 public (32)<br/>= 1216 bytes
    Note over S: Check C_INIT is exactly 1216 bytes<br/>Check ML-KEM pk (FIPS 203)<br/>ENCAPS → ct, K_PQ<br/>X25519 → K_CL<br/>K = SHA-256(K_PQ ‖ K_CL)<br/>sign H with host key
    S->>C: SSH_MSG_KEX_HYBRID_REPLY (31)<br/>string K_S<br/>string S_REPLY = ML-KEM ct (1088) ‖ X25519 public (32)<br/>= 1120 bytes<br/>string signature
    Note over C: Check host key trust<br/>Check S_REPLY is exactly 1120 bytes<br/>DECAPS → K_PQ, X25519 → K_CL (reject all-zero)<br/>K = SHA-256(K_PQ ‖ K_CL)<br/>compute H, verify signature
```

A failed length check, key check, or decapsulation ends the connection with
`SSH_DISCONNECT_KEY_EXCHANGE_FAILED`. Three encoding details differ from
`curve25519-sha256`:

- `K_CL` is the 32-byte X25519 result as a fixed-length byte array, not an
  `mpint`.
- `K` is the 32-byte hash output, encoded in the exchange hash as an SSH
  `string` (a 4-byte length followed by 32 bytes). This avoids the
  secret-dependent length of an `mpint` described in
  [X25519](./crypto-key-agreement.md#how-the-result-becomes-k).
- The exchange hash includes `C_INIT` and `S_REPLY` in place of `Q_C` and
  `Q_S`, and `string K` in place of `mpint K`.

RFC 10042's other two methods follow the same structure with NIST curves:
`mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384`.

`sntrup761x25519-sha512`
([RFC 9941](https://www.rfc-editor.org/rfc/rfc9941.html)) has the same design
with different components. It reuses the RFC 5656 message layout, puts the
KEM value first in `Q_C` and `Q_S`, and computes `K = SHA-512(K_PQ ‖ K_CL)`,
a 64-byte value encoded as a `string` (in the RFC's test vectors it begins
`00 00 00 40`, the length 64). RFC 9941 recommends also accepting the older
name `sntrup761x25519-sha512@openssh.com` as an alias.

### Size comparison

Values carried in the key-exchange `string` fields, in bytes:

| Method | Client → server | Server → client | Hash |
| --- | --- | --- | --- |
| `curve25519-sha256` | 32 | 32 | SHA-256 |
| `sntrup761x25519-sha512` | 1158 + 32 = 1190 | 1039 + 32 = 1071 | SHA-512 |
| `mlkem768x25519-sha256` | 1184 + 32 = 1216 | 1088 + 32 = 1120 | SHA-256 |
| `mlkem768nistp256-sha256` | 1184 + 65 = 1249 | 1088 + 65 = 1153 | SHA-256 |
| `mlkem1024nistp384-sha384` | 1568 + 97 = 1665 | 1568 + 97 = 1665 | SHA-384 |

The NIST-curve rows assume uncompressed points; RFC 10042 permits point
compression. The extra kilobyte or so each way is small next to typical SSH
traffic and well within the 32768-byte payload every SSH implementation must
accept. ML-KEM is also fast: OpenSSH describes `mlkem768x25519-sha256` as
"considerably faster than the previous default."

### Deployment in OpenSSH

The [OpenSSH release notes](https://www.openssh.com/releasenotes.html) record
the transition:

```mermaid
timeline
    title Post-quantum support in OpenSSH
    2021 (8.5) : sntrup761x25519-sha512@openssh.com replaces an earlier experimental method
    2022 (8.9) : sntrup761 hybrid added to the default KexAlgorithms list
    2022 (9.0) : sntrup761 hybrid becomes the default key exchange
    2024 (9.9) : mlkem768x25519-sha256 added and enabled
               : sntrup761x25519-sha512 accepted under its IANA name
    2025 (10.0) : mlkem768x25519-sha256 becomes the default
    2025 (10.1) : ssh warns when a non-post-quantum key exchange is negotiated
    2026 (10.4) : experimental ML-DSA-44 + Ed25519 composite signatures, off by default
```

The OpenSSH 10.1 warning begins
`** WARNING: connection is not using a post-quantum key exchange algorithm.`
The [`WarnWeakCrypto`](https://man.archlinux.org/man/ssh_config.5#WarnWeakCrypto)
option controls it; `WarnWeakCrypto no-pq-kex` silences only this warning,
ideally inside a `Match host` block for a server that cannot yet be upgraded.
[OpenSSH: Post-Quantum Cryptography](https://www.openssh.com/pq.html)
explains the project's rationale.

Verbose output shows which method a connection used:

```text
debug1: kex: algorithm: mlkem768x25519-sha256
```

`ssh -Q kex` lists the methods a client supports. Negotiation selects the
first method in the client's list that the server also offers; see
[Algorithm negotiation](./version-and-negotiation.md).

### What post-quantum key exchange does not do

Hybrid key exchange protects *confidentiality*, not authentication:

- The server still proves its identity with a classical host-key signature
  (`ssh-ed25519`, `ecdsa-sha2-*`, or `rsa-sha2-*`). A quantum attacker present
  at connection time could forge it and impersonate the server.
- Public-key user authentication still uses classical signatures, with the
  same limitation.
- Key-exchange and host-key algorithms are separate negotiation categories.
  A post-quantum `kex: algorithm:` line says nothing about the host key.

NIST has standardized post-quantum signatures: ML-DSA in
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and SLH-DSA in
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final). SSH deployment is at
an early stage. OpenSSH 10.4 added experimental support for
`ssh-mldsa44-ed25519@openssh.com`, a composite of ML-DSA-44 and Ed25519
described in
[draft-miller-sshm-mldsa44-ed25519-composite-sigs](https://datatracker.ietf.org/doc/draft-miller-sshm-mldsa44-ed25519-composite-sigs/).
It is off by default and must be added to `HostKeyAlgorithms` or
`PubkeyAcceptedAlgorithms`. Classical signatures do not endanger recorded
traffic; they matter only once quantum attacks are feasible in real time.

## Check your understanding

1. Why does Grover's algorithm leave AES-256 essentially unaffected, while
   Shor's algorithm breaks X25519 completely?
2. An attacker records a `curve25519-sha256` session today. Why does forward
   secrecy not protect it from a future quantum computer?
3. Why was it more urgent to deploy post-quantum key exchange than
   post-quantum host-key signatures?
4. In a KEM-based exchange, which side generates a key pair, and what does the
   other side send back?
5. For `mlkem768x25519-sha256`, how long must `C_INIT` and `S_REPLY` be, and
   what should the receiving side do if the length is wrong?
6. Why does the hybrid design hash `K_PQ ‖ K_CL` instead of using only
   `K_PQ`?
7. A connection's debug log shows `kex: algorithm: mlkem768x25519-sha256` and
   `kex: host key algorithm: ssh-ed25519`. Which parts of the connection are
   protected against a future quantum attacker?

<details>
<summary>Answers</summary>

1. Grover gives only a square-root speed-up on brute-force search, so a
   256-bit key still requires about `2^128` sequential quantum steps. Shor's
   algorithm solves the discrete logarithm problem underlying X25519 in
   polynomial time, so no practical key size is safe.
2. Forward secrecy assumes the ephemeral private values are gone. Shor's
   algorithm recomputes an ephemeral private value from the recorded public
   value, so the attacker can rebuild `K` without stealing anything.
3. Recorded traffic can be decrypted at any later time, so confidentiality is
   at risk today. A signature only needs to resist forgery during the
   handshake it authenticates; a future attacker cannot impersonate a server
   in a connection that is already over.
4. The client generates the key pair and sends the public key. The server
   runs `ENCAPS` and returns the ciphertext; it does not generate a key pair.
5. `C_INIT` must be 1184 + 32 = 1216 bytes and `S_REPLY` 1088 + 32 = 1120
   bytes. On a mismatch, the receiver aborts with `SSH_MSG_DISCONNECT` and the
   reason `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`.
6. So that `K` stays secret if either component remains secure. If ML-KEM
   were broken classically, X25519 would still protect `K`; if X25519 falls
   to a quantum computer, ML-KEM still protects it.
7. The session's confidentiality, including anything typed or transferred,
   is protected against later decryption. Server authentication is still
   classical: safe now, but a quantum attacker present at connection time
   could forge an Ed25519 signature.

</details>

## References

- [RFC 10042 — Post-Quantum/Traditional Hybrid Key Exchange with the Module-Lattice-Based Key-Encapsulation Mechanism for Use in SSH](https://www.rfc-editor.org/rfc/rfc10042.html).
- [RFC 9941 — Secure Shell (SSH) Key Exchange Method Using Hybrid Streamlined NTRU Prime sntrup761 and X25519 with SHA-512: sntrup761x25519-sha512](https://www.rfc-editor.org/rfc/rfc9941.html).
- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final).
- [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final).
- [FIPS 205 — Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final).
- [RFC 9958 — Post-Quantum Cryptography for Engineers](https://www.rfc-editor.org/rfc/rfc9958.html).
- [OpenSSH: Post-Quantum Cryptography](https://www.openssh.com/pq.html) and
  [OpenSSH release notes](https://www.openssh.com/releasenotes.html).
- [ssh_config(5)](https://man.archlinux.org/man/ssh_config.5#WarnWeakCrypto) —
  `WarnWeakCrypto`.
- [draft-miller-sshm-mldsa44-ed25519-composite-sigs](https://datatracker.ietf.org/doc/draft-miller-sshm-mldsa44-ed25519-composite-sigs/)
  — the experimental composite signature in OpenSSH 10.4.
- [NTRU Prime](https://ntruprime.cr.yp.to/).
- [Key-exchange method survey](./key-exchange-methods.md) — how hybrid
  methods compare with the classical ones.
