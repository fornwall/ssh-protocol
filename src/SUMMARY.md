<!-- markdownlint-disable MD025 -->

# Summary

[Introduction](./introduction.md)

# Orientation

- [Observe a connection](./first-connection.md)
- [The client's view of protocol state](./client-architecture.md)

# The transport layer

- [Identification exchange](./identification.md)
- [SSH binary packets and data types](./binary-packets.md)
- [Algorithm negotiation](./version-and-negotiation.md)

# Cryptographic building blocks

- [Cryptography as protocol building blocks](./cryptography-primer.md)
  - [Hashes, MACs, and key derivation](./crypto-hashes.md)
  - [Symmetric encryption and packet protection](./crypto-symmetric.md)
  - [Key agreement: Diffie–Hellman and elliptic curves](./crypto-key-agreement.md)
  - [Post-quantum key exchange](./crypto-post-quantum.md)
  - [Digital signatures](./crypto-signatures.md)

# Key exchange and server authentication

- [Key exchange](./key-exchange.md)
  - [Key-exchange method survey](./key-exchange-methods.md)
- [Server authentication](./server-authentication.md)

# User authentication

- [User authentication](./user-authentication.md)
- [FIDO security keys (YubiKey)](./fido-security-keys.md)

# The connection protocol

- [Channels and flow control](./channels.md)
- [Sessions: commands, terminals, and subsystems](./sessions.md)
- [TCP forwarding](./forwarding.md)
- [Agent, X11, and Unix-socket forwarding](./other-channels.md)

# Security and analysis

- [Security properties and boundaries](./robustness-and-security.md)
- [Reading traces and diagnosing failures](./testing-and-debugging.md)

---

[Glossary](./glossary.md)
[Reference map](./reference-map.md)
