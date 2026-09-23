<!-- markdownlint-disable MD025 -->

# Summary

- [Introduction](./introduction.md)

# Orientation

- [Observe a connection](./first-connection.md)
- [The client's view of protocol state](./client-architecture.md)

# The transport layer

- [Identification exchange](./identification.md)
- [SSH binary packets and data types](./binary-packets.md)
- [Algorithm negotiation](./version-and-negotiation.md)
- [Cryptography as protocol building blocks](./cryptography-primer.md)
  - [Hashes, MACs, and key derivation](./crypto-hashes.md)
  - [Symmetric encryption and packet protection](./crypto-symmetric.md)
  - [Key agreement: Diffie–Hellman and elliptic curves](./crypto-key-agreement.md)
  - [Digital signatures](./crypto-signatures.md)
  - [Post-quantum key exchange](./crypto-post-quantum.md)
- [Key exchange](./key-exchange.md)
  - [Key-exchange method survey (optional)](./key-exchange-methods.md)
- [Server authentication](./server-authentication.md)

# User authentication and the connection protocol

- [User authentication](./user-authentication.md)
  - [FIDO security keys (YubiKey)](./fido-security-keys.md)
- [Channels and flow control](./channels.md)
- [Sessions: commands, terminals, and subsystems](./sessions.md)
- [TCP forwarding](./forwarding.md)

# Security and analysis

- [Security properties and boundaries](./robustness-and-security.md)
- [Reading traces and diagnosing failures](./testing-and-debugging.md)
- [Glossary](./glossary.md)
- [Reference map](./reference-map.md)
