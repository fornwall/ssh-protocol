# SSH Protocol Course

An [mdBook](https://rust-lang.github.io/mdBook/) course about SSH at both levels: how to use it safely and effectively, and how the protocol works on the wire.

## What is SSH?

Secure Shell (SSH) is a cryptographic network protocol for securely operating a remote computer over an untrusted network. It is most familiar as a tool for interactive shell access, but one encrypted connection can also carry commands, file transfers, TCP forwarding, and multiple independent channels. SSH authenticates the server, can authenticate the user with public-key cryptography, and protects the confidentiality and integrity of the session.

SSH version 2 is divided into three layers: the transport layer establishes encryption and authenticates the server, the user authentication layer proves the client's identity, and the connection layer multiplexes shells, commands, forwarding, and other channels.

## Read and build

Install [mdBook](https://rust-lang.github.io/mdBook/guide/installation.html), [mdbook-mermaid](https://github.com/badboy/mdbook-mermaid), [just](https://just.systems/man/en/), and [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2), then run:

```console
just doctor
just view
```

`just view` serves the book locally and opens it in a browser. Run `just` to see all available tasks, including build, lint, test, package, and clean.

Mermaid is configured as an mdBook preprocessor, and its browser assets are kept in the repository so diagrams also work offline. After upgrading `mdbook-mermaid`, run `just install-mermaid` to refresh those assets.

## Protocol references

- [RFC 4251 — SSH Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251)
- [RFC 4252 — SSH Authentication Protocol](https://www.rfc-editor.org/rfc/rfc4252)
- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253)
- [RFC 4254 — SSH Connection Protocol](https://www.rfc-editor.org/rfc/rfc4254)
- [RFC 4256 — Generic Message Exchange Authentication](https://www.rfc-editor.org/rfc/rfc4256)
- [RFC 4716 — SSH Public Key File Format](https://www.rfc-editor.org/rfc/rfc4716)
- [RFC 5656 — Elliptic Curve Algorithms for SSH](https://www.rfc-editor.org/rfc/rfc5656)
- [RFC 8332 — Use of RSA Keys with SHA-2](https://www.rfc-editor.org/rfc/rfc8332)
- [RFC 8709 — Ed25519 and Ed448 Host Key Algorithms](https://www.rfc-editor.org/rfc/rfc8709)
- [RFC 9142 — Key Exchange Method Updates and Recommendations](https://www.rfc-editor.org/rfc/rfc9142)
- [RFC 9519 — Strict Key Exchange](https://www.rfc-editor.org/rfc/rfc9519)
- [IANA SSH Protocol Parameters](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml)

For a general overview and history, see [Secure Shell on Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell).

## Notable implementations and tools

- [OpenSSH](https://www.openssh.com/) — the widely deployed open-source client and server maintained by OpenBSD.
- [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/) — an SSH and terminal client, especially well known on Windows.
- [Dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) — a small client and server used on embedded systems.
- [libssh](https://www.libssh.org/) and [libssh2](https://libssh2.org/) — C libraries for adding SSH to applications.
- [AsyncSSH](https://asyncssh.readthedocs.io/) and [Paramiko](https://www.paramiko.org/) — Python SSH implementations.
- [Wireshark](https://www.wireshark.org/) — a packet analyzer useful for studying SSH negotiation and traffic metadata.

## Status

The book is at its initial scaffolding stage. Deployment is intentionally left for a future change.

## License

No license has been selected. All rights are reserved by default.
