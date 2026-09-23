# A Client’s Guide to the SSH Protocol

An [mdBook](https://rust-lang.github.io/mdBook/) guide about the SSH protocol
from the client's point of view.

## What is SSH?

Secure Shell (SSH) is a cryptographic network protocol for operating a remote
computer over an untrusted network. One protected connection can carry
commands, file-transfer protocols, TCP forwarding, and multiple independent
channels.

SSH version 2 has three layers. The transport layer negotiates packet
protection and supplies a signed server host-key proof. The user-authentication
layer authorizes access to a requested account. The connection layer
multiplexes sessions, forwarding, and other channels.

## Read and build

Install [mdBook](https://rust-lang.github.io/mdBook/guide/installation.html), [mdbook-mermaid](https://github.com/badboy/mdbook-mermaid), [just](https://just.systems/man/en/), and [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2), then run:

```console
just doctor
just view
```

`just view` serves the book locally and opens it in a browser. Run `just` to see all available tasks, including build, lint, test, package, and clean.

Mermaid is configured as an mdBook preprocessor, and its browser assets are kept in the repository so diagrams also work offline. After upgrading `mdbook-mermaid`, run `just install-mermaid` to refresh those assets. `custom.css` styles the collapsible `<details>` blocks used for “Go deeper” sections and answers.

## Publish

Run `just publish` to check, build, and deploy the guide to
[ssh.fornwall.net](https://ssh.fornwall.net) using Cloudflare Pages
[Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/).
`just deploy` is an alias for the same task.

Publishing requires Node.js and npm in addition to the authoring tools. The task
runs a pinned version of Wrangler through `npx` and uses the `ssh-fornwall-net`
Pages project. It always deploys to the production branch, `main`, regardless of
the local Git branch, and publishes the current working tree.

Authenticate with `npx --yes wrangler@4.129.0 login`, or provide a token with
Cloudflare Pages Edit permission in `CLOUDFLARE_API_TOKEN` (the existing
`CLOUDFLARE_PAGES_EDIT_API_TOKEN` variable is also supported). Credentials stay
outside the repository.

The project's custom domain is `ssh.fornwall.net`. Its Cloudflare DNS record must
be a proxied CNAME pointing to `ssh-fornwall-net.pages.dev`. This is a one-time
setup; subsequent publishes update the site without changing DNS.

## Protocol references

- [RFC 4251 — SSH Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251)
- [RFC 4252 — SSH Authentication Protocol](https://www.rfc-editor.org/rfc/rfc4252)
- [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253)
- [RFC 4254 — SSH Connection Protocol](https://www.rfc-editor.org/rfc/rfc4254)
- [RFC 4256 — Generic Message Exchange Authentication](https://www.rfc-editor.org/rfc/rfc4256)
- [RFC 4335 — Session Channel Break Extension](https://www.rfc-editor.org/rfc/rfc4335)
- [RFC 4462 — GSS-API Authentication and Key Exchange](https://www.rfc-editor.org/rfc/rfc4462)
- [RFC 4716 — SSH Public Key File Format](https://www.rfc-editor.org/rfc/rfc4716)
- [RFC 5656 — Elliptic Curve Algorithms for SSH](https://www.rfc-editor.org/rfc/rfc5656)
- [RFC 8308 — Extension Negotiation in SSH](https://www.rfc-editor.org/rfc/rfc8308)
- [RFC 8332 — Use of RSA Keys with SHA-2](https://www.rfc-editor.org/rfc/rfc8332)
- [RFC 8709 — Ed25519 and Ed448 Host Key Algorithms](https://www.rfc-editor.org/rfc/rfc8709)
- [RFC 8731 — Curve25519 and Curve448 Key Exchange](https://www.rfc-editor.org/rfc/rfc8731)
- [RFC 9142 — Key Exchange Method Updates and Recommendations](https://www.rfc-editor.org/rfc/rfc9142)
- [RFC 9519 — SSH Registry Requirements](https://www.rfc-editor.org/rfc/rfc9519)
- [RFC 9941 — Hybrid sntrup761/X25519 Key Exchange](https://www.rfc-editor.org/rfc/rfc9941)
- [RFC 9987 — SSH Agent Protocol](https://www.rfc-editor.org/rfc/rfc9987)
- [RFC 10042 — ML-KEM Hybrid Key Exchange for SSH](https://www.rfc-editor.org/rfc/rfc10042)
- [Strict KEX Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/)
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

The guide covers identification, packet framing, negotiation, key exchange,
host and user authentication (including FIDO security keys), sessions, TCP,
agent, X11, and Unix-socket forwarding, security analysis, and trace-based
diagnosis.

A cryptography part explains the primitives SSH relies on: hashes, MACs, and
key derivation; symmetric packet protection; Diffie–Hellman and elliptic-curve
key agreement; post-quantum key exchange; and digital signatures. Each chapter
presents its primitive as a black box first, with optional collapsible
“Go deeper” sections for the underlying math. A glossary and a reference map
close the guide.

## License

No license has been selected. All rights are reserved by default.
