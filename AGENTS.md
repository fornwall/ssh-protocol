# Repository structure

This project is an mdBook guide about SSH, published at <https://ssh.fornwall.net>.

- `book.toml` configures mdBook, the Mermaid preprocessor, and extra assets.
- `src/SUMMARY.md` defines the chapter order and navigation.
- `src/*.md` contains the guide material:
  - protocol chapters (transport, key exchange and server authentication, user
    authentication, connection protocol including `other-channels.md` for
    agent, X11, and Unix-socket forwarding);
  - a separate "Cryptographic building blocks" part: `cryptography-primer.md`
    plus nested `crypto-*.md` chapters (hashes/MACs/KDF, symmetric ciphers, key
    agreement, post-quantum, signatures);
  - `fido-security-keys.md`, which also covers OpenSSH and `ykman` setup;
  - `glossary.md` and `reference-map.md`, which should be updated when terms or
    references are added.
- `custom.css` styles the collapsible `<details>` sections.
- `mermaid.min.js` and `mermaid-init.js` are vendored by `mdbook-mermaid` for offline diagrams.
- `justfile` provides the common development tasks; run `just` to list them.
- `book/` and `dist/` are generated and must not be committed.

Run `just check` (markdownlint, `mdbook test`, build) before committing. Use
`just view` for local authoring and `just package VERSION` to create a
distributable archive.

# Guide focus

- Teach a deep understanding of the SSH protocol from the client's point of
  view. This is not a tutorial on how to write an SSH client or parser.
- Include wire formats, state transitions, and implementation considerations
  only when they clarify protocol behavior or a security boundary. Avoid
  low-level parser construction, software architecture, and generic engineering
  detail that would derail the protocol narrative.
- Use code or pseudocode sparingly, and only when it makes a protocol rule or
  interaction materially easier to understand.

# Conventions

- Cryptography is explained black box first: what goes in, what comes out,
  what it guarantees, and where SSH uses it, illustrated with Mermaid. Math
  goes in collapsible sections that start with `Go deeper:`:

  ```html
  <details>
  <summary>Go deeper: …</summary>

  …markdown, with a blank line after the summary…

  </details>
  ```

  Use small worked examples whose numbers have been checked by running them,
  plain-text math (no LaTeX), and links for further reading.
- Do not put Mermaid diagrams inside `<details>`; they render at the wrong
  size while collapsed. Quote labels that contain punctuation, and give colored
  nodes an explicit `color:#000`.
- End chapters with optional `## Lab: …` sections, then
  `## Check your understanding` (numbered questions and a `<details>` block
  with `<summary>Answers</summary>`), then `## References`. The introduction,
  glossary, and reference map are exempt.
- Cite primary sources (RFCs, Internet-Drafts, NIST FIPS, OpenSSH man pages and
  release notes) and check that external links still resolve. OpenSSH has
  replaced some `PROTOCOL.*` files with Internet-Drafts.
- Link OpenSSH man pages on `man.archlinux.org` (current portable OpenSSH,
  with mandoc option anchors), for example
  `https://man.archlinux.org/man/ssh_config.5#ProxyJump`.
