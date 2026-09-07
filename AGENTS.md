# Repository structure

This project is an mdBook guide about SSH.

- `book.toml` configures mdBook and the Mermaid preprocessor.
- `src/SUMMARY.md` defines the chapter order and navigation.
- `src/*.md` contains the guide material.
- `mermaid.min.js` and `mermaid-init.js` are vendored by `mdbook-mermaid` for offline diagrams.
- `justfile` provides the common development tasks; run `just` to list them.
- `book/` and `dist/` are generated and must not be committed.

Run `just check` before committing. Use `just view` for local authoring and `just package VERSION` to create a distributable archive.

# Guide focus

- Teach a deep understanding of the SSH protocol from the client's point of
  view. This is not a tutorial on how to write an SSH client or parser.
- Include wire formats, state transitions, and implementation considerations
  only when they clarify protocol behavior or a security boundary. Avoid
  low-level parser construction, software architecture, and generic engineering
  detail that would derail the protocol narrative.
- Use code or pseudocode sparingly, and only when it makes a protocol rule or
  interaction materially easier to understand.
