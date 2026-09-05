# Repository structure

This project is an mdBook course about SSH.

- `book.toml` configures mdBook and the Mermaid preprocessor.
- `src/SUMMARY.md` defines the chapter order and navigation.
- `src/*.md` contains the course material.
- `mermaid.min.js` and `mermaid-init.js` are vendored by `mdbook-mermaid` for offline diagrams.
- `justfile` provides the common development tasks; run `just` to list them.
- `book/` and `dist/` are generated and must not be committed.

Run `just check` before committing. Use `just view` for local authoring and `just package VERSION` to create a distributable archive.
