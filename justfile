set shell := ["sh", "-eu", "-c"]

book_dir := "book"
dist_dir := "dist"
host := "127.0.0.1"
port := "3000"

# Show the available project tasks.
default:
    @just --list

# Report whether the local authoring tools are installed.
doctor:
    @status=0; \
    for tool in mdbook mdbook-mermaid markdownlint-cli2; do \
      if command -v "$tool" >/dev/null 2>&1; then \
        printf 'ok       %s\n' "$tool"; \
      else \
        printf 'missing  %s\n' "$tool"; \
        status=1; \
      fi; \
    done; \
    exit "$status"

# Build the static book into book/.
build:
    mdbook build

# Refresh the Mermaid browser assets after upgrading mdbook-mermaid.
install-mermaid:
    mdbook-mermaid install .

# Serve the book without opening a browser.
serve bind=host listen=port:
    mdbook serve --hostname "{{ bind }}" --port "{{ listen }}"

# Serve the book and open it in the default browser.
view bind=host listen=port:
    mdbook serve --open --hostname "{{ bind }}" --port "{{ listen }}"

# Watch and rebuild the book without running a web server.
watch:
    mdbook watch

# Lint all hand-written Markdown.
lint:
    markdownlint-cli2

# Apply safe automatic Markdown lint fixes.
format:
    markdownlint-cli2 --fix

# Test Rust code examples and validate the mdBook structure.
test:
    mdbook test

# Run all checks and produce the static book.
check: lint test build

# Package the built static site as dist/ssh-protocol-guide-VERSION.tar.gz.
package version="dev": build
    mkdir -p "{{ dist_dir }}"
    tar -C "{{ book_dir }}" -czf "{{ dist_dir }}/ssh-protocol-guide-{{ version }}.tar.gz" .
    @printf 'Created %s\n' "{{ dist_dir }}/ssh-protocol-guide-{{ version }}.tar.gz"

# Remove generated build and package artifacts.
clean:
    rm -rf "{{ book_dir }}" "{{ dist_dir }}"

# Deployment is intentionally deferred until a target has been chosen.
deploy:
    @printf '%s\n' 'Deployment is not implemented yet.' >&2
    @exit 1
