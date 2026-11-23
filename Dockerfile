# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
# Full (non-slim) Rust image: it ships gcc/make, which rusqlite's `bundled`
# feature needs to compile SQLite from C. A slim image lacks the toolchain.
FROM rust:1-bookworm AS build
WORKDIR /src

# Build dependencies first so edits to src/ don't re-download/rebuild the crate
# graph on every change. (Cargo.lock is committed-or-generated; copy if present.)
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Now the real sources and the release build.
COPY src ./src
# Touch so cargo rebuilds against the real main.rs (the stub above shares its path).
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ---------------------------------------------------------
# Slim runtime: just glibc + the binary + the static web/ assets. SQLite is
# statically linked into the binary (bundled), so no libsqlite package is needed.
FROM debian:bookworm-slim AS runtime

# The server opens HTTPS to nothing by default (loopback/local-first), so
# ca-certificates isn't strictly required today; omit it to keep the image lean.

# web/ lives in the image (read-only), while /data is a mounted volume holding
# chartcraft.db. ServeDir is CWD-relative, so the server (run from WORKDIR /data)
# needs ./web — a symlink into the image keeps the assets versioned with the image
# instead of frozen inside the volume on first `up`.
COPY --from=build /src/target/release/chartcraft /usr/local/bin/chartcraft
COPY web /opt/chartcraft/web

WORKDIR /data
RUN ln -s /opt/chartcraft/web /data/web

EXPOSE 8080
# Bind on all interfaces INSIDE the container; compose publishes it host-local.
ENV CHARTCRAFT_BIND=0.0.0.0:8080

CMD ["chartcraft"]
