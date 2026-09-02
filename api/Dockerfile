# honeypot-api.
#
# Built ON THE HOST rather than pulled: there is no registry credential on
# these machines and no CI publishing an image, so a multi-stage build from the
# checkout is the path that costs nothing and needs no account. The toolchain
# lives in the builder stage only -- the deployed image has no compiler.

FROM rust:1.98-slim-bookworm AS build
WORKDIR /src

# Sources first, dependencies resolved from the committed lockfile. `--locked`
# is what makes the image reproducible: without it a fresh `cargo build` is free
# to pick up a newer semver-compatible release and produce a binary that differs
# from the one the tests ran against.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The migrations are EMBEDDED by `sqlx::migrate!` at compile time, so they have
# to be in the build context. This is also why the build needs no database.
COPY migrations ./migrations
RUN cargo build --release --locked

# Runtime on the same Debian release as the builder, so the glibc the binary was
# linked against is the one it finds.
FROM debian:bookworm-slim

# ca-certificates for a future TLS connection to a remote Postgres; curl only so
# the container has a healthcheck it can run on itself. Nothing else -- no
# shell tooling, no compiler, no package manager cache.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/honeypot-api /usr/local/bin/honeypot-api

# nobody:nogroup. The process owns nothing on disk (its state is in PostgreSQL),
# so it needs no writable path at all -- which is what lets the compose file run
# it with a read-only root filesystem.
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/honeypot-api"]
