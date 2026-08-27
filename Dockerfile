FROM rust:1-bookworm AS build
# protoc for silo-proto's build.rs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p silo-server -p silo-cli

FROM debian:bookworm-slim
# ca-certificates is the only runtime dependency: outbound TLS to S3 and to
# the OIDC issuer. All three index formats — repodata, APKINDEX, packuments
# — are generated in-process, so there is no package tooling to install.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/silo-server /usr/local/bin/silo-server
# The CLI ships in the same image so `kubectl exec` can manage tokens and
# users without a second image or a local install.
COPY --from=build /build/target/release/silo /usr/local/bin/silo

# Runs unprivileged, and with nothing to write to: index generation is
# entirely in-memory, and everything durable lives in object storage and
# Postgres.
RUN useradd --system --uid 10001 --create-home silo
USER 10001

EXPOSE 9090 8080
ENTRYPOINT ["/usr/local/bin/silo-server"]
