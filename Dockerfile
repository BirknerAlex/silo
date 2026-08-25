FROM rust:1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release -p silo-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends createrepo-c ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/silo-server /usr/local/bin/silo-server

EXPOSE 9090 8080
ENTRYPOINT ["/usr/local/bin/silo-server"]
