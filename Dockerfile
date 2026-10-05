# tachi-flow: build the release binary, run it from a data directory.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/tachi-flow /usr/local/bin/tachi-flow
# Desk keys, the escrow key, the admin token and the SQLite state are all
# written to the working directory: mount a persistent volume here.
WORKDIR /data
ENV RUST_LOG=info
CMD ["tachi-flow"]
