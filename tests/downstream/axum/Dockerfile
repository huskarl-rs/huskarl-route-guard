FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730
WORKDIR /fixture
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked
USER 65534:65534
CMD ["/fixture/target/debug/route-guard-axum-fixture"]
