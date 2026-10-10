# syntax=docker/dockerfile:1

# --- Build stage ---
FROM docker.io/library/rust:1-slim-bookworm AS builder
WORKDIR /build/backend

# Build dependencies first so they are cached between code changes
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/clea target/release/deps/clea*

COPY backend/migrations ./migrations
COPY backend/src ./src
RUN cargo build --release --locked

# --- Runtime stage: no shell, no package manager, non-root ---
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app/backend

# The app serves files from ../frontend (relative to the working directory)
COPY --from=builder /build/backend/target/release/clea ./clea
COPY frontend/ /app/frontend/

USER nonroot
EXPOSE 8080
ENTRYPOINT ["./clea"]
