# StateSet Sequencer Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM rust:latest AS builder

WORKDIR /workspace

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests and local path dependencies for build caching
COPY stateset-sequencer/Cargo.toml stateset-sequencer/Cargo.lock* ./stateset-sequencer/
COPY stateset-stark ./stateset-stark

# Create dummy source files to build dependencies (lib + bin + bench targets)
WORKDIR /workspace/stateset-sequencer
RUN mkdir -p src/bin && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs && \
    echo "fn main() {}" > src/bin/admin.rs && \
    mkdir benches && echo "fn main() {}" > benches/sequencer_bench.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src benches

# Copy actual source code

# Copy build script and application sources for real build
COPY stateset-sequencer/build.rs ./build.rs
COPY stateset-sequencer/src ./src
COPY stateset-sequencer/migrations ./migrations
COPY stateset-sequencer/benches ./benches
COPY stateset-sequencer/proto ./proto

# Build the actual application
RUN cargo build --release --manifest-path /workspace/stateset-sequencer/Cargo.toml

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false sequencer

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /workspace/stateset-sequencer/target/release/stateset-sequencer /app/stateset-sequencer

# Copy migrations for reference
COPY --from=builder /workspace/stateset-sequencer/migrations /app/migrations

# Set ownership
RUN chown -R sequencer:sequencer /app

# Switch to non-root user
USER sequencer

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment variables
ENV RUST_LOG=info
ENV HOST=0.0.0.0
ENV PORT=8080

# Run the application
CMD ["/app/stateset-sequencer"]
