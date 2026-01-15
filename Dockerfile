# StateSet Sequencer Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock* ./

# Create dummy source files to build dependencies (lib + bin + bench targets)
RUN mkdir -p src/bin && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs && \
    echo "fn main() {}" > src/bin/admin.rs && \
    mkdir benches && echo "fn main() {}" > benches/sequencer_bench.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src benches

# Copy actual source code
COPY src ./src
COPY migrations ./migrations
COPY benches ./benches

# Touch source files to rebuild with actual source
RUN touch src/main.rs src/lib.rs src/bin/admin.rs

# Build the actual application
RUN cargo build --release

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
COPY --from=builder /app/target/release/stateset-sequencer /app/stateset-sequencer

# Copy migrations for reference
COPY --from=builder /app/migrations /app/migrations

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
