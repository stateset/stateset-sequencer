# Contributing to StateSet Sequencer

Thank you for your interest in contributing to the StateSet Sequencer! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Documentation](#documentation)

## Code of Conduct

Please be respectful and constructive in all interactions. We're building something together.

## Getting Started

### Prerequisites

- **Rust**: 1.70+ (install via [rustup](https://rustup.rs/))
- **PostgreSQL**: 14+ (or Docker)
- **Docker & Docker Compose**: For integration tests
- **Git**: For version control

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/stateset-sequencer.git
   cd stateset-sequencer
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/stateset/stateset-sequencer.git
   ```

## Development Setup

### Install Dependencies

```bash
# Install Rust toolchain
rustup update stable
rustup component add clippy rustfmt

# Install sqlx-cli for migrations
cargo install sqlx-cli --features postgres

# Install cargo-watch for development
cargo install cargo-watch
```

### Database Setup

**Option 1: Docker (Recommended)**
```bash
docker-compose up -d postgres
```

**Option 2: Local PostgreSQL**
```bash
createdb stateset_sequencer
export DATABASE_URL="postgres://localhost/stateset_sequencer"
```

### Run Migrations

```bash
sqlx migrate run
```

### Build and Run

```bash
# Development build
cargo build

# Run the sequencer
cargo run

# Watch mode (auto-reload on changes)
cargo watch -x run
```

### Verify Setup

```bash
# Health check
curl http://localhost:8080/health

# Run tests
cargo test
```

## Making Changes

### Branch Naming

Create a branch for your changes:

```bash
git checkout -b <type>/<description>
```

Types:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/improvements
- `chore/` - Maintenance tasks

Examples:
- `feature/add-grpc-support`
- `fix/sequence-counter-race`
- `docs/improve-api-reference`

### Commit Messages

Follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(api): add batch event ingestion endpoint

fix(sequencer): handle concurrent sequence assignment

docs(readme): update installation instructions
```

### Keep Changes Focused

- One logical change per commit
- One feature/fix per pull request
- Keep PRs small and reviewable (< 500 lines ideal)

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Tests

```bash
# Run tests matching a pattern
cargo test test_sign_and_verify

# Run tests in a specific module
cargo test crypto::signing

# Run with output
cargo test -- --nocapture
```

### Integration Tests

```bash
# Start dependencies
docker-compose up -d

# Run integration tests
cargo test --test integration

# Stop dependencies
docker-compose down
```

### Test Coverage

```bash
# Install coverage tool
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

### Writing Tests

Place tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        // Arrange
        let input = "test";

        // Act
        let result = do_something(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_something() {
        // Async test
        let result = async_operation().await;
        assert!(result.is_ok());
    }
}
```

For integration tests, create files in `tests/`:

```rust
// tests/integration.rs
use stateset_sequencer::*;

#[tokio::test]
async fn test_full_workflow() {
    // Test end-to-end scenarios
}
```

## Submitting Changes

### Before Submitting

1. **Format code:**
   ```bash
   cargo fmt
   ```

2. **Run linter:**
   ```bash
   cargo clippy -- -D warnings
   ```

3. **Run tests:**
   ```bash
   cargo test
   ```

4. **Update documentation** if needed

5. **Rebase on latest main:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Pull Request Process

1. Push your branch:
   ```bash
   git push origin feature/your-feature
   ```

2. Open a Pull Request on GitHub

3. Fill out the PR template:
   ```markdown
   ## Summary
   Brief description of changes

   ## Changes
   - Change 1
   - Change 2

   ## Testing
   How was this tested?

   ## Checklist
   - [ ] Tests added/updated
   - [ ] Documentation updated
   - [ ] `cargo fmt` run
   - [ ] `cargo clippy` passes
   ```

4. Request review from maintainers

5. Address review feedback

6. Once approved, maintainer will merge

### PR Review Guidelines

We look for:
- Correct functionality
- Test coverage
- Code clarity
- Performance considerations
- Security implications
- Documentation

## Code Style

### Rust Style

Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

```rust
// Use descriptive names
fn calculate_merkle_root(leaves: &[Hash256]) -> Hash256 {
    // Implementation
}

// Document public APIs
/// Computes the Merkle root for a set of leaf hashes.
///
/// # Arguments
/// * `leaves` - The leaf node hashes to include in the tree
///
/// # Returns
/// The 32-byte Merkle root hash
///
/// # Example
/// ```
/// let root = calculate_merkle_root(&leaves);
/// ```
pub fn calculate_merkle_root(leaves: &[Hash256]) -> Hash256 {
    // Implementation
}

// Use Result for fallible operations
pub fn verify_signature(key: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), VerifyError> {
    // Implementation
}

// Prefer explicit error types over anyhow in library code
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid signature format")]
    InvalidSignatureFormat,

    #[error("verification failed")]
    VerificationFailed,
}
```

### Formatting

Use `rustfmt` defaults:

```bash
# Format all code
cargo fmt

# Check formatting without changing
cargo fmt -- --check
```

### Linting

Address all clippy warnings:

```bash
# Run clippy
cargo clippy -- -D warnings

# Allow specific lints when justified
#[allow(clippy::too_many_arguments)]
fn complex_function(...) { }
```

## Documentation

### Code Documentation

Document all public items:

```rust
//! Module-level documentation
//!
//! This module provides...

/// Function documentation
///
/// # Arguments
/// * `param` - Description
///
/// # Returns
/// Description of return value
///
/// # Errors
/// When this function can fail
///
/// # Examples
/// ```
/// let result = function(param);
/// ```
pub fn function(param: Type) -> Result<Output, Error> {
    // Implementation
}
```

### Building Docs

```bash
# Generate documentation
cargo doc --open

# Include private items
cargo doc --document-private-items
```

### Markdown Documentation

- Use ATX-style headers (`#`, `##`, `###`)
- Use fenced code blocks with language hints
- Include examples where helpful
- Keep line length reasonable (~100 chars)

## Architecture Overview

### Module Structure

```
src/
├── main.rs           # Entry point
├── lib.rs            # Library root
├── api/              # HTTP handlers
├── domain/           # Core types
├── infra/            # Infrastructure (DB, external services)
├── auth/             # Authentication
├── crypto/           # Cryptographic operations
├── projection/       # Event projection
└── anchor.rs         # On-chain anchoring
```

### Key Abstractions

- **Traits**: Define interfaces in `infra/traits.rs`
- **Domain Types**: Pure data structures in `domain/`
- **Implementations**: Concrete implementations in `infra/postgres/`

### Adding New Features

1. Define types in `domain/`
2. Define trait in `infra/traits.rs`
3. Implement trait in `infra/postgres/` (or other backend)
4. Add API endpoints in `api/` or `main.rs`
5. Add tests at each layer

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email security@stateset.io (do not open public issue)

## Recognition

Contributors are recognized in:
- GitHub contributors list
- Release notes
- CONTRIBUTORS.md (for significant contributions)

Thank you for contributing!
