.PHONY: help
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Development
.PHONY: dev install build run
.PHONY: test test-unit test-integration test-coverage
.PHONY: lint fmt clippy check
.PHONY: clean

dev: ## Quick setup for local development (install deps, build, start services)
	@echo "Setting up development environment..."
	@make install
	@make check
	@make docker-up
	@echo "Development environment ready!"
	@echo "Run 'make run' to start the sequencer"
	@echo "Or use 'docker-compose up' with existing services"

install: ## Install dependencies
	@echo "Installing Rust dependencies..."
	cargo fetch

build: ## Build the project (debug)
	cargo build

build-release: ## Build the project (release)
	cargo build --release

run: ## Run the sequencer (debug)
	@echo "Starting sequencer in debug mode..."
	@docker-compose up -d postgres
	@sleep 3
	cargo run

run-release: ## Run the sequencer (release)
	@echo "Starting sequencer in release mode..."
	@docker-compose up -d postgres
	@sleep 3
	cargo run --release

## Testing
test: ## Run all tests
	cargo test

test-unit: ## Run unit tests only
	cargo test -- --ignored

test-integration: ## Run integration tests only
	cargo test -- --ignored

test-coverage: ## Generate test coverage report
	@echo "Requires cargo-tarpaulin: cargo install cargo-tarpaulin"
	cargo tarpaulin --out Html --output-dir coverage --timeout 300

## Code Quality
lint: clippy fmt-check ## Run all linters

fmt: ## Format code
	cargo fmt

fmt-check: ## Check code formatting
	cargo fmt --all -- --check

clippy: ## Run clippy linter
	cargo clippy --all-targets -- -D warnings

check: fmt check ## Check code quality (format + clippy)
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings

## Docker
docker-build: ## Build Docker image
	docker build -t stateset-sequencer:latest .

docker-up: ## Start services with docker-compose
	docker-compose up -d

docker-down: ## Stop services
	docker-compose down

docker-logs: ## Show docker-compose logs
	docker-compose logs -f

## Database
migrate: ## Run database migrations
	@echo "Running migrations..."
	cargo run --bin stateset-sequencer-admin -- migrate

migrate-backfill: ## Backfill VES state roots
	cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

## Utilities
clean: ## Clean build artifacts
	cargo clean
	@rm -rf coverage/

deps-update: ## Update dependencies
	cargo update

deps-outdated: ## Check for outdated dependencies
	@echo "Install cargo-outdated: cargo install cargo-outdated"
	cargo outdated

## CI/CD
ci: ## Run CI checks locally
	@echo "Running CI checks..."
	@make check
	@make test
	@echo "CI checks passed!"

## Admin
admin-migrate: ## Run admin migration
	cargo run --bin stateset-sequencer-admin -- migrate

admin-backfill: ## Backfill VES state roots (dry-run)
	cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots --dry-run

admin-backfill-apply: ## Backfill VES state roots (apply changes)
	cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

## Benchmarks
bench: ## Run benchmarks
	cargo bench

bench-criterion: ## Run benchmarks with Criterion output
	cargo bench -- --output-format bencher

## Security
audit: ## Run security audit
	@echo "Install cargo-audit: cargo install cargo-audit"
	cargo audit

deny: ## Run cargo-deny checks
	@echo "Install cargo-deny: cargo install cargo-deny"
	cargo deny check licenses bans advisories

## Documentation
docs: ## Generate and open documentation
	cargo doc --open

docs-check: ## Check documentation coverage
	@echo "Checking for undocumented public items..."
	cargo doc --no-deps --document-private-items 2>&1 | grep -i "warning: missing documentation" || echo "All public items documented!"

## Tags (for code navigation)
tags: ## Generate ctags
	ctags -R --exclude=target --exclude=.git .

## Environment
env-example: ## Copy .env.example to .env
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example..."; \
		cp .env.example .env; \
		echo "Please edit .env with your configuration"; \
	else \
		echo ".env already exists"; \
	fi