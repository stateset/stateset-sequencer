#!/bin/bash
set -e

echo "🆕 Setting up new developer environment..."

if [ -f ".env" ]; then
  echo "⚠️  .env file already exists. Skipping template copy."
else
  echo "📋 Creating .env from template..."
  cp .env.example .env
fi

echo "🐳 Starting PostgreSQL container..."
docker-compose up -d postgres

echo "⏳ Waiting for database to be ready..."
sleep 5

until docker-compose exec -T pg_isready -U sequencer -d stateset_sequencer 2>/dev/null; do
  echo "⏳ Waiting for postgres..."
  sleep 2
done

echo "📦 Installing Rust dependencies..."
cargo install --quiet cargo-tarpaulin cargo-audit cargo-deny 2>/dev/null || true

echo "🛠️  Building project..."
cargo build --quiet || cargo build

echo "📊 Running database migrations..."
cargo run --quiet --bin stateset-sequencer-admin -- migrate 2>/dev/null || true

echo ""
echo "✅ Developer environment setup complete!"
echo ""
echo "Quick commands:"
echo "  make run              - Start the sequencer"
echo "  make test             - Run tests"
echo "  make docker-logs      - View logs"
echo "  make test-coverage    - Generate coverage report"
echo ""