#!/bin/bash

# VES End-to-End Integration Test Runner
# Tests VES-CONTRACT-1, VES-MULTI-1, VES-STARK-1 integration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              VES E2E Integration Test Suite                      ║"
echo "║                                                                  ║"
echo "║  Testing:                                                        ║"
echo "║    • VES-CONTRACT-1 (Smart Contract Integration)                 ║"
echo "║    • VES-MULTI-1 (Multi-Agent Coordination)                      ║"
echo "║    • VES-STARK-1 (Validity Proofs)                               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Node.js version
NODE_VERSION=$(node -v 2>/dev/null || echo "not found")
if [[ "$NODE_VERSION" == "not found" ]]; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    exit 1
fi

MAJOR_VERSION=$(echo "$NODE_VERSION" | cut -d'.' -f1 | tr -d 'v')
if [[ "$MAJOR_VERSION" -lt 18 ]]; then
    echo -e "${YELLOW}Warning: Node.js 18+ recommended (found $NODE_VERSION)${NC}"
fi

echo -e "${BLUE}Node.js version: $NODE_VERSION${NC}"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Run the tests
echo -e "${BLUE}Running E2E integration tests...${NC}"
echo ""

START_TIME=$(date +%s%N)

if node --experimental-vm-modules tests/e2e/ves-integration.test.mjs; then
    END_TIME=$(date +%s%N)
    DURATION=$(( (END_TIME - START_TIME) / 1000000 ))

    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    ALL TESTS PASSED                              ║"
    echo "║                                                                  ║"
    echo "║  Total execution time: ${DURATION}ms                                    "
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 0
else
    END_TIME=$(date +%s%N)
    DURATION=$(( (END_TIME - START_TIME) / 1000000 ))

    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    TESTS FAILED                                  ║"
    echo "║                                                                  ║"
    echo "║  Total execution time: ${DURATION}ms                                    "
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 1
fi
