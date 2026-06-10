#!/usr/bin/env bash
# bin/lint.sh — run black, isort, flake8, and mypy
# Usage:
#   ./bin/lint.sh          # check only (no changes)
#   ./bin/lint.sh --fix    # auto-fix black + isort, then check
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

FIX=false
if [[ "${1:-}" == "--fix" ]]; then
  FIX=true
fi

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

FAILED=0

run_check() {
  local name="$1"
  shift
  echo -e "\n${BOLD}── $name${NC}"
  if "$@"; then
    echo -e "${GREEN}✓ $name passed${NC}"
  else
    echo -e "${RED}✗ $name failed${NC}"
    FAILED=$((FAILED + 1))
  fi
}

if $FIX; then
  echo -e "${BOLD}Auto-fixing with black and isort...${NC}"
  uv run black .
  uv run isort .
  echo ""
fi

run_check "black"  uv run black --check .
run_check "isort"  uv run isort --check-only .
run_check "flake8" uv run flake8 eidolon/
run_check "mypy"   uv run --with mypy mypy eidolon/

echo ""
if [[ $FAILED -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}All checks passed.${NC}"
else
  echo -e "${RED}${BOLD}$FAILED check(s) failed.${NC}"
  exit 1
fi
