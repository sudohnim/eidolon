#!/usr/bin/env bash
# bin/check.sh — verify the osint-agent Docker environment is ready
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  osint-agent environment check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Docker ────────────────────────────────────────────────────────────────────
echo "Docker"
if command -v docker &>/dev/null; then
  ok "docker installed ($(docker --version | awk '{print $3}' | tr -d ','))"
else
  fail "docker not found — install from https://docs.docker.com/get-docker/"
fi

if docker info &>/dev/null 2>&1; then
  ok "Docker daemon running"
else
  fail "Docker daemon not running — start Docker Desktop or dockerd"
fi

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  ok "docker compose available"
else
  fail "docker compose not found — requires Docker Compose v2"
fi

echo ""

# ── .env file ─────────────────────────────────────────────────────────────────
echo ".env"
ENV_FILE="$PROJECT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  ok ".env file exists"
else
  fail ".env file missing — copy .env.example and fill in values"
fi

REQUIRED_VARS=(HIBP_API_KEY APIFY_API_TOKEN APIFY_ACTOR_ID SCRAPFLY_API_KEY)
for var in "${REQUIRED_VARS[@]}"; do
  val=$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"')
  if [[ -n "$val" && "$val" != "your_"* ]]; then
    ok "$var is set"
  else
    fail "$var missing or placeholder in .env"
  fi
done

OPTIONAL_VARS=(LEAKRADAR_API_KEY)
for var in "${OPTIONAL_VARS[@]}"; do
  val=$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"')
  if [[ -n "$val" ]]; then
    ok "$var is set (optional)"
  else
    warn "$var not set — tool will be skipped"
  fi
done

echo ""

# ── Services ──────────────────────────────────────────────────────────────────
echo "Services"

# SpiderFoot
if curl -sf http://localhost:5001/ping &>/dev/null || curl -sf http://localhost:5001/ &>/dev/null; then
  ok "SpiderFoot reachable at localhost:5001"
else
  fail "SpiderFoot not reachable — run: docker compose up -d spiderfoot"
fi

# Ollama
if curl -sf http://localhost:11434/api/tags &>/dev/null; then
  ok "Ollama reachable at localhost:11434"
  # Check model
  if curl -sf http://localhost:11434/api/tags | grep -q "llama3.1"; then
    ok "llama3.1:8b model available"
  else
    fail "llama3.1:8b not pulled — run: docker exec ollama ollama pull llama3.1:8b"
  fi
else
  fail "Ollama not reachable — run: docker compose up -d ollama"
fi

echo ""

# ── Docker images ─────────────────────────────────────────────────────────────
echo "Images"

if docker image inspect osint-agent &>/dev/null 2>&1; then
  ok "osint-agent image built"
else
  warn "osint-agent image not built — run: docker compose build agent"
fi

echo ""

# ── GHunt credentials ─────────────────────────────────────────────────────────
echo "Optional setup"
COMPOSE_PROJECT=$(basename "$PROJECT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
GHUNT_VOL="${COMPOSE_PROJECT}_ghunt_creds"
GHUNT_CREDS=$(docker volume inspect "$GHUNT_VOL" &>/dev/null 2>&1 && \
  docker run --rm -v "${GHUNT_VOL}:/creds" alpine test -f /creds/creds.m 2>/dev/null && echo "yes" || echo "no") 2>/dev/null || GHUNT_CREDS="no"

LOCAL_GHUNT="$HOME/.malfrats/ghunt/creds.m"
if [[ -f "$LOCAL_GHUNT" ]]; then
  ok "GHunt credentials found locally"
elif [[ "$GHUNT_CREDS" == "yes" ]]; then
  ok "GHunt credentials found in Docker volume"
else
  echo ""
  echo -e "  ${YELLOW}!${NC}  GHunt not authenticated"
  echo "     GHunt queries Google's APIs for account intel (Maps reviews, YouTube,"
  echo "     linked services) — currently skipped on every scan."
  echo ""
  echo "     To enable, run this once:"
  echo ""
  echo -e "       ${BOLD}./bin/ghunt-login.sh${NC}"
  echo ""
  echo "     Follow the OAuth prompts. Credentials are saved to a Docker volume"
  echo "     and persist across all future scans automatically."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -eq 0 ]]; then
  echo -e "  ${GREEN}All checks passed${NC} ($PASS passed)"
  echo "  Run a scan: ./bin/run.sh \"target@email.com\""
else
  echo -e "  ${RED}$FAIL check(s) failed${NC}, $PASS passed"
  echo "  Fix the issues above before running scans."
  exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
