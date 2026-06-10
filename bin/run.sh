#!/usr/bin/env bash
# bin/run.sh — run an osint-agent scan
# Usage: ./bin/run.sh --email target@example.com
#        ./bin/run.sh --name "John Smith" --state CA
#        ./bin/run.sh --email addr@example.com --name "John Smith" --state CA --phone +14155550100
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Usage ─────────────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
  echo ""
  echo -e "${BOLD}Usage:${NC}"
  echo "  ./bin/run.sh --email target@example.com"
  echo "  ./bin/run.sh --name \"John Smith\" --state CA"
  echo "  ./bin/run.sh --name \"John Smith\" --city \"San Francisco\" --state CA --zip 94102"
  echo "  ./bin/run.sh --email target@example.com --name \"John Smith\" --state NY --phone +14155550100"
  echo ""
  echo -e "${BOLD}Flags:${NC}"
  echo "  --email   Target email address"
  echo "  --phone   Target phone number"
  echo "  --name    Target full name  (requires at least one of: --city, --state, --zip)"
  echo "  --city    Target city       (narrows broker search results)"
  echo "  --state   Target state, e.g. CA or 'California'  (required with --name)"
  echo "  --zip     Target zip code   (further narrows broker search)"
  echo ""
  echo "At least one of --email, --phone, or --name is required."
  echo "When using --name, you must also provide --city, --state, or --zip."
  echo ""
  exit 1
fi

# Forward all flags to main.py — validation/sanitization happens there
AGENT_ARGS=("$@")

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BOLD}osint-agent${NC}"
echo "  Inputs: ${AGENT_ARGS[*]}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
echo -e "${BOLD}Running pre-flight checks...${NC}"

# Docker daemon
if ! docker info &>/dev/null 2>&1; then
  echo -e "${RED}✗ Docker daemon not running. Start Docker Desktop first.${NC}"
  exit 1
fi

# .env
if [[ ! -f "$PROJECT_DIR/.env" ]]; then
  echo -e "${RED}✗ .env file missing. Copy .env.example and fill in values.${NC}"
  exit 1
fi

# ── Helper: wait for a container to be Docker-healthy ─────────────────────────
wait_healthy() {
  local service="$1"
  local label="$2"
  local max_wait=120  # seconds
  local waited=0

  while [[ $waited -lt $max_wait ]]; do
    local status
    # Find the container for this compose service (project dir based name)
    status=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" ps --format json "$service" 2>/dev/null \
      | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0].get('Health','') if data else '')" 2>/dev/null || echo "")

    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    sleep 3
    waited=$((waited + 3))
    if (( waited % 15 == 0 )); then
      echo "  Still waiting for $label... (${waited}s)"
    fi
  done

  echo -e "${RED}✗ $label did not become healthy after ${max_wait}s${NC}"
  echo "  Check logs: docker compose logs $service"
  exit 1
}

# ── SpiderFoot ────────────────────────────────────────────────────────────────
SF_UP=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" ps --format json spiderfoot 2>/dev/null \
  | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0].get('Health','') if data else '')" 2>/dev/null || echo "")

if [[ "$SF_UP" != "healthy" ]]; then
  echo -e "${YELLOW}! SpiderFoot not healthy. Starting...${NC}"
  docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d spiderfoot
  wait_healthy spiderfoot SpiderFoot
fi
echo -e "${GREEN}✓ SpiderFoot healthy${NC}"

# ── Ollama ────────────────────────────────────────────────────────────────────
OL_UP=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" ps --format json ollama 2>/dev/null \
  | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0].get('Health','') if data else '')" 2>/dev/null || echo "")

if [[ "$OL_UP" != "healthy" ]]; then
  echo -e "${YELLOW}! Ollama not healthy. Starting...${NC}"
  docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d ollama
  wait_healthy ollama Ollama
fi
echo -e "${GREEN}✓ Ollama healthy${NC}"

# ── Check llama3.1 model ──────────────────────────────────────────────────────
if ! curl -sf http://localhost:11434/api/tags | grep -q "llama3.1"; then
  echo -e "${YELLOW}! llama3.1:8b not found. Pulling (this may take a while)...${NC}"
  docker compose -f "$PROJECT_DIR/docker-compose.yml" exec ollama ollama pull llama3.1:8b
fi
echo -e "${GREEN}✓ llama3.1:8b model ready${NC}"

# ── Build agent image if needed ───────────────────────────────────────────────
if ! docker image inspect osint-agent &>/dev/null 2>&1; then
  echo -e "${YELLOW}! osint-agent image not found. Building...${NC}"
  docker compose -f "$PROJECT_DIR/docker-compose.yml" build agent
fi
echo -e "${GREEN}✓ osint-agent image ready${NC}"

# ── GHunt nudge ───────────────────────────────────────────────────────────────
COMPOSE_PROJECT=$(basename "$PROJECT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
GHUNT_VOL="${COMPOSE_PROJECT}_ghunt_creds"
GHUNT_CREDS=$(docker volume inspect "$GHUNT_VOL" &>/dev/null 2>&1 && \
  docker run --rm -v "${GHUNT_VOL}:/creds" alpine test -f /creds/creds.m 2>/dev/null && echo "yes" || echo "no") 2>/dev/null || GHUNT_CREDS="no"
LOCAL_GHUNT="$HOME/.malfrats/ghunt/creds.m"

if [[ ! -f "$LOCAL_GHUNT" && "$GHUNT_CREDS" != "yes" ]]; then
  echo -e "${RED}✗ GHunt not authenticated — scan blocked.${NC}"
  echo ""
  echo "  GHunt finds Google account intel (Maps reviews, YouTube, linked"
  echo "  services) and requires a one-time setup using your browser."
  echo ""
  echo "  Run this now, then re-run your scan:"
  echo ""
  echo -e "    ${BOLD}./bin/ghunt-login.sh${NC}"
  echo ""
  exit 1
fi

echo -e "${GREEN}✓ All services ready${NC}"
echo ""

# ── Run scan ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}Starting scan...${NC}"
echo ""

mkdir -p "$PROJECT_DIR/output"

docker compose -f "$PROJECT_DIR/docker-compose.yml" run --rm --no-deps agent "${AGENT_ARGS[@]}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}Scan complete.${NC} Reports saved to ./output/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
