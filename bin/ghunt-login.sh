#!/usr/bin/env bash
# bin/ghunt-login.sh — one-time GHunt OAuth setup via GHunt Companion extension
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BOLD}GHunt login${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "GHunt needs your Google session cookies from a browser"
echo "where you're already logged into Google."
echo ""
echo -e "${BOLD}Step 1 — Install the GHunt Companion extension${NC}"
echo "  Chrome / Edge / Opera:"
echo "  https://chromewebstore.google.com/detail/dpdcofblfbmmnikcbmmiakkclocadjab"
echo ""
echo "  Firefox:"
echo "  https://addons.mozilla.org/firefox/addon/ghunt-companion/"
echo ""
echo -e "${BOLD}Step 2 — Copy your session${NC}"
echo "  1. Make sure you are logged into Google in that browser"
echo "  2. Click the GHunt Companion extension icon"
echo "  3. Click ${BOLD}\"Send cookies\"${NC} (or \"Copy session as base64\")"
echo "     — it copies a base64 string to your clipboard"
echo ""
echo -e "${BOLD}Step 3 — Paste it below${NC}"
echo ""
echo -e "${YELLOW}Paste the base64 string from the extension and press Enter:${NC}"
read -r B64

if [[ -z "$B64" ]]; then
  echo -e "${RED}✗ Nothing pasted. Aborting.${NC}"
  exit 1
fi

echo ""
echo "Authenticating..."
echo ""

# Pipe option 2 (Companion base64) + the token into ghunt non-interactively
printf "2\n%s\n" "$B64" | \
  docker compose -f "$PROJECT_DIR/docker-compose.yml" \
    run --rm -T \
    --entrypoint /app/.venv/bin/ghunt \
    agent login

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}GHunt authenticated.${NC}"
echo "  Credentials saved — all future scans will include"
echo "  Google account intel automatically."
echo ""
echo "  Run a scan:"
echo "    ./bin/run.sh \"target@gmail.com\""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
