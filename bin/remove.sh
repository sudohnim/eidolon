#!/usr/bin/env bash
# bin/remove.sh — Data broker opt-out automation
#
# Usage:
#   ./bin/remove.sh                                        # uses most recent results file
#   ./bin/remove.sh output/2026-06-07_18-21_email_results.json
#   ./bin/remove.sh output/2026-06-07_18-21_email_results.json --visible
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Parse args ────────────────────────────────────────────────────────────────
RESULTS_FILE=""
EXTRA_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --visible)
      EXTRA_ARGS+=("--visible")
      ;;
    --*)
      EXTRA_ARGS+=("$arg")
      ;;
    *)
      RESULTS_FILE="$arg"
      ;;
  esac
done

# ── Find results file ─────────────────────────────────────────────────────────
if [[ -z "$RESULTS_FILE" ]]; then
  # Find most recent *_results.json in output/
  RESULTS_FILE=$(ls -1t "$PROJECT_DIR/output/"*_results.json 2>/dev/null | head -1 || true)
  if [[ -z "$RESULTS_FILE" ]]; then
    echo -e "${RED}ERROR: No results JSON files found in output/.${NC}"
    echo "  Run a scan first:  ./bin/run.sh --email target@example.com"
    exit 1
  fi
  echo -e "${YELLOW}Using most recent results file:${NC} $(basename "$RESULTS_FILE")"
fi

if [[ ! -f "$RESULTS_FILE" ]]; then
  echo -e "${RED}ERROR: File not found: $RESULTS_FILE${NC}"
  exit 1
fi

# ── Extract broker info for confirmation prompt ───────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BOLD}eidolon  |  Removal Bot${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  Results file: ${BOLD}$(basename "$RESULTS_FILE")${NC}"
echo ""

# Parse brokers_found from JSON (portable, no jq required)
BROKERS_FOUND=$(python3 - <<'PYEOF'
import json, sys, pathlib, os

path = os.environ.get("RESULTS_FILE", "")
if not path:
    sys.exit(0)

try:
    data = json.loads(pathlib.Path(path).read_text())
    brokers = data.get("broker_result", {}).get("data", {}).get("brokers_found", [])
    if brokers:
        for b in brokers:
            name = b.get("broker_name") or b.get("source") or "Unknown"
            domain = b.get("broker_domain", "")
            print(f"  • {name}" + (f" ({domain})" if domain else ""))
    else:
        print("  (none detected — will attempt all 5 supported brokers)")
except Exception as e:
    print(f"  (could not parse: {e})")
PYEOF
)
export RESULTS_FILE

echo "  Brokers found in scan:"
echo "$BROKERS_FOUND"
echo ""
echo "  Will attempt opt-out for:"
echo "    • FastPeopleSearch"
echo "    • TruePeopleSearch"
echo "    • Spokeo"
echo "    • BeenVerified"
echo "    • Whitepages"
echo ""
echo -e "${YELLOW}Note:${NC} This will open a browser (headless by default) and submit"
echo "opt-out forms on your behalf. Confirmation emails may be sent to"
echo "the target email address. Screenshots are saved to output/removal_screenshots/."
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
read -rp "Proceed with opt-out submissions? [y/N] " CONFIRM
case "$CONFIRM" in
  [yY][eE][sS]|[yY])
    echo ""
    ;;
  *)
    echo "Aborted."
    exit 0
    ;;
esac

# ── Pre-flight: Docker ────────────────────────────────────────────────────────
if ! docker info &>/dev/null 2>&1; then
  echo -e "${RED}ERROR: Docker daemon not running. Start Docker Desktop first.${NC}"
  exit 1
fi

# ── Check agent image exists ──────────────────────────────────────────────────
REMOVAL_IMAGE="eidolon"
if ! docker image inspect "$REMOVAL_IMAGE" &>/dev/null 2>&1; then
  echo -e "${RED}ERROR: eidolon image not found. Build it first:${NC}"
  echo "  docker compose build eidolon"
  exit 1
fi

# ── Convert results path to container-relative path ──────────────────────────
# The container mounts ./output at /app/output
RESULTS_BASENAME=$(basename "$RESULTS_FILE")
CONTAINER_RESULTS="/app/output/$RESULTS_BASENAME"

# ── Run ───────────────────────────────────────────────────────────────────────
echo -e "${BOLD}Starting opt-out automation...${NC}"
echo ""

mkdir -p "$PROJECT_DIR/output/removal_screenshots"

docker run --rm \
  --name osint-removal-run \
  --entrypoint "uv" \
  -v "$PROJECT_DIR/output:/app/output" \
  "$REMOVAL_IMAGE" \
  run python bin/removal.py \
  "$CONTAINER_RESULTS" \
  "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"

echo ""
echo -e "${GREEN}Done.${NC} Screenshots saved to output/removal_screenshots/"
