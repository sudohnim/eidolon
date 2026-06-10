#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "     $1"; }

ERRORS=0

echo ""
echo "================================================"
echo "  OSINT Agent — Setup & Dependency Check"
echo "================================================"
echo ""

# ── 1. uv ────────────────────────────────────────────
echo "Checking uv..."
if command -v uv &>/dev/null; then
    ok "uv $(uv --version)"
else
    warn "uv not found — installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
    if command -v uv &>/dev/null; then
        ok "uv installed"
    else
        fail "uv install failed — install manually: https://astral.sh/uv"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── 2. Python deps ───────────────────────────────────
echo ""
echo "Installing Python dependencies..."
cd "$(dirname "$0")/.."
if uv sync --extra dev 2>&1 | tail -3; then
    ok "Python dependencies installed"
else
    fail "uv sync failed"
    ERRORS=$((ERRORS + 1))
fi

# ── 2b. Pre-commit lint hook ─────────────────────────
echo ""
echo "Enabling pre-commit lint hook..."
if [ -f ".githooks/pre-commit" ]; then
    chmod +x .githooks/pre-commit
    git config core.hooksPath .githooks
    ok "pre-commit hook enabled (runs lint checks on staged files)"
else
    warn ".githooks/pre-commit not found — skipping hook setup"
fi

# ── 3. .env ──────────────────────────────────────────
echo ""
echo "Checking .env..."
if [ ! -f ".env" ]; then
    fail ".env not found — copy the template and fill in your keys:"
    info "cp .env.example .env"
    ERRORS=$((ERRORS + 1))
else
    REQUIRED_VARS=(
        HIBP_API_KEY
        APIFY_API_TOKEN
        APIFY_ACTOR_ID
        SCRAPFLY_API_KEY
        GOOGLE_CSE_API_KEY
        GOOGLE_CSE_ID
        OLLAMA_HOST
        SPIDERFOOT_HOST
    )
    MISSING=()
    for var in "${REQUIRED_VARS[@]}"; do
        val=$(grep "^${var}=" .env | cut -d= -f2-)
        if [ -z "$val" ]; then
            MISSING+=("$var")
        fi
    done
    if [ ${#MISSING[@]} -eq 0 ]; then
        ok ".env present and all required vars populated"
    else
        fail ".env is missing values for:"
        for var in "${MISSING[@]}"; do
            info "  - $var"
        done
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── 4. Ollama ────────────────────────────────────────
echo ""
echo "Checking Ollama..."
if ! command -v ollama &>/dev/null; then
    warn "ollama not found — installing..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

if curl -sf http://localhost:11434 &>/dev/null; then
    ok "Ollama is running"
else
    warn "Ollama is not running — starting..."
    ollama serve &>/dev/null &
    sleep 3
    if curl -sf http://localhost:11434 &>/dev/null; then
        ok "Ollama started"
    else
        fail "Could not start Ollama — start it manually: ollama serve"
        ERRORS=$((ERRORS + 1))
    fi
fi

echo ""
echo "Checking llama3.1:8b model..."
if ollama list 2>/dev/null | grep -q "llama3.1:8b"; then
    ok "llama3.1:8b model present"
else
    warn "llama3.1:8b not found — pulling (this may take a few minutes)..."
    if ollama pull llama3.1:8b; then
        ok "llama3.1:8b pulled"
    else
        fail "Failed to pull llama3.1:8b"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── 5. Docker ────────────────────────────────────────
echo ""
echo "Checking Docker..."
if ! command -v docker &>/dev/null; then
    fail "Docker not found — install Docker Desktop: https://www.docker.com/products/docker-desktop"
    ERRORS=$((ERRORS + 1))
else
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

    # ── 6. SpiderFoot ─────────────────────────────────
    echo ""
    echo "Checking SpiderFoot..."
    if docker ps --format '{{.Names}}' | grep -q "^spiderfoot$"; then
        ok "SpiderFoot container is running"
    elif docker ps -a --format '{{.Names}}' | grep -q "^spiderfoot$"; then
        warn "SpiderFoot container exists but is stopped — starting..."
        docker start spiderfoot
        sleep 2
        ok "SpiderFoot started"
    else
        warn "SpiderFoot container not found — building from source..."
        SPIDERFOOT_DIR="$HOME/spiderfoot"
        if [ ! -d "$SPIDERFOOT_DIR" ]; then
            git clone https://github.com/smicallef/spiderfoot.git "$SPIDERFOOT_DIR"
        fi
        docker build -t spiderfoot "$SPIDERFOOT_DIR"
        docker run -d -p 5001:5001 --name spiderfoot spiderfoot
        sleep 3
        ok "SpiderFoot built and started"
    fi

    echo ""
    echo "Verifying SpiderFoot at localhost:5001..."
    if curl -sf http://localhost:5001 &>/dev/null; then
        ok "SpiderFoot UI is reachable"
    else
        fail "SpiderFoot not reachable at localhost:5001"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── 7. Run tests in TEST_MODE ────────────────────────
echo ""
echo "Running test suite in TEST_MODE..."
if TEST_MODE=true uv run pytest tests/ -q 2>&1; then
    ok "All tests pass"
else
    fail "Tests failed — fix before running against real endpoints"
    ERRORS=$((ERRORS + 1))
fi

# ── Summary ──────────────────────────────────────────
echo ""
echo "================================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}  All checks passed. Ready to run:${NC}"
    echo ""
    echo '  uv run python main.py "your@email.com"'
else
    echo -e "${RED}  $ERRORS check(s) failed. Fix the errors above before running.${NC}"
fi
echo "================================================"
echo ""

exit $ERRORS
