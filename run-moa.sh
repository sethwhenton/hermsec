#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HERMSEC_BIN="$SCRIPT_DIR/dist/src/bin/hermsec.js"

if [ ! -f "$HERMSEC_BIN" ]; then
  echo "ERROR: hermsec binary not found at $HERMSEC_BIN. Run 'npm run build' first."
  exit 1
fi

# Source shell profile to load OPENROUTER_API_KEY
if [ -z "$OPENROUTER_API_KEY" ]; then
  if [ -f "$HOME/.zshrc" ]; then
    source "$HOME/.zshrc"
  elif [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc"
  fi
fi

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "ERROR: OPENROUTER_API_KEY not found in environment or shell profile."
  exit 1
fi

# OpenRouter configuration
export HERMSEC_MODEL_PROVIDER=openrouter
export HERMSEC_ALLOW_REMOTE_PROVIDERS=true

PROJECTS=(
  "nodejs-express-app"
  "python-flask-app"
  "java-servlet-app"
  "go-web-app"
  "php-web-app"
  "ruby-rails-app"
  "c-cpp-app"
  "csharp-dotnet-app"
  "rust-web-app"
  "advanced-js-ts-app"
  "supply-chain-project"
  "docker-ci-project"
  "advanced-java-python"
)

BASE_DIR="Test projects/primary_tests"
OUT_BASE=".hermsec/moa-results"

# MoA Low: 3 specialists
echo "=== Running MoA Low (3 specialists) ==="
export HERMSEC_PRODUCT_AGENT_PANEL=low
export HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT=3
export HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT=60

for proj in "${PROJECTS[@]}"; do
  echo "  Scanning: $proj"
  node "$HERMSEC_BIN" scan "$BASE_DIR/$proj" \
    --mode online \
    --assist-mode scanner-moa-assisted \
    --out "$OUT_BASE/moa-low/$proj" \
    --json 2>/dev/null || echo "  FAILED: $proj"
done

# MoA Mid: 3 specialists (default)
echo "=== Running MoA Mid (3 specialists, default) ==="
unset HERMSEC_PRODUCT_AGENT_PANEL
export HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT=3
export HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT=80

for proj in "${PROJECTS[@]}"; do
  echo "  Scanning: $proj"
  node "$HERMSEC_BIN" scan "$BASE_DIR/$proj" \
    --mode online \
    --assist-mode scanner-moa-assisted \
    --out "$OUT_BASE/moa-mid/$proj" \
    --json 2>/dev/null || echo "  FAILED: $proj"
done

# MoA High: 5 specialists
echo "=== Running MoA High (5 specialists) ==="
export HERMSEC_PRODUCT_AGENT_PANEL=high
export HERMSEC_PRODUCT_AGENT_SPECIALIST_COUNT=5
export HERMSEC_PRODUCT_AGENT_CANDIDATE_LIMIT=120

for proj in "${PROJECTS[@]}"; do
  echo "  Scanning: $proj"
  node "$HERMSEC_BIN" scan "$BASE_DIR/$proj" \
    --mode online \
    --assist-mode scanner-moa-assisted \
    --out "$OUT_BASE/moa-high/$proj" \
    --json 2>/dev/null || echo "  FAILED: $proj"
done

echo "=== All scans complete ==="
echo "Results in: $OUT_BASE/"
