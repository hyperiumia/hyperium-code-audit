#!/bin/bash
set -e

SCAN_PATH="${1:-.}"
FORMAT="${2:-sarif}"
MIN_CONF="${3:-0.5}"
SKIP_SECRETS="${4:-false}"
SKIP_DEPS="${5:-false}"
SKIP_PAYMENT="${6:-false}"
FAIL_ON="${7:-critical}"

ARGS="scan $SCAN_PATH --format $FORMAT --min-confidence $MIN_CONF"

if [ "$SKIP_SECRETS" = "true" ]; then ARGS="$ARGS --no-secrets"; fi
if [ "$SKIP_DEPS" = "true" ]; then ARGS="$ARGS --no-deps"; fi
if [ "$SKIP_PAYMENT" = "true" ]; then ARGS="$ARGS --no-payment"; fi

echo "🔍 Hyperium Code-Audit — Scanning $SCAN_PATH"
echo "   Format: $FORMAT | Confidence: $MIN_CONF | Fail on: $FAIL_ON"

python -m src.cli $ARGS || EXIT_CODE=$?

# Find the output file
RESULTS=$(find ./reports -name "*.sarif" -o -name "*.json" -o -name "*.html" 2>/dev/null | head -1)
if [ -n "$RESULTS" ]; then
    echo "results-path=$RESULTS" >> "$GITHUB_OUTPUT"
fi

# Extract risk score from JSON if available
if [ -f "./reports/"*.json ]; then
    SCORE=$(python -c "
import json, glob
files = glob.glob('./reports/*.json')
if files:
    data = json.load(open(files[0]))
    score = data.get('risk_score', {}).get('overall_score', 0)
    total = data.get('total_findings', 0)
    print(f'risk-score={score}')
    print(f'total-findings={total}')
" 2>/dev/null)
    echo "$SCORE" >> "$GITHUB_OUTPUT"
fi

# Exit code handling
if [ "${EXIT_CODE:-0}" -ne 0 ]; then
    case "$FAIL_ON" in
        critical) echo "::warning::Critical findings detected" ;;
        high)     echo "::warning::High findings detected" ;;
        *)        echo "::error::Findings detected (fail-on: $FAIL_ON)" ;;
    esac
fi

exit ${EXIT_CODE:-0}
