#!/usr/bin/env bash
# drive-plan.sh - loop pi over docs/PLAN.md until no open tasks.
# One model, no fallback (cost=0). 504/timeout -> capped exponential backoff, retry same.
set -uo pipefail
cd "$(dirname "$0")"
PLAN=docs/PLAN.md
VERIFY='./bin/lint.sh && TEST_MODE=true uv run pytest -x -q'

PROVIDER=opencode
MODEL=nemotron-3-ultra-free
BASE=5            # backoff seconds
CAP=300           # max backoff (5min) - free tier, don't hammer
DEAD_AFTER=20     # consecutive fails => endpoint truly down, stop

START_EPOCH=$(date +%s)
ts() {  # timestamped log line: [ISO | +elapsed] msg
  local now el
  now=$(date '+%Y-%m-%d %H:%M:%S')
  el=$(( $(date +%s) - START_EPOCH ))
  printf '[%s | +%02d:%02d:%02d] %s\n' "$now" $((el/3600)) $((el%3600/60)) $((el%60)) "$*"
}

open_count() { grep -cE '^\- \[ \]' "$PLAN"; }

run_turn() {  # retry same model until it lands or DEAD_AFTER
  local log fail=0 t0 dt
  log=$(mktemp)
  while :; do
    ts ">>> turn start (attempt $((fail+1)))"
    t0=$(date +%s)
    if pi -p --continue --provider "$PROVIDER" --model "$MODEL" --thinking high \
         "Read $PLAN. Do FIRST unchecked [ ] task only. Follow 'How to execute'. \
          Run verify. Flip [x] only if green. Stop after one task." 2>&1 | tee "$log"
    then
      dt=$(( $(date +%s) - t0 ))
      grep -qiE '\[504\]|Timeout Occurred|Retry failed' "$log" \
        || { ts "<<< turn ok in ${dt}s"; rm -f "$log"; return 0; }
    else
      dt=$(( $(date +%s) - t0 ))
    fi
    (( ++fail >= DEAD_AFTER )) && { ts "!!! $fail straight fails - endpoint dead, stop"; rm -f "$log"; return 1; }
    local wait=$(( BASE * 2**(fail-1) )); (( wait > CAP )) && wait=$CAP
    wait=$(( wait + RANDOM % 5 ))                       # jitter
    ts "!!! 504/timeout after ${dt}s, fail #$fail, backoff ${wait}s"
    sleep "$wait"
  done
}

ts "=== drive-plan start, $(open_count) open tasks ==="
while (( $(open_count) > 0 )); do
  n=$(open_count)
  run_turn || { ts "gave up - stop for human"; exit 1; }
  eval "$VERIFY" || { ts "verify RED - stop for human"; exit 1; }
  (( $(open_count) < n )) || { ts "no progress - stalled, stop"; exit 1; }
  ts ">>> task landed, $(open_count) open remain"
done
ts "=== all tasks done ==="
