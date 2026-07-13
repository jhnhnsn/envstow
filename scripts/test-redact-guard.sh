#!/usr/bin/env bash
# Behavioral test for redact-guard.sh.
#
# Proves the two claims that matter:
#   1. A tool result containing a LIVE secret value is BLOCKED (exit 2).
#   2. A tool result that only references a secret by NAME is ALLOWED (exit 0).
#   3. A base64-encoded copy of the secret is also BLOCKED (evasion attempt).
#
# The guard compares against the live environment, so we export a fake secret
# here and let the child hook inherit it. The fake value never touches a real
# secret store; it is a random-looking literal defined below.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/redact-guard.sh"

# A fake, obviously-not-real secret value used only for this test.
export FAKE_API_TOKEN="sk-test-9d4f2a7c1e8b0000dEADbeef"

fail=0
run_case() {
  local desc="$1" expected="$2" payload="$3"
  local got=0
  printf '%s' "$payload" | "$guard" >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$expected" ]; then
    echo "ok   - $desc (exit $got)"
  else
    echo "FAIL - $desc (expected $expected, got $got)"
    fail=1
  fi
}

# 1. Leak: the literal value appears in stdout -> blocked (2).
run_case "blocks a leaked secret value" 2 \
  "$(printf '{"tool_response":{"stdout":"the token is %s here"}}' "$FAKE_API_TOKEN")"

# 2. Name-reference only -> allowed (0).
run_case "allows a name reference" 0 \
  '{"tool_response":{"stdout":"using $FAKE_API_TOKEN to authenticate"}}'

# 3. Base64-encoded value -> blocked (2). Guards the common encoding-evasion path.
b64="$(printf '%s' "$FAKE_API_TOKEN" | base64)"
run_case "blocks a base64-encoded secret" 2 \
  "$(printf '{"tool_response":{"stdout":"blob %s"}}' "$b64")"

# 4. Empty / unrelated output -> allowed (0).
run_case "allows unrelated output" 0 \
  '{"tool_response":{"stdout":"build succeeded in 3.2s"}}'

exit "$fail"
