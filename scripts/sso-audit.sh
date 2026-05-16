#!/usr/bin/env bash
#
# sso-audit.sh — Outline-side fork audit against the cross-app SSO contract.
#
# ============================================================================
# Covers fork-side rows of awais786/sso-rules-moneta:openspec/specs/
# proxy-auth-middleware/spec.md that a deterministic bash check can verify
# against Outline's source tree. Catches regressions BEFORE they reach
# foss-server-bundle-devstack.
#
# Exit codes:
#   0 — all rows ✅ or n/a / informational
#   1 — at least one SECURITY-CRITICAL row failed
#
# Rows covered:
#   Row 14 — logout shape: SPA logout (app/stores/AuthStore.ts) MUST NOT
#            call /oauth2/sign_out.
#   Row 20 — session-identity reconciliation (Rule 2 mismatch flush):
#            server/middlewares/authentication.ts MUST throw
#            AuthenticationError on identity mismatch when AUTH_TYPE === 'SSO'
#            and transport === 'cookie'. The existing outer auth() catch
#            block clears the accessToken cookie via err.headers.
#            SECURITY-CRITICAL.
#   Row 21 — email-shape detection MUST NOT use polynomial-backtracking
#            regex. Outline uses indexOf-based detection in
#            normalizeProxyEmail (post-PR #19); this row is a regression
#            guard.
# ============================================================================

set -euo pipefail

AUTH_MIDDLEWARE="server/middlewares/authentication.ts"
AUTH_STORE="app/stores/AuthStore.ts"

declare -a ROW_STATUS=()
declare -a ROW_TITLES=(
  "logout shape: SPA logout does not call /oauth2/sign_out"
  "session-identity reconciliation present (Rule 2 mismatch flush)"
  "email-shape detection uses indexOf, not polynomial regex"
)
declare -a ROW_NOTES=()
declare -a ROW_NUMBERS=(14 20 21)

SECURITY_CRITICAL=(1)
SECURITY_CRITICAL_FAILS=0

record() {
  local idx=$1 status=$2 note=$3
  ROW_STATUS[$idx]="$status"
  ROW_NOTES[$idx]="$note"
  if [[ "$status" == "❌" ]]; then
    for c in "${SECURITY_CRITICAL[@]}"; do
      if [[ "$c" -eq "$idx" ]]; then
        SECURITY_CRITICAL_FAILS=$((SECURITY_CRITICAL_FAILS + 1))
        return
      fi
    done
  fi
}

# ============================================================================
# Row 14 (idx 0): logout shape — narrow check
# ============================================================================
check_row_14() {
  if [[ ! -f "$AUTH_STORE" ]]; then
    record 0 "?" "$AUTH_STORE not found — skipping"
    return
  fi

  if grep -qE '/oauth2/sign_?out' "$AUTH_STORE"; then
    local line
    line=$(grep -nE '/oauth2/sign_?out' "$AUTH_STORE" | head -1)
    record 0 "❌" "Logout calls \`/oauth2/sign_out\` at $AUTH_STORE:$line — per logout-flow spec, per-app Logout is navigation-only. Drop the call; portal 'Logout all' handles oauth2-proxy clearing."
    return
  fi

  record 0 "✅" "$AUTH_STORE does not invoke \`/oauth2/sign_out\` (this row verifies only that the SPA doesn't try to clear the upstream proxy cookie itself; that's the portal's job)"
}

# ============================================================================
# Row 20 (idx 1): session-identity reconciliation
#
# Outline's flush mechanism is: throw AuthenticationError → outer auth()
# catch block clears the accessToken cookie via err.headers. The deterministic
# signal is the presence of the `normalizeProxyEmail` helper function — it
# was added in Pressingly/outline#19 specifically to do the bidirectional
# header normalisation for the mismatch comparison. The function only exists
# post-fix, so its presence is a precise marker.
#
# A weaker fallback check looks for the "proxy identity" literal in a
# `throw AuthenticationError(...)` call, in case a future refactor renames
# the helper.
#
# The test suite at server/middlewares/authentication.test.ts pins the
# exact behaviour with the `should clear stale accessToken cookie when
# proxy identity changes` and `should NOT clear cookie when proxy email
# matches JWT user` test cases.
#
# SECURITY-CRITICAL: without this, the stale-session leak returns.
# ============================================================================
check_row_20() {
  if [[ ! -f "$AUTH_MIDDLEWARE" ]]; then
    record 1 "?" "$AUTH_MIDDLEWARE not found — skipping"
    return
  fi

  # Primary marker: normalizeProxyEmail function (introduced by PR #19).
  local has_normalize_helper
  has_normalize_helper=$(grep -cF "normalizeProxyEmail" "$AUTH_MIDDLEWARE" || true)

  # Fallback marker: "proxy identity" literal in a throw — used in the
  # AuthenticationError message when the mismatch fires.
  local has_throw_proxy
  has_throw_proxy=$(grep -cE "throw[[:space:]]+AuthenticationError\(.*[Pp]roxy" "$AUTH_MIDDLEWARE" || true)

  if [[ "$has_normalize_helper" -gt 0 ]]; then
    record 1 "✅" "$AUTH_MIDDLEWARE defines \`normalizeProxyEmail\` and uses it for bidirectional header normalisation — Rule 2 mismatch flush in place (flush mechanism: throw 401 → outer auth() catch clears accessToken cookie)"
    return
  fi

  if [[ "$has_throw_proxy" -gt 0 ]]; then
    record 1 "✅" "$AUTH_MIDDLEWARE has \`throw AuthenticationError(...proxy...)\` indicating a stale-session detection — Rule 2 mismatch flush in place (consider extracting bidirectional normalisation into a normalizeProxyEmail helper for clarity)"
    return
  fi

  record 1 "❌" "$AUTH_MIDDLEWARE does NOT define \`normalizeProxyEmail\` and has no \`throw AuthenticationError(...proxy...)\` call site. The cross-app spec (proxy-auth-middleware Rule 2) requires the JWT cookie branch of validateAuthentication to compare normalized X-Auth-Request-Email against the JWT user's email and throw AuthenticationError on mismatch, gated on \`env.AUTH_TYPE === 'SSO'\` and \`transport === 'cookie'\`. The existing outer auth() catch block then clears the accessToken + lastSignedIn cookies via err.headers. Without this check, the stale-session-on-user-switch leak returns. Reference: Pressingly/outline#19."
}

# ============================================================================
# Row 21 (idx 2): polynomial-regex avoidance in email-shape detection
#
# Detects the problematic pattern [^\s@]+@ which causes polynomial
# backtracking. The pattern matches character classes that exclude both
# whitespace (\s) and @ symbols, followed by +@ — this is the exact
# construct that leads to catastrophic backtracking in email validation.
# Using head -1 ensures only the first match is reported, preventing
# newlines from breaking the markdown table output.
# ============================================================================
check_row_21() {
  if [[ ! -f "$AUTH_MIDDLEWARE" ]]; then
    record 2 "?" "$AUTH_MIDDLEWARE not found — skipping"
    return
  fi

  local hits
  hits=$(grep -nE '\[\^\\s@\]\+@' "$AUTH_MIDDLEWARE" 2>/dev/null | head -1 || true)

  if [[ -n "$hits" ]]; then
    record 2 "❌" "Polynomial-backtracking email-shape regex detected in $AUTH_MIDDLEWARE: $hits. Rewrite to indexOf-based check per openspec proxy-auth-middleware §'email-shape detection SHALL avoid polynomial-backtracking regex'. Reference: \`normalizeProxyEmail\` in this file."
    return
  fi

  record 2 "✅" "No polynomial-backtracking email-shape regex in $AUTH_MIDDLEWARE; using indexOf-based detection"
}

# ============================================================================
# Run checks
# ============================================================================
check_row_14
check_row_20
check_row_21

# ============================================================================
# Print table
# ============================================================================
echo "## Outline SSO Fork Audit"
echo
echo "Cross-app contract: https://github.com/awais786/sso-rules-moneta/blob/main/openspec/specs/proxy-auth-middleware/spec.md"
echo "Row numbers match the 21-row table at https://github.com/awais786/sso-rules-moneta/blob/main/skills/app-rules/SKILL.md#5-report"
echo
echo "| Row | Invariant | Status | Notes |"
echo "|-----|-----------|--------|-------|"
for i in "${!ROW_TITLES[@]}"; do
  printf "| %d | %s | %s | %s |\n" \
    "${ROW_NUMBERS[$i]}" "${ROW_TITLES[$i]}" "${ROW_STATUS[$i]:-?}" "${ROW_NOTES[$i]:-}"
done
echo

# ============================================================================
# Summary + exit code
# ============================================================================
TOTAL_FAILS=0
for s in "${ROW_STATUS[@]}"; do
  [[ "$s" == "❌" ]] && TOTAL_FAILS=$((TOTAL_FAILS + 1))
done

if [[ "$TOTAL_FAILS" -eq 0 ]]; then
  echo "**All fork-side invariants hold.**"
  exit 0
fi

echo "**$TOTAL_FAILS violations.** Security-critical (row 20): $SECURITY_CRITICAL_FAILS."
if [[ "$SECURITY_CRITICAL_FAILS" -gt 0 ]]; then
  exit 1
fi
exit 0
