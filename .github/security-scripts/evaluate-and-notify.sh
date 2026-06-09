#!/usr/bin/env bash
set -uo pipefail

RESULTS_FILE="${1:-claudecode-results.json}"

if [ ! -f "$RESULTS_FILE" ]; then
  echo "No results file ($RESULTS_FILE); nothing to evaluate."
  exit 0
fi

if jq -e '.error' "$RESULTS_FILE" >/dev/null 2>&1; then
  echo "::warning::Scan reported an error; not gating."
  exit 0
fi

BLOCKING=$(jq '[.findings[]? | select((.severity|tostring|ascii_upcase) == "HIGH" or (.severity|tostring|ascii_upcase) == "CRITICAL")] | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
TOTAL=$(jq '.findings | length' "$RESULTS_FILE" 2>/dev/null || echo 0)
echo "Total findings: $TOTAL | HIGH/CRITICAL: $BLOCKING"

if [ "$BLOCKING" -gt 0 ] && [ -n "${SLACK_SECURITY_WEBHOOK:-}" ]; then
  DETAILS=$(jq -r '[.findings[]? | select((.severity|tostring|ascii_upcase) == "HIGH" or (.severity|tostring|ascii_upcase) == "CRITICAL")] | .[:10] | map("• [\(.severity)] \(.file):\(.line) — \(.description)") | join("\n")' "$RESULTS_FILE")

  KIND_LABEL="Pull Request"
  [ "${CONTEXT_KIND:-}" = "push" ] && KIND_LABEL="Push direto (sem PR)"

  TEXT=":rotating_light: *Security findings — ${CONTEXT_REPO:-repo}*
*Origem:* ${KIND_LABEL}
*Autor:* ${CONTEXT_ACTOR:-unknown}
*Ref:* ${CONTEXT_TITLE:-}
*Link:* ${CONTEXT_REF:-}
*HIGH/CRITICAL:* ${BLOCKING}

${DETAILS}"

  PAYLOAD=$(jq -n --arg t "$TEXT" '{text: $t}')
  HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H 'Content-type: application/json' \
    --data "$PAYLOAD" "$SLACK_SECURITY_WEBHOOK" || echo "000")
  echo "Slack notification HTTP status: $HTTP"
fi

if [ "$BLOCKING" -gt 0 ]; then
  echo "::error::${BLOCKING} HIGH/CRITICAL security finding(s) detected."
  jq -r '.findings[]? | select((.severity|tostring|ascii_upcase) == "HIGH" or (.severity|tostring|ascii_upcase) == "CRITICAL") | "- [\(.severity)] \(.file):\(.line) — \(.description)"' "$RESULTS_FILE"
  if [ "${CONTEXT_KIND:-}" = "pull_request" ]; then
    exit 1
  fi
  echo "::warning::Direct push cannot be blocked on Free plan; notified via Slack and check is red."
  exit 1
fi

echo "No HIGH/CRITICAL findings. Gate passed."
