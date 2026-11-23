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

QUEUED=false
if [ "$BLOCKING" -gt 0 ] && [ "${CONTEXT_KIND:-}" = "push" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${INTAKE_OUTBOX:-}" ] && [ -n "${SRE_INTAKE_QUEUE_URL:-}" ]; then
  REPO_NAME="${CONTEXT_REPO#*/}"
  FIRST_LINE=$(printf '%s' "${CONTEXT_TITLE:-}" | head -n 1 | cut -c1-200)
  DETAILS=$(jq -r '[.findings[]? | select((.severity|tostring|ascii_upcase) == "HIGH" or (.severity|tostring|ascii_upcase) == "CRITICAL")] | .[:10] | map("• [\(.severity|tostring|ascii_upcase)] \(.file):\(.line) — \(.description|tostring|.[0:300])") | join("\n")' "$RESULTS_FILE")
  TEXT=":rotating_light: *Furo de segurança alto em <${CONTEXT_REF:-}|${CONTEXT_REPO:-repo}>* de ${CONTEXT_ACTOR:-unknown}
Push direto, sem PR: ${FIRST_LINE}
${DETAILS}"
  if jq -n \
    --arg id "vuln-${CONTEXT_REPO%%/*}-${REPO_NAME}-${CONTEXT_SHA:-unknown}" \
    --arg key "${REPO_NAME}:push" \
    --arg title "Furo de segurança alto em ${CONTEXT_REPO:-repo}" \
    --arg text "$TEXT" \
    --arg url "${CONTEXT_REF:-}" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg repo "${CONTEXT_REPO:-}" \
    --arg sha "${CONTEXT_SHA:-}" \
    --argjson findings "$BLOCKING" \
    '{v: 1, id: $id, source: "vuln", key: $key, state: "open", severity: "high", title: $title, text: $text,
      links: (if ($url | startswith("https://")) then [{label: "Ver o commit", url: $url}] else [] end),
      at: $at, data: {unpaired: true, origin: "arvore-builders security review", repo: $repo, sha: $sha, findings: $findings}}' > "$INTAKE_OUTBOX"; then
    QUEUED=true
    echo "queue=true" >> "${GITHUB_OUTPUT:-/dev/null}"
    echo "Finding handed to the SRE intake queue."
  else
    echo "::warning::Could not build the intake notice; falling back to Slack."
  fi
fi

if [ "$BLOCKING" -gt 0 ] && [ "$QUEUED" = "false" ] && [ -n "${SLACK_SECURITY_WEBHOOK:-}" ]; then
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
  echo "::warning::Direct push cannot be blocked on Free plan; the team was notified and the check is red."
  exit 1
fi

echo "No HIGH/CRITICAL findings. Gate passed."
