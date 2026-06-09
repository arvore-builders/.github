#!/usr/bin/env bash
set -uo pipefail

RESULTS_FILE="claudecode-results.json"
echo '{"findings":[]}' > "$RESULTS_FILE"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "::error::ANTHROPIC_API_KEY is not set"
  exit 1
fi

BEFORE="${PUSH_BEFORE:-}"
AFTER="${PUSH_AFTER:-$(git rev-parse HEAD)}"

ZERO="0000000000000000000000000000000000000000"
if [ -z "$BEFORE" ] || [ "$BEFORE" = "$ZERO" ]; then
  DIFF=$(git show --no-color "$AFTER" 2>/dev/null || git diff --no-color "HEAD~1..HEAD" 2>/dev/null || echo "")
else
  DIFF=$(git diff --no-color "$BEFORE..$AFTER" 2>/dev/null || echo "")
fi

if [ -n "${EXCLUDE_DIRECTORIES:-}" ]; then
  IFS=',' read -ra DIRS <<< "$EXCLUDE_DIRECTORIES"
  FILTER_ARGS=()
  for d in "${DIRS[@]}"; do
    d_trimmed="$(echo "$d" | xargs)"
    [ -n "$d_trimmed" ] && FILTER_ARGS+=(":(exclude)$d_trimmed/**")
  done
  if [ ${#FILTER_ARGS[@]} -gt 0 ]; then
    if [ -z "$BEFORE" ] || [ "$BEFORE" = "$ZERO" ]; then
      DIFF=$(git diff --no-color "HEAD~1..HEAD" -- . "${FILTER_ARGS[@]}" 2>/dev/null || echo "$DIFF")
    else
      DIFF=$(git diff --no-color "$BEFORE..$AFTER" -- . "${FILTER_ARGS[@]}" 2>/dev/null || echo "$DIFF")
    fi
  fi
fi

if [ -z "$DIFF" ]; then
  echo "No diff to analyze for this push. Skipping."
  exit 0
fi

DIFF_FILE="$(mktemp)"
printf '%s\n' "$DIFF" > "$DIFF_FILE"
DIFF_BYTES=$(wc -c < "$DIFF_FILE")
echo "Push diff size: $DIFF_BYTES bytes"

MAX_BYTES=200000
if [ "$DIFF_BYTES" -gt "$MAX_BYTES" ]; then
  echo "::warning::Diff exceeds ${MAX_BYTES} bytes; truncating for analysis."
  head -c "$MAX_BYTES" "$DIFF_FILE" > "${DIFF_FILE}.trunc"
  mv "${DIFF_FILE}.trunc" "$DIFF_FILE"
fi

MODEL="${CLAUDE_MODEL:-claude-sonnet-4-6}"

SYSTEM_PROMPT='You are a senior security engineer reviewing code pushed directly to a default branch (no pull request). Identify HIGH-CONFIDENCE security vulnerabilities newly introduced by the diff. Focus ONLY on real, exploitable issues: injection (SQL/command/XSS), authentication/authorization bypass, hardcoded secrets or credentials, insecure deserialization, SSRF, path traversal, unsafe cryptography, and exposure of sensitive data. Ignore style, performance, and pre-existing concerns. Output ONLY a single JSON object with this schema: {"findings":[{"file":"path","line":0,"severity":"HIGH","category":"x","description":"y","recommendation":"z","confidence":0.9}]}. Severity must be HIGH, MEDIUM, or LOW. If there are no findings, output {"findings": []}. Do not wrap the JSON in markdown fences.'

USER_CONTENT="Review this diff for newly introduced security vulnerabilities:\n\n$(cat "$DIFF_FILE")"

echo "Running Anthropic API security analysis on push diff (model: $MODEL)..."
RAW_OUTPUT="$(mktemp)"
REQ_BODY="$(mktemp)"
jq -n \
  --arg model "$MODEL" \
  --arg system "$SYSTEM_PROMPT" \
  --arg user "$USER_CONTENT" \
  '{model: $model, max_tokens: 2048, system: $system, messages: [{role: "user", content: $user}]}' > "$REQ_BODY"

HTTP=$(curl -s -o "$RAW_OUTPUT" -w "%{http_code}" https://api.anthropic.com/v1/messages \
  -H "x-api-key: ${ANTHROPIC_API_KEY}" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  --data @"$REQ_BODY" || echo "000")
echo "Anthropic API HTTP status: $HTTP"

echo "::group::Anthropic API raw output (first 2000 chars)"
head -c 2000 "$RAW_OUTPUT" || true
echo
echo "::endgroup::"

if [ "$HTTP" != "200" ]; then
  echo "::warning::Anthropic API returned $HTTP; treating as no findings."
  echo '{"findings":[]}' > "$RESULTS_FILE"
  echo "Push scan parsed 0 finding(s)."
  exit 0
fi

RESULT_TEXT=$(jq -r '.content[]? | select(.type=="text") | .text' "$RAW_OUTPUT" 2>/dev/null)

FINDINGS_JSON=$(printf '%s' "$RESULT_TEXT" | python3 -c '
import sys, json, re
s = sys.stdin.read().strip()
s = re.sub(r"^```(?:json)?", "", s).strip()
s = re.sub(r"```$", "", s).strip()

def try_load(t):
    try:
        o = json.loads(t)
        return o if isinstance(o, dict) and "findings" in o else None
    except Exception:
        return None

res = try_load(s)
if res is None:
    start = s.find("{")
    while start != -1 and res is None:
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{": depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    res = try_load(s[start:i+1])
                    break
        start = s.find("{", start + 1)

print(json.dumps(res) if res is not None else "")
' 2>/dev/null)

if printf '%s' "$FINDINGS_JSON" | jq -e '.findings' >/dev/null 2>&1; then
  printf '%s' "$FINDINGS_JSON" | jq '{findings: (.findings // [])}' > "$RESULTS_FILE"
else
  echo "::warning::Could not parse model output as JSON; treating as no findings."
  echo '{"findings":[]}' > "$RESULTS_FILE"
fi

COUNT=$(jq '.findings | length' "$RESULTS_FILE")
echo "Push scan parsed $COUNT finding(s)."
