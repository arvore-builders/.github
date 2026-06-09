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

PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<'PROMPT'
You are a senior security engineer reviewing code pushed directly to a default branch (no pull request).

OBJECTIVE:
Identify HIGH-CONFIDENCE security vulnerabilities newly introduced by the diff below. Focus ONLY on real, exploitable security issues introduced by these changes. Ignore style, performance, and pre-existing concerns.

Look for: injection (SQL/command/XSS), authentication/authorization bypass, hardcoded secrets or credentials, insecure deserialization, SSRF, path traversal, unsafe use of cryptography, and exposure of sensitive data.

OUTPUT FORMAT (MANDATORY):
Output ONLY a single JSON object, no prose, with this exact schema:
{
  "findings": [
    {
      "file": "path/to/file",
      "line": 0,
      "severity": "HIGH",
      "category": "short_category",
      "description": "what the issue is",
      "recommendation": "how to fix it",
      "confidence": 0.9
    }
  ]
}
Severity must be one of HIGH, MEDIUM, LOW. If there are no findings, output {"findings": []}.

DIFF TO REVIEW:
PROMPT

cat "$DIFF_FILE" >> "$PROMPT_FILE"

echo "Running Claude CLI security analysis on push diff (model: $MODEL)..."
RAW_OUTPUT="$(mktemp)"
claude --output-format json --model "$MODEL" --disallowed-tools 'Bash(ps:*)' < "$PROMPT_FILE" > "$RAW_OUTPUT" 2>"${RAW_OUTPUT}.err" || {
  echo "::warning::Claude CLI exited non-zero"
  cat "${RAW_OUTPUT}.err" || true
}

echo "::group::Claude CLI raw output (first 2000 chars)"
head -c 2000 "$RAW_OUTPUT" || true
echo
echo "::endgroup::"

RESULT_TEXT=$(jq -r '.result // empty' "$RAW_OUTPUT" 2>/dev/null)
if [ -z "$RESULT_TEXT" ]; then
  RESULT_TEXT=$(cat "$RAW_OUTPUT")
fi

FINDINGS_JSON=$(printf '%s' "$RESULT_TEXT" | sed -n 's/^```json//; s/^```//; p' | grep -o '{.*}' | tail -1)
if [ -z "$FINDINGS_JSON" ]; then
  FINDINGS_JSON=$(printf '%s' "$RESULT_TEXT" | python3 -c 'import sys,re,json
s=sys.stdin.read()
m=re.findall(r"\{(?:[^{}]|\{[^{}]*\})*\}", s, re.DOTALL)
for cand in reversed(m):
    try:
        o=json.loads(cand)
        if isinstance(o,dict) and "findings" in o:
            print(json.dumps(o)); break
    except Exception:
        pass' 2>/dev/null)
fi

if printf '%s' "$FINDINGS_JSON" | jq -e '.findings' >/dev/null 2>&1; then
  printf '%s' "$FINDINGS_JSON" | jq '{findings: (.findings // [])}' > "$RESULTS_FILE"
else
  echo "::warning::Could not parse Claude output as JSON; treating as no findings."
  echo '{"findings":[]}' > "$RESULTS_FILE"
fi

COUNT=$(jq '.findings | length' "$RESULTS_FILE")
echo "Push scan parsed $COUNT finding(s)."
