#!/usr/bin/env bash
set -uo pipefail

outbox="${INTAKE_OUTBOX:-}"
queue="${SRE_INTAKE_QUEUE_URL:-}"

fall_back_to_slack() {
  echo "::error::$1"
  if [ -n "${SLACK_SECURITY_WEBHOOK:-}" ] && [ -s "$outbox" ]; then
    payload=$(jq '{text: .text}' "$outbox")
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_SECURITY_WEBHOOK") || true
    echo "Slack fallback HTTP status: $status"
  fi
  exit 1
}

if [ -z "$outbox" ] || [ ! -s "$outbox" ]; then
  echo "::error::No intake notice; nothing was delivered."
  exit 1
fi

[ -n "$queue" ] || fall_back_to_slack "No intake queue URL; the finding went to Slack instead."

if ! command -v aws >/dev/null 2>&1; then
  arch=$(uname -m)
  workdir=$(mktemp -d)
  sudo apt-get install -y unzip >/dev/null 2>&1 || true
  curl -sSfL "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "$workdir/awscliv2.zip" \
    && unzip -q "$workdir/awscliv2.zip" -d "$workdir" \
    && sudo "$workdir/aws/install" >/dev/null \
    || fall_back_to_slack "Could not install the AWS CLI; the finding went to Slack instead."
fi

id=$(jq -er '.id' "$outbox") || fall_back_to_slack "The intake notice has no id; the finding went to Slack instead."
group=$(jq -er '.source + ":" + .key' "$outbox") || fall_back_to_slack "The intake notice has no source or key; the finding went to Slack instead."

if aws sqs send-message \
  --region us-east-1 \
  --queue-url "$queue" \
  --message-group-id "$group" \
  --message-deduplication-id "$id" \
  --message-body "$(cat "$outbox")" \
  --output text --query MessageId >/dev/null; then
  echo "Finding $id delivered to the SRE intake queue."
else
  fall_back_to_slack "Finding $id was not delivered to the SRE intake queue; it went to Slack instead."
fi
