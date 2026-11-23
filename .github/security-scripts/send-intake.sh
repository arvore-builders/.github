#!/usr/bin/env bash
set -uo pipefail

outbox="${INTAKE_OUTBOX:-}"
queue="${SRE_INTAKE_QUEUE_URL:-}"

if [ -z "$outbox" ] || [ -z "$queue" ] || [ ! -s "$outbox" ]; then
  echo "::error::No intake notice or queue URL; the finding was not delivered."
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  arch=$(uname -m)
  workdir=$(mktemp -d)
  sudo apt-get install -y unzip >/dev/null 2>&1 || true
  curl -sSfL "https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip" -o "$workdir/awscliv2.zip" \
    && unzip -q "$workdir/awscliv2.zip" -d "$workdir" \
    && sudo "$workdir/aws/install" >/dev/null \
    || { echo "::error::Could not install the AWS CLI; the finding was not delivered."; exit 1; }
fi

id=$(jq -er '.id' "$outbox") || { echo "::error::The intake notice has no id."; exit 1; }
group=$(jq -er '.source + ":" + .key' "$outbox") || { echo "::error::The intake notice has no source or key."; exit 1; }

if aws sqs send-message \
  --region us-east-1 \
  --queue-url "$queue" \
  --message-group-id "$group" \
  --message-deduplication-id "$id" \
  --message-body "$(cat "$outbox")" \
  --output text --query MessageId >/dev/null; then
  echo "Finding $id delivered to the SRE intake queue."
else
  echo "::error::Finding $id was not delivered to the SRE intake queue."
  exit 1
fi
