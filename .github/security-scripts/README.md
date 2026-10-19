# Security review pipeline

PR review and push review share `review-policy.txt`: a HIGH finding requires
attacker control, a reachable exploit, impact, and analysis of existing defenses.
PRs use the upstream action's false-positive filter and run for every commit.
Uncovered pushes include surrounding source and run a second, independent model
request to confirm or reject each candidate before notification.

The evaluator returns 0 for a completed review without HIGH/CRITICAL findings,
1 for blocking findings, and 2 for inconclusive analysis. Missing/invalid results,
API failures, timeouts, truncation and insufficient context are not clean scans.
Push results and validation errors are uploaded as workflow artifacts; raw API
responses and source excerpts are not printed in logs.

## Coverage and permissions

After a successful PR gate, `coverage.json` records the repository, PR number,
reviewed head/base SHAs and merge tree. A subsequent push reuses this review only
when GitHub identifies a merged PR, the first parent equals the push's before SHA,
the successful PR workflow matches the caller's workflow path, and the artifact
matches every recorded field and the actual pushed tree. A push with additional
commits, a stale review, failed/expired/missing artifacts or API errors is scanned.
Absence of GitHub metadata is labeled unknown, never assumed to mean direct push.

Callers should grant `contents: read`, `pull-requests: write` and `actions: read`.
Existing callers without `actions: read` still scan uncovered pushes; they cannot
reuse PR artifacts until permissions are updated. Attestations from older workflow
versions do not exist, so the first deployment may scan a merge again.

The two model requests are additional automated evidence checks, not proof that
false positives are impossible. Genuine ambiguity requires human review and a
non-successful gate. No vulnerability class or project file is exempted.

## Tests

```bash
python -m unittest discover -s .github/security-scripts/tests -v
bash -n .github/security-scripts/push-scan.sh .github/security-scripts/evaluate-and-notify.sh
```

Tests use mocked API/model responses and never send Slack notifications.
