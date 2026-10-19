"""Fail explicitly on inconclusive analysis; alert only validated findings."""
import json
import os
from pathlib import Path
import sys
import urllib.request


def load_results(path):
    if os.environ.get("SCAN_OUTCOME", "success") != "success":
        raise ValueError("scan step did not succeed")
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or value.get("error") or value.get("status") == "inconclusive":
        raise ValueError("scanner reported an error or needs manual review")
    if "status" in value and value["status"] not in ("completed", "covered"):
        raise ValueError("unknown analysis status")
    if not isinstance(value.get("findings"), list):
        raise ValueError("missing findings array")
    for finding in value["findings"]:
        if not isinstance(finding, dict) or finding.get("severity", "").upper() not in ("HIGH", "CRITICAL", "MEDIUM", "LOW"):
            raise ValueError("invalid finding severity/schema")
        if not all(isinstance(finding.get(k), str) and finding[k].strip() for k in ("file", "description")):
            raise ValueError("missing finding description/location")
    return value


def origin_label(result):
    if os.environ.get("CONTEXT_KIND") == "pull_request":
        return "Pull Request"
    return {"merge_pr": "Merge de Pull Request", "direct_push": "Push direto (sem PR)"}.get(
        result.get("origin"), "Push (origem não confirmada)")


def main():
    try:
        result = load_results(sys.argv[1] if len(sys.argv) > 1 else "claudecode-results.json")
    except (OSError, ValueError, TypeError, AttributeError):
        Path("security-evaluation.json").write_text(json.dumps({"status": "inconclusive"}))
        print("::error::Security analysis inconclusive: missing, invalid or unsuccessful scan. Manual review/rerun required.")
        return 2
    blocking = [f for f in result["findings"] if f["severity"].upper() in ("HIGH", "CRITICAL")]
    Path("security-evaluation.json").write_text(json.dumps({"status": "blocked" if blocking else "passed"}))
    print(f"Security review: {len(result['findings'])} findings; {len(blocking)} HIGH/CRITICAL; {origin_label(result)}")
    if not blocking:
        return 0
    for f in blocking:
        # JSON encoding prevents model-controlled newlines from becoming workflow commands.
        print(json.dumps({k: f.get(k) for k in ("severity", "file", "line", "description")}, ensure_ascii=True))
    webhook = os.environ.get("SLACK_SECURITY_WEBHOOK", "")
    if webhook:
        details = "\n".join(f"• [{f['severity']}] {f['file']}:{f.get('line', '?')} — {f['description']}" for f in blocking[:10])
        text = (f"Security findings — {os.environ.get('CONTEXT_REPO', 'repo')}\n"
                f"Origem: {origin_label(result)}\nAutor: {os.environ.get('CONTEXT_ACTOR', '')}\n"
                f"Ref: {os.environ.get('CONTEXT_TITLE', '')}\nLink: {os.environ.get('CONTEXT_REF', '')}\n"
                f"HIGH/CRITICAL: {len(blocking)}\n{details}")
        req = urllib.request.Request(webhook, data=json.dumps({"text": text, "unfurl_links": False}).encode(),
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                print(f"Slack notification HTTP status: {response.status}")
        except OSError:
            print("::warning::Could not deliver security notification")
    return 1


if __name__ == "__main__":
    sys.exit(main())
