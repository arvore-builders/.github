"""Review uncovered pushes with source context and independent evidence validation."""
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class Inconclusive(Exception):
    pass


def git(*args):
    try:
        return subprocess.check_output(["git", *args], input=b"", stderr=subprocess.PIPE).decode("utf-8", "replace").strip()
    except subprocess.CalledProcessError as exc:
        raise Inconclusive("Could not read git revision/context") from exc


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise Inconclusive("Non-HTTPS API redirect refused")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header("Authorization")
        return redirected


def github(path, binary=False):
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise Inconclusive("GitHub token unavailable; coverage unknown")
    req = urllib.request.Request("https://api.github.com/" + path, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.build_opener(SafeRedirect()).open(req, timeout=45) as response:
            data = response.read(2_000_001)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise Inconclusive(f"GitHub metadata unavailable (HTTP {status})") from exc
    if len(data) > 2_000_000:
        raise Inconclusive("GitHub response too large")
    return data if binary else json.loads(data)


def covered_by_pr(pr, before, after, repository, api=github):
    # A push including other commits cannot reuse a single PR's review.
    parents = git("rev-list", "--parents", "-n", "1", after).split()[1:]
    if not parents or parents[0] != before:
        return False
    head = pr["head"]["sha"]
    tree = git("rev-parse", after + "^{tree}")
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    match = re.search(r"(/\.github/workflows/[^@]+)@", ref)
    workflow = match.group(1).lstrip("/") if match else ".github/workflows/security.yml"
    runs = api(f"repos/{repository}/actions/runs?event=pull_request&head_sha={head}&per_page=100")
    for run in runs["workflow_runs"]:
        if (run.get("event") != "pull_request" or run.get("head_sha") != head
                or run.get("path") != workflow or run.get("conclusion") != "success"):
            continue
        artifacts = api(f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100")
        for artifact in artifacts["artifacts"]:
            if artifact["name"] != "security-review-coverage" or artifact.get("expired"):
                continue
            archive = api(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip", binary=True)
            with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                info = zipped.getinfo("coverage.json")
                if info.file_size > 16_384:
                    raise Inconclusive("Invalid coverage artifact size")
                coverage = json.loads(zipped.read(info))
            if coverage == {"version": 1, "repository": repository, "pr_number": pr["number"],
                            "head_sha": head, "base_sha": before, "merge_tree": tree}:
                return True
    return False


def push_origin(before, after, api=github):
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    meta = {"origin": "push_unknown"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return meta, False
    try:
        prs = api(f"repos/{repository}/commits/{after}/pulls?per_page=100")
        for pr in prs:
            if (pr.get("merged_at") and pr.get("merge_commit_sha") == after
                    and pr.get("base", {}).get("repo", {}).get("full_name") == repository
                    and pr["base"]["ref"] == os.environ.get("GITHUB_REF_NAME")):
                meta = {"origin": "merge_pr", "pr_number": pr["number"], "pr_url": pr["html_url"]}
                return meta, covered_by_pr(pr, before, after, repository, api)
        return {"origin": "direct_push"}, False
    except (Inconclusive, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        # Unknown permissions/coverage never skip the scan.
        return meta, False


def collect_context(before, after):
    excluded = [d.strip() for d in os.environ.get("EXCLUDE_DIRECTORIES", "").split(",") if d.strip()]
    paths = [".", ":(exclude).security-pipeline/**", *[f":(exclude){d}/**" for d in excluded]]
    options = ["--no-ext-diff", "--no-textconv", "--no-color"]
    if not before or set(before) == {"0"}:
        # Initial default-branch pushes must review the entire tree, even if the
        # tip is a merge commit. Only creates the empty git tree object.
        before = git("hash-object", "-w", "-t", "tree", "--stdin")
    diff = git("diff", *options, before, after, "--", *paths)
    changed = git("diff", "--name-only", before, after, "--", *paths).splitlines()
    if len(diff.encode()) > 200_000:
        raise Inconclusive("Diff exceeds review limit; split push or review manually")
    available = set(git("ls-tree", "-r", "--name-only", after).splitlines())
    wanted = set(changed)
    for name in changed:
        parent = str(Path(name).parent)
        wanted.update(p for p in available if str(Path(p).parent) == parent and p.endswith((".py", ".sh")))
    wanted.update(p for p in ("migrations/env.py", "app/core/migrate.py", "app/core/database.py") if p in available)
    context, size = [], 0
    for name in sorted(wanted & available):
        if any(name == d or name.startswith(d + "/") for d in excluded):
            continue
        if not name.endswith((".py", ".sh", ".yml", ".yaml", ".js", ".ts", ".tsx", ".sql", ".go", ".rb", ".java", ".cs")):
            continue
        content = git("show", after + ":" + name)
        size += len(content.encode())
        if size > 400_000:
            raise Inconclusive("Source context exceeds review limit; manual review required")
        context.append({"file": name, "content": content})
    return {"diff": diff, "source_context": context}


def ask_model(system, payload):
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise Inconclusive("ANTHROPIC_API_KEY is not set")
    body = {"model": os.environ.get("CLAUDE_MODEL") or "claude-sonnet-4-6", "max_tokens": 8192,
            "system": system, "messages": [{"role": "user", "content": json.dumps(payload)}]}
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            raw = json.load(response)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise Inconclusive(f"Analysis API returned HTTP {status}") from exc
    if raw.get("stop_reason") != "end_turn":
        raise Inconclusive("Analysis response incomplete")
    result = "".join(c["text"] for c in raw.get("content", []) if c.get("type") == "text").strip()
    if result.startswith("```json") and result.endswith("```"):
        result = result[7:-3].strip()
    value = json.loads(result)
    if not isinstance(value, dict):
        raise Inconclusive("Invalid analysis schema")
    return value


def review(context, ask=ask_model):
    policy = (HERE / "review-policy.txt").read_text()
    schema = ('Return only JSON: {"findings":[{"file":"path","line":1,"severity":"HIGH|MEDIUM|LOW",'
              '"description":"...","recommendation":"...","confidence":0.95,'
              '"attacker_control":"...","exploit_path":"...","impact":"...","bypass_analysis":"..."}]}. '
              'Use {"findings":[]} if no vulnerability is demonstrated. '
              'If context is insufficient return {"error":"missing evidence/context"}.')
    first = ask(policy + "\n" + schema, context)
    if first.get("error") or not isinstance(first.get("findings"), list):
        raise Inconclusive("Initial analysis requires review or returned invalid findings")
    findings = first["findings"]
    for f in findings:
        if not isinstance(f, dict) or f.get("severity") not in ("HIGH", "CRITICAL", "MEDIUM", "LOW"):
            raise Inconclusive("Invalid finding severity/schema")
        if not all(isinstance(f.get(k), str) and f[k].strip() for k in (
                "file", "description", "recommendation", "attacker_control", "exploit_path", "impact", "bypass_analysis")):
            raise Inconclusive("Finding missing exploit evidence")
        if type(f.get("line")) is not int or f["line"] < 1:
            raise Inconclusive("Finding missing source location")
        score = f.get("confidence")
        if type(score) not in (int, float) or not 0 <= score <= 1:
            raise Inconclusive("Invalid finding confidence")
        if f["severity"] in ("HIGH", "CRITICAL") and score < .9:
            raise Inconclusive("HIGH finding lacks confidence")
    if not findings:
        return []
    verify = ask(policy + '\nIndependently challenge every candidate against supplied code. '
                 'Return JSON {"verdicts":[{"index":0,"verdict":"confirmed|rejected|inconclusive","reason":"evidence"}]}. '
                 'Use inconclusive when you cannot demonstrate or refute exploitability.',
                 {**context, "candidates": findings})
    verdicts = verify.get("verdicts")
    if (not isinstance(verdicts, list) or len(verdicts) != len(findings)
            or any(not isinstance(v, dict) or type(v.get("index")) is not int for v in verdicts)
            or {v["index"] for v in verdicts} != set(range(len(findings)))):
        raise Inconclusive("Independent validation incomplete")
    confirmed = []
    for verdict in verdicts:
        if not isinstance(verdict.get("reason"), str) or not verdict["reason"].strip():
            raise Inconclusive("Validation missing evidence")
        if verdict.get("verdict") == "confirmed":
            confirmed.append({**findings[verdict["index"]], "validation": verdict["reason"]})
        elif verdict.get("verdict") != "rejected":
            raise Inconclusive("Exploitability requires human review")
    return confirmed


def main():
    output = Path("claudecode-results.json")
    meta = {"origin": "push_unknown"}
    try:
        before = os.environ.get("PUSH_BEFORE", "")
        after = os.environ.get("PUSH_AFTER") or git("rev-parse", "HEAD")
        if not SHA.fullmatch(after) or (before and not SHA.fullmatch(before)):
            raise Inconclusive("Invalid push commit identifiers")
        meta, covered = push_origin(before, after)
        if covered:
            result = {"status": "covered", "findings": [], **meta}
        else:
            context = collect_context(before, after)
            result = {"status": "completed", "findings": review(context) if context["diff"] else [], **meta}
        output.write_text(json.dumps(result))
        print(f"Security review: {result['status']}; origin={meta['origin']}; findings={len(result['findings'])}")
        return 0
    except (Inconclusive, OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, Inconclusive) else type(exc).__name__
        output.write_text(json.dumps({"status": "inconclusive", "error": reason, "findings": [], **meta}))
        print(f"::error::Security analysis inconclusive: {reason}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
