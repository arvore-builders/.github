import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import evaluate
import push_scan as scan
import write_coverage

A, B, H, TREE = (c * 40 for c in "abcf")
PR = {"number": 15, "merged_at": "2026-10-19", "merge_commit_sha": B, "html_url": "https://github.com/org/repo/pull/15",
      "head": {"sha": H}, "base": {"sha": A, "ref": "main", "repo": {"full_name": "org/repo"}}}
FINDING = {"file": "app.py", "line": 1, "severity": "HIGH", "confidence": .95,
           "description": "SQL injection", "recommendation": "Bind values",
           "attacker_control": "Request query", "exploit_path": "query passed to SQL execution",
           "impact": "data read", "bypass_analysis": "no bind or quoting"}


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"GITHUB_REPOSITORY": "org/repo", "GITHUB_REF_NAME": "main",
            "GITHUB_WORKFLOW_REF": "org/repo/.github/workflows/security.yml@refs/heads/main"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.git = patch.object(scan, "git", side_effect=lambda *a: f"{B} {A} {H}" if a[0] == "rev-list" else TREE)
        self.git.start()
        self.addCleanup(self.git.stop)
        self.coverage = {"version": 1, "repository": "org/repo", "pr_number": 15,
                         "head_sha": H, "base_sha": A, "merge_tree": TREE}
        self.run = {"id": 1, "event": "pull_request", "head_sha": H,
                    "path": ".github/workflows/security.yml", "conclusion": "success"}
        self.artifact = {"id": 2, "name": "security-review-coverage", "expired": False}

    def api(self, path, binary=False):
        if "/commits/" in path:
            return [PR]
        if path.endswith("/zip"):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("coverage.json", json.dumps(self.coverage))
            return buf.getvalue()
        if "/artifacts?" in path:
            return {"artifacts": [self.artifact]}
        return {"workflow_runs": [self.run]}

    def test_exact_approved_pr_can_be_reused(self):
        meta, covered = scan.push_origin(A, B, self.api)
        self.assertTrue(covered)
        self.assertEqual(meta["origin"], "merge_pr")

    def test_manifest_must_match_every_field(self):
        for key in self.coverage:
            with self.subTest(key=key):
                original = self.coverage[key]
                self.coverage[key] = "mismatch"
                self.assertFalse(scan.covered_by_pr(PR, A, B, "org/repo", self.api))
                self.coverage[key] = original

    def test_unreviewed_range_not_skipped(self):
        self.assertFalse(scan.covered_by_pr(PR, "d" * 40, B, "org/repo", self.api))

    def test_failed_stale_or_wrong_workflow_not_coverage(self):
        for key, value in [("conclusion", "failure"), ("head_sha", A), ("event", "push"), ("path", "other.yml")]:
            with self.subTest(key=key):
                original = self.run[key]
                self.run[key] = value
                self.assertFalse(scan.covered_by_pr(PR, A, B, "org/repo", self.api))
                self.run[key] = original

    def test_expired_artifact_is_not_coverage(self):
        self.artifact["expired"] = True
        self.assertFalse(scan.covered_by_pr(PR, A, B, "org/repo", self.api))

    def test_no_pr_is_direct_push(self):
        self.assertEqual(scan.push_origin(A, B, lambda *a: []), ({"origin": "direct_push"}, False))

    def test_api_failure_does_not_skip_or_call_it_direct(self):
        def failure(*a, **kw):
            raise scan.Inconclusive("GitHub HTTP 403")
        self.assertEqual(scan.push_origin(A, B, failure), ({"origin": "push_unknown"}, False))

    def test_artifact_permission_failure_keeps_merge_label(self):
        def failure(path, **kwargs):
            if "/commits/" in path:
                return [PR]
            raise scan.Inconclusive("permissions")
        meta, covered = scan.push_origin(A, B, failure)
        self.assertFalse(covered)
        self.assertEqual(meta["origin"], "merge_pr")


class AnalysisTests(unittest.TestCase):
    def test_safe_result_does_not_need_second_request(self):
        def ask(*args):
            return {"findings": []}
        self.assertEqual(scan.review({}, ask), [])

    def test_confirmation_rejection_and_inconclusive(self):
        for verdict in ("confirmed", "rejected", "inconclusive"):
            with self.subTest(verdict=verdict):
                responses = iter([{"findings": [FINDING]}, {"verdicts": [
                    {"index": 0, "verdict": verdict, "reason": "checked source and protection"}]}])
                ask = lambda *args: next(responses)
                if verdict == "inconclusive":
                    with self.assertRaises(scan.Inconclusive):
                        scan.review({}, ask)
                else:
                    result = scan.review({}, ask)
                    self.assertEqual(len(result), int(verdict == "confirmed"))

    def test_missing_evidence_and_bad_schema_do_not_pass(self):
        variants = [{"error": "missing context"}, {}, {"findings": None}, {"findings": ["invalid"]},
            {"findings": [{**FINDING, "confidence": .5}]},
            {"findings": [{**FINDING, "exploit_path": ""}]}]
        for response in variants:
            with self.subTest(response=response), self.assertRaises(scan.Inconclusive):
                scan.review({}, lambda *a: response)

    def test_incomplete_validation_does_not_pass(self):
        for verdicts in ([], [{"index": 99}], [{"index": 0, "verdict": "confirmed", "reason": ""}]):
            responses = iter([{"findings": [FINDING]}, {"verdicts": verdicts}])
            with self.subTest(verdicts=verdicts), self.assertRaises(scan.Inconclusive):
                scan.review({}, lambda *a: next(responses))

    def test_api_http_failure_is_inconclusive(self):
        err = urllib.error.HTTPError("https://api.anthropic.com", 429, "quota", {}, io.BytesIO())
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}), patch.object(urllib.request, "urlopen", side_effect=err):
            with self.assertRaisesRegex(scan.Inconclusive, "HTTP 429"):
                scan.ask_model("policy", {})

    def test_invalid_json_and_truncated_api_response_do_not_pass(self):
        for raw in (b"not json", json.dumps({"stop_reason": "max_tokens"}).encode()):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}), patch.object(urllib.request, "urlopen", return_value=io.BytesIO(raw)):
                with self.assertRaises((ValueError, scan.Inconclusive)):
                    scan.ask_model("policy", {})

    def test_main_records_inconclusive_and_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp), \
                patch.dict(os.environ, {"PUSH_BEFORE": A, "PUSH_AFTER": B}), \
                patch.object(scan, "push_origin", return_value=({"origin": "direct_push"}, False)), \
                patch.object(scan, "collect_context", side_effect=scan.Inconclusive("too large")):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scan.main(), 2)
            result = json.loads(Path("claudecode-results.json").read_text())
            self.assertEqual(result["status"], "inconclusive")
            self.assertIn("error", result)

    def test_redirect_drops_token_on_external_artifact_host(self):
        req = urllib.request.Request("https://api.github.com/archive", headers={"Authorization": "Bearer test"})
        redirected = scan.SafeRedirect().redirect_request(req, None, 302, "found", {}, "https://artifacts.example/file")
        self.assertFalse(redirected.has_header("Authorization"))
        with self.assertRaises(scan.Inconclusive):
            scan.SafeRedirect().redirect_request(req, None, 302, "found", {}, "http://example/file")

    def test_context_includes_full_push_range_and_transaction_code(self):
        calls = []
        def fake_git(*args):
            calls.append(args)
            if args[0] == "ls-tree":
                return "app/a.py\napp/b.py\nmigrations/env.py"
            if args[0] == "diff" and "--name-only" in args:
                return "app/a.py\napp/b.py"
            return "source or diff"
        with patch.object(scan, "git", side_effect=fake_git):
            result = scan.collect_context(A, B)
        self.assertEqual({c["file"] for c in result["source_context"]}, {"app/a.py", "app/b.py", "migrations/env.py"})
        self.assertIn(("diff", "--no-ext-diff", "--no-textconv", "--no-color", A, B, "--", ".", ":(exclude).security-pipeline/**"), calls)

    def test_large_diff_is_not_silently_truncated(self):
        with patch.object(scan, "git", return_value="x" * 200_001), self.assertRaises(scan.Inconclusive):
            scan.collect_context(A, B)

    def test_initial_push_compares_complete_tree_not_merge_commit_hunks(self):
        calls = []
        def fake_git(*args):
            calls.append(args)
            return A if args[0] == "hash-object" else ""
        with patch.object(scan, "git", side_effect=fake_git):
            scan.collect_context("0" * 40, B)
        self.assertIn(("hash-object", "-w", "-t", "tree", "--stdin"), calls)
        self.assertTrue(any(c[0] == "diff" and A in c and B in c for c in calls))
        self.assertFalse(any(c[0] == "show" for c in calls))


class EvaluationTests(unittest.TestCase):
    def test_invalid_missing_and_error_outputs_fail(self):
        for payload in (None, "not json", {}, {"error": "failure", "findings": []}, {"findings": None},
                        {"status": "inconclusive", "findings": []}, {"findings": [{"severity": "unknown"}]}):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                result = Path(tmp) / "results.json"
                if payload is not None:
                    result.write_text(payload if isinstance(payload, str) else json.dumps(payload))
                process = subprocess.run([sys.executable, str(SCRIPTS / "evaluate.py"), str(result)], cwd=tmp,
                    env={**os.environ, "SLACK_SECURITY_WEBHOOK": "", "SCAN_OUTCOME": "success"}, capture_output=True, text=True)
                self.assertEqual(process.returncode, 2, process.stdout)
                self.assertEqual(json.loads((Path(tmp) / "security-evaluation.json").read_text()), {"status": "inconclusive"})

    def test_failed_scan_never_passes_with_empty_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = Path(tmp) / "results.json"
            result.write_text('{"findings":[]}')
            with patch.dict(os.environ, {"SCAN_OUTCOME": "failure"}), self.assertRaises(ValueError):
                evaluate.load_results(result)

    def test_blocking_and_empty_results(self):
        for findings, expected in (([], 0), ([FINDING], 1)):
            with tempfile.TemporaryDirectory() as tmp:
                result = Path(tmp) / "results.json"
                result.write_text(json.dumps({"findings": findings, "origin": "merge_pr"}))
                process = subprocess.run(["bash", str(SCRIPTS / "evaluate-and-notify.sh"), str(result)], cwd=tmp,
                    env={**os.environ, "SLACK_SECURITY_WEBHOOK": "", "SCAN_OUTCOME": "success", "CONTEXT_KIND": "push"}, capture_output=True, text=True)
                self.assertEqual(process.returncode, expected, process.stderr)
                self.assertIn("Merge de Pull Request", process.stdout)

    def test_cannot_attest_failed_gate(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("security-evaluation.json").write_text('{"status":"inconclusive"}')
            with self.assertRaises(ValueError):
                write_coverage.main()

    def test_attestation_contains_exact_reviewed_tree_and_commits(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("security-evaluation.json").write_text('{"status":"passed"}')
            Path("event.json").write_text(json.dumps({"pull_request": PR}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": "event.json", "GITHUB_SHA": B,
                    "GITHUB_REPOSITORY": "org/repo"}), \
                    patch.object(write_coverage.subprocess, "check_output", side_effect=[B, TREE]):
                write_coverage.main()
            self.assertEqual(json.loads(Path("coverage.json").read_text()), {
                "version": 1, "repository": "org/repo", "pr_number": 15,
                "head_sha": H, "base_sha": A, "merge_tree": TREE})

    def test_checkout_mismatch_cannot_be_attested(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            Path("security-evaluation.json").write_text('{"status":"passed"}')
            Path("event.json").write_text(json.dumps({"pull_request": PR}))
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": "event.json", "GITHUB_SHA": B}), \
                    patch.object(write_coverage.subprocess, "check_output", return_value=A), \
                    self.assertRaises(ValueError):
                write_coverage.main()
            self.assertFalse(Path("coverage.json").exists())


if __name__ == "__main__":
    unittest.main()
