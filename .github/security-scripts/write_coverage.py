"""Attest the exact PR merge tree only after the security gate passes."""
import json
import os
from pathlib import Path
import subprocess


def main():
    if json.loads(Path("security-evaluation.json").read_text()) != {"status": "passed"}:
        raise ValueError("Cannot attest an incomplete or blocked review")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != os.environ["GITHUB_SHA"]:
        raise ValueError("Checkout does not match reviewed merge commit")
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    coverage = {"version": 1, "repository": os.environ["GITHUB_REPOSITORY"], "pr_number": pr["number"],
                "head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"], "merge_tree": tree}
    Path("coverage.json").write_text(json.dumps(coverage))


if __name__ == "__main__":
    main()
