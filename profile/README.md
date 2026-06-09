# arvore-builders — org defaults

Centralized security pipeline for all repositories in this organization.

## How it works

Every pull request runs an AI-powered security review ([anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)). HIGH/CRITICAL findings block the merge.

```
.github (this repo)
├── .github/workflows/claude-security.yml   reusable workflow (single source of truth)
└── workflow-templates/claude-security.yml   template offered when creating new repos
```

The Anthropic API key lives as an org secret (`ANTHROPIC_API_KEY`, visibility: all repos). Nothing to configure per repo beyond enrolling.

## Enrolling a new repository

1. In the repo, add `.github/workflows/security.yml`:

   ```yaml
   name: Claude Security Review
   on:
     pull_request:
       types: [opened, synchronize, reopened]

   jobs:
     claude-security:
       uses: arvore-builders/.github/.github/workflows/claude-security.yml@main
       secrets: inherit
   ```

   Or, when creating the repo, pick the **Claude Security Review** template under the Actions tab.

2. Add a branch protection rule on the default branch requiring the status check **`claude-security / review`** to pass before merging.

That is the entire setup. Free plan has no org-wide ruleset enforcement, so step 2 is per repo for now.

## Tuning

The reusable workflow accepts inputs via `with:`:

- `exclude-directories` — comma-separated dirs to skip (default skips `node_modules,dist,build,.next,coverage,vendor`)
- `claude-model` — override the Claude model (default uses the action's default)
- `block-on-high` — set `false` to run in advisory mode (comments only, no merge block)

## Security notes

- The API key is an org secret; never hardcode it.
- Rotate `ANTHROPIC_API_KEY` if it is ever exposed: `gh secret set ANTHROPIC_API_KEY --org arvore-builders --visibility all`
