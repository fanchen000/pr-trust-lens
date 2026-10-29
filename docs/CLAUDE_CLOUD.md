# Claude Cloud connection: verified October 29, 2026

This **public, self-contained, no-secrets** Python repository is the only suggested Claude Code Cloud entry point. No workstation exports, personal context, Hermes, DragonFlow, or trading code belong here.

## One-time cloud setup

1. Use the **official** [Claude Code Cloud](https://claude.ai/code) and its GitHub App onboarding. Choose **Only select repositories**, with `fanchen000/pr-trust-lens` as the sole selected repository. Important: [Anthropic documents](https://code.claude.com/docs/en/claude-code-on-the-web) that GitHub App cloud sessions can access **public repositories generally**; selecting one repository limits the *private repository installation scope*, not public read access. Do not use `/web-setup`, which sends the local `gh` CLI token and can inherit broader repository access.
2. Use an ordinary **single-repo session outside Claude Projects**, without additional repositories. [Project threads and multi-repo sessions do not fully load](https://code.claude.com/docs/en/settings) the repo's `.claude/settings.json` permission rules.
3. Choose the plain **Default** Anthropic cloud environment: trusted network access, no setup script, no custom environment variables, no network secrets, no MCP servers or installed plugins. Do **not** enable unrestricted network access. The default already permits approved package registries.
4. Choose **Manual / review-first** permission mode for the first task. Verify loaded rules in `/permissions`. Project denies are an extra guard, **not a sandbox**: indirect Python subprocess reads may bypass a file-tool deny rule.
5. Use your normal claude.ai login. Do not share/copy OAuth tokens, browser sessions, local Windows identity profiles or third-party proxy credentials. Leave `ANTHROPIC_API_KEY` unset when using a subscription; check `/status` if you later run local CLI sessions. Never route third-party workloads through subscription OAuth.

## First cloud task

Ask Claude to **read-only inspect** the repository and report its current state, with no commits, code edits, other repositories or shell scripts. Then use only these existing verification commands:

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m pr_trust_lens scan . --fail-on high
```

Report each actual exit code and any failed tests. Only after that, undertake a *small* task on a new branch and review its PR diff. Disable PR auto-fix until comment-triggered automations have been reviewed. Do not self-merge.

## What is actually enforced

- GitHub Actions tests run against Python 3.10, 3.12, and 3.13 and check the repository for accidental credential and cloud permission drift.
- `.gitignore` does **not** remove already committed or historically exposed secrets.
- `CLAUDE.md` is guidance, not a security barrier; `.claude/settings.json` protects only certain matching operations in applicable sessions. GitHub service-side rulesets and the cloud VM's network isolation are separate controls.
- **GitHub `main` branch protection is not yet verified/enabled.** At [GitHub Rulesets](https://github.com/fanchen000/pr-trust-lens/settings/rules), require a PR, passing `test (3.10)`, `test (3.12)`, `test (3.13)`, block force pushes and deletion. No exception for the Claude GitHub App.
- This setup lowers accidental access and execution risk; it does **not** guarantee eligibility for credits or immunity from account restrictions.

## Source checks

Official: [Claude Cloud/GitHub access](https://code.claude.com/docs/en/claude-code-on-the-web), [cloud environments](https://code.claude.com/docs/en/cloud-environments), [cloud settings precedence](https://code.claude.com/docs/en/settings), [permission limits](https://code.claude.com/docs/en/permissions), [best practices](https://code.claude.com/docs/en/best-practices), [subscription authentication](https://support.claude.com/en/articles/13189465-log-in-to-your-claude-account).

Community signals, not security guarantees: [October 20 discussion about plugin/context sprawl](https://www.reddit.com/r/ClaudeCode/comments/1xb2833/), [October 14 warning that prose alone cannot block pushes](https://www.reddit.com/r/ClaudeCode/comments/1x5pm53/), [October 7 malicious build configuration report](https://www.reddit.com/r/ClaudeCode/comments/1wzj3cw/). These favor a tiny environment with no extra scripts or credentials.
