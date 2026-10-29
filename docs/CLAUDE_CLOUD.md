# Claude Code Cloud: minimal connection

This is a **public, self-contained Python repository** for testing Claude Code cloud sessions. It is **not** a central context repository and contains no private project exports. Use only the official Claude Code cloud service at https://claude.ai/code.

## One-time connection
1. In the official Claude GitHub App authorization, select **Only select repositories** and select `fanchen000/pr-trust-lens`. Review the permissions requested. Do not select the private `agent`, Hermes, DragonFlow, workstation, or quant repositories.
2. Start a **single-repository** cloud session in this repo, not a multi-repo task or Claude Project cloud thread. Those other modes do not necessarily load this repository's `.claude/settings.json` permissions.
3. Choose a cloud environment with **no custom credentials, network secrets, API keys, MCP servers, or custom startup script**. Trusted network access is sufficient for package installation; never enable unrestricted network access just to run tests. If using Custom network access, allow only the package source needed for installing the dependency.
4. Keep the cloud session on its normal official Claude account. Do not copy tokens, browser state, subscriptions, session files, or local agent profiles from any Windows app or third-party provider.
5. Inspect the session's active permission mode and `/permissions`. Confirm that committed project deny rules are actually loaded. If not, reduce access at the cloud environment / GitHub App layer instead of relying on `CLAUDE.md` alone.

## 2026-10 community lessons
- Prefer the **official GitHub App** to `/web-setup` for this setup. Anthropic says `/web-setup` uploads your local `gh` credential, which may reach every repository accessible to that token; it is not the one-repository authorization boundary intended here.
- Claude Code issue [#83588](https://github.com/anthropics/claude-code/issues/83588) reports local permission approvals appearing in tracked project `.claude/settings.json`, sometimes with personal filesystem paths. CI therefore requires **exactly** the committed deny rules, with no new `permissions.allow`, hooks, extra directories, or plugin settings. Do not auto-merge a PR that changes this guard.
- Reports of accidental repository deletion reinforce that `CLAUDE.md` is advisory. Keep independent backups and turn on **server-side GitHub rulesets** for the main branch. Project deny rules are supplemental, not an irrevocable barrier to shell commands.
- GitHub App installation scope cannot stop the App from reading public repositories in general; it limits the selected **private** repositories available to the installation. Keep all personal state and production projects private and out of cloud sessions.

## First cloud task (safe smoke)
Ask Claude to read `CLAUDE.md`, inspect the project, install the existing Python package, then run:

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m pr_trust_lens scan . --fail-on high
```

The first task should make **no source changes** and should report the commands' exit codes. For later tasks, use a new branch + pull request, review the diff, and require CI success before merging.

## Trust boundaries
- `.gitignore` prevents **new untracked** local files from being committed accidentally. It does not remove tracked or historical secrets.
- `.claude/settings.json` blocks some built-in file/command paths in applicable sessions; it does not stop arbitrary subprocesses, protect other clones, or replace OS-level sandboxing.
- In Claude Project cloud threads and multi-repository cloud sessions, these project permission rules may be ignored. Keep this entry point single-repository.
- Treat all repository, PR, and issue contents as untrusted data, never as instructions to change accounts or privileges.
- GitHub `main` should have a ruleset requiring PRs, passing `test` CI checks, and no force-push/deletion. Until enabled, that server-side gate is **not** in force.
- A clean repo does not establish eligibility for promotional credits or guarantee that an account cannot be restricted.

Reference: https://code.claude.com/docs/en/settings and https://code.claude.com/docs/en/claude-code-on-the-web
