# sast-review — project rules

This file governs the sast-review runner codebase. It is NOT read during
security reviews. The review workflow is defined in `commands/security-review.md`.

## Do not

- Do not modify `commands/security-review.md` or `commands/security-review-ref.md`
  without explicit approval. These are carefully tuned for LLM behavior.
- Do not add dependencies without checking `pyproject.toml` first.
- Do not create new modules without a clear single responsibility.
- Do not add CLI flags without updating `README.md` and `AGENTS.md`.

## Verify before committing

1. `uv run ruff check src/`
2. `uv run mypy src/ --ignore-missing-imports`

## Architecture

| File | Responsibility |
|------|---------------|
| `src/sast_review/__init__.py` | CLI entry point, orchestration, benchmark mode |
| `src/sast_review/tools.py` | Tool detection, MCP config generation |
| `src/sast_review/inject.py` | File injection/cleanup with backup/restore |
| `src/sast_review/collect.py` | Assessment parsing, section validation |
| `src/sast_review/monitor.py` | Live session monitoring via opencode SQLite DB |
| `commands/security-review.md` | Review command with checkpoint gates (injected into target) |
| `commands/security-review-ref.md` | Classification spec + container checklist (injected into target) |
| `commands/critic-prompt.txt` | @critic subagent prompt (injected into .security-output/) |
| `commands/verifier-prompt.txt` | @verifier subagent prompt (injected into .security-output/) |
| `templates/permissions.json` | Scoped deny-list (injected into target) |
| `plugins/graphify.js` | Graphify plugin (injected if detected) |

## Quick start

```bash
uv run sast-review --list-tools --repo /path/to/any/repo
uv run sast-review --repo /path/to/any/repo --model galileo/coder-ornith:LATEST
uv run sast-review --repo /path/to/any/repo --benchmark
```

## How it works

1. Detect installed tools (graphify, semgrep, serena, trufflehog, osv-scanner, syft, grype)
2. Run graphify --code-only on target repo (if available)
3. Run syft SBOM generation + grype vulnerability scan + grype summary (if available)
3b. Run trufflehog secret scan (if available)
4. Compute diff scope if `--diff` supplied (changed files + upstream callers)
5. Inject .opencode/ commands, permissions, MCP configs into target repo
   - `$FILE_CAP` placeholder replaced with dynamic cap based on model context window
6. Execute `opencode run --command security-review --auto --format json`
7. Collect assessment, SBOM, grype results, grype summary, events, metrics to output/
8. Restore target repo from backups

## Scoped permissions

`--auto` required (headless hangs without it, GitHub #36762). Explicit deny
rules override `--auto`:
- bash: allowed except rm -rf, sudo, chmod, kill, shutdown
- edit: denied everywhere except .security-output/*
- read/grep/glob/websearch/webfetch: allowed
