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

1. `uv run python -m unittest discover -s tests`
2. `uv run ruff check src/ tests/`
3. `uv run mypy src/ --ignore-missing-imports`

## Architecture

| File | Responsibility |
|------|---------------|
| `src/sast_review/__init__.py` | CLI entry point, orchestration, benchmark mode |
| `src/sast_review/tools.py` | Tool detection, MCP config generation |
| `src/sast_review/inject.py` | File injection/cleanup with backup/restore |
| `src/sast_review/collect.py` | Assessment parsing, section validation |
| `src/sast_review/fingerprint.py` | Stable IDs and Git/source evidence fingerprints |
| `src/sast_review/knowledge_models.py` | Versioned evidence, verdict, verifier, and pattern models |
| `src/sast_review/knowledge_store.py` | Authoritative SQLite/WAL ledger and FTS5 pattern index |
| `src/sast_review/knowledge_collect.py` | Assessment-to-bundle parsing and prior-context rendering |
| `src/sast_review/knowledge_pipeline.py` | Pre/post-review knowledge orchestration |
| `src/sast_review/knowledge_mcp.py` | Read-only localhost Streamable HTTP MCP daemon |
| `src/sast_review/okf_export.py` | One-way OKF v0.2 publication export and validation |
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
uv run sast-review-knowledge
uv run sast-review --repo /path/to/any/repo --repo-id <stable-uuid>
```

## How it works

1. Detect installed tools (graphify, semgrep, serena, trufflehog, osv-scanner, syft, grype)
2. Run graphify --code-only, or incrementally update an existing graph (if available)
3. Run syft SBOM generation + grype vulnerability scan + grype summary (if available)
3b. Run trufflehog secret scan (if available)
4. Compute diff scope if `--diff` supplied (changed files + upstream callers)
5. Derive a stable Git repository ID (or use `--repo-id`) and render bounded prior knowledge
6. Inject .opencode/ commands, permissions, MCP configs, and prior context
   - `$FILE_CAP` placeholder replaced with dynamic cap based on model context window
7. Execute `opencode run --command security-review --auto --format json`
8. Resume the same OpenCode session once if its fresh assessment is incomplete
9. Collect assessment, scanner artifacts, typed evidence bundle, OKF export, and metrics
10. Gate SQLite ingestion on assessment completeness and per-finding verifier evidence
11. Restore target repo from backups

## Scoped permissions

`--auto` required (headless hangs without it, GitHub #36762). Explicit deny
rules override `--auto`:
- bash: allowed except rm -rf, sudo, chmod, kill, shutdown
- edit: denied everywhere except .security-output/*
- read/grep/glob/websearch/webfetch: allowed
