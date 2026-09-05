"""Injection and cleanup of opencode configuration into target repositories.

Handles the lifecycle of injecting .opencode/ commands, permissions,
MCP server configs, and the graphify plugin into any target repo,
with backup/restore so the repo is left clean after the review.

Also handles pre-processing steps:
  - graphify: codebase knowledge graph
  - syft + grype: SBOM generation and vulnerability scanning
  - diff scope: incremental scanning via git diff
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sast_review.tools import DetectedTool

logger = logging.getLogger(__name__)

# Suffix appended to backed-up files so cleanup can find them
_BACKUP_SUFFIX = ".sast-backup"

# Context-window tiers -> max source files to scan in step 6.
# Conservative: assumes ~1.5k tokens per file read + finding write.
_FILE_CAP_TIERS: list[tuple[int, int]] = [
    (262_144, 60),   # 262k context
    (131_072, 50),   # 131k context
    (65_536, 30),    # 65k context (default)
]
_DEFAULT_FILE_CAP = 30


def compute_file_cap(model: str) -> int:
    """Estimate the file-scan cap based on the model's likely context window.

    Uses a simple heuristic: oMLX and lmstudio models default to 131k,
    galileo MoE models to 131k, galileo dense 27B+ to 65k. Falls back
    to the conservative 30-file default for unknown providers.
    """
    model_lower = model.lower()
    provider = model.split("/")[0] if "/" in model else ""

    if provider in ("omlx", "lmstudio"):
        return _context_to_cap(131_072)
    if provider == "galileo":
        # Dense 27B+ models have 65k context on galileo
        if any(tag in model_lower for tag in ("27b", "homura")):
            return _context_to_cap(65_536)
        return _context_to_cap(131_072)
    return _DEFAULT_FILE_CAP


def _context_to_cap(ctx_size: int) -> int:
    """Look up the file cap for a given context window size."""
    for threshold, cap in _FILE_CAP_TIERS:
        if ctx_size >= threshold:
            return cap
    return _DEFAULT_FILE_CAP


@dataclass
class InjectionManifest:
    """Tracks every file injected so cleanup can restore or remove them."""

    # Maps destination path -> backup path (None = no original existed)
    backups: dict[str, Path | None] = field(default_factory=dict)
    # Directories created by injection (removed on cleanup if empty)
    created_dirs: list[Path] = field(default_factory=list)


def _ensure_safe_directory(
    target_repo: Path,
    directory: Path,
    manifest: InjectionManifest | None = None,
) -> None:
    root = target_repo.resolve(strict=True)
    if directory.is_symlink():
        raise ValueError(f"refusing symlinked injection directory: {directory}")
    if directory.exists():
        if not directory.is_dir() or not directory.resolve().is_relative_to(root):
            raise ValueError(f"injection directory escapes target repository: {directory}")
        return
    parent = directory.parent.resolve()
    if not parent.is_relative_to(root):
        raise ValueError(f"injection directory escapes target repository: {directory}")
    directory.mkdir()
    if manifest is not None:
        manifest.created_dirs.append(directory)


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlinked output file: {path}")


def _track_backup(dst: Path, manifest: InjectionManifest) -> None:
    if dst.is_symlink():
        raise ValueError(f"refusing symlinked injection file: {dst}")
    if dst.exists():
        backup = dst.with_suffix(dst.suffix + _BACKUP_SUFFIX)
        if backup.is_symlink():
            raise ValueError(f"refusing symlinked injection backup: {backup}")
        shutil.copy2(dst, backup)
        manifest.backups[str(dst)] = backup
        logger.debug("Backed up %s -> %s", dst, backup)
    else:
        manifest.backups[str(dst)] = None


def _backup_and_copy(src: Path, dst: Path, manifest: InjectionManifest) -> None:
    """Back up dst if it exists, then copy src to dst."""
    _track_backup(dst, manifest)
    shutil.copy2(src, dst)
    logger.info("Injected %s", dst)


def inject_prior_knowledge(
    target_repo: Path,
    content: str,
    manifest: InjectionManifest,
) -> None:
    """Temporarily inject bounded same-repository knowledge context."""
    security_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, security_out, manifest)
    destination = security_out / "PRIOR_KNOWLEDGE.md"
    _track_backup(destination, manifest)
    destination.write_text(content, encoding="utf-8")
    logger.info("Injected prior knowledge context into %s", destination)


def inject_commands(
    runner_dir: Path,
    target_repo: Path,
    manifest: InjectionManifest,
    *,
    file_cap: int = 30,
) -> None:
    """Copy security-review command templates into target .opencode/commands/.

    Also copies subagent prompt files into .security-output/ so the model
    reads them fresh at invocation time (late in the context window) rather
    than relying on prompt text inlined in the command template.

    Args:
        runner_dir: sast-review project root.
        target_repo: target repository path.
        manifest: injection tracking manifest.
        file_cap: max files to scan in step 6, scaled to model context.
    """
    opencode_dir = target_repo / ".opencode"
    _ensure_safe_directory(target_repo, opencode_dir, manifest)
    commands_dir = opencode_dir / "commands"
    _ensure_safe_directory(target_repo, commands_dir, manifest)

    for filename in ("security-review.md", "security-review-ref.md"):
        src = runner_dir / "commands" / filename
        dst = commands_dir / filename
        _backup_and_copy(src, dst, manifest)

    # Replace $FILE_CAP placeholder with the computed cap
    review_cmd = commands_dir / "security-review.md"
    content = review_cmd.read_text()
    if "$FILE_CAP" in content:
        content = content.replace("$FILE_CAP", str(file_cap))
        review_cmd.write_text(content)
        logger.info("File cap set to %d in injected command", file_cap)

    # Inject subagent prompt files into .security-output/ so the model
    # reads them at steps 11/12 — fresh in context when needed.
    security_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, security_out, manifest)
    for prompt_file in ("critic-prompt.txt", "verifier-prompt.txt"):
        src = runner_dir / "commands" / prompt_file
        if src.exists():
            dst = security_out / prompt_file
            _backup_and_copy(src, dst, manifest)


def inject_permissions(
    runner_dir: Path,
    target_repo: Path,
    manifest: InjectionManifest,
) -> None:
    """Merge scoped permissions into the project opencode.json."""
    opencode_dir = target_repo / ".opencode"
    _ensure_safe_directory(target_repo, opencode_dir, manifest)
    proj_config = opencode_dir / "opencode.json"

    # Load existing config or create fresh
    _track_backup(proj_config, manifest)
    if proj_config.exists():
        existing = json.loads(proj_config.read_text())
    else:
        existing = {"$schema": "https://opencode.ai/config.json"}

    # Load the scoped permissions template
    perms_template = runner_dir / "templates" / "permissions.json"
    perms = json.loads(perms_template.read_text())

    # Merge: our permissions override, preserve everything else
    existing["permission"] = perms["permission"]

    proj_config.write_text(json.dumps(existing, indent=2) + "\n")
    logger.info("Injected permissions into %s", proj_config)


def inject_mcp_servers(
    target_repo: Path,
    mcp_config: dict[str, dict[str, Any]],
    manifest: InjectionManifest,
) -> None:
    """Add MCP server entries to the project opencode.json.

    Must be called AFTER inject_permissions so the config file exists.
    """
    if not mcp_config:
        return

    proj_config = target_repo / ".opencode" / "opencode.json"
    existing = json.loads(proj_config.read_text())

    # Merge MCP entries, preserving any existing ones
    existing_mcp: dict[str, Any] = existing.get("mcp", {})
    existing_mcp.update(mcp_config)
    existing["mcp"] = existing_mcp

    proj_config.write_text(json.dumps(existing, indent=2) + "\n")
    logger.info(
        "Injected MCP servers: %s",
        ", ".join(mcp_config.keys()),
    )


def inject_agent_overrides(
    target_repo: Path,
    critic_model: str | None = None,
    verifier_model: str | None = None,
) -> None:
    """Override critic/verifier agent models in the project opencode.json.

    Must be called AFTER inject_permissions so the config file exists.
    Only modifies the model field — all other agent settings (permissions,
    tools, system prompts) remain as configured in the global config.
    """
    if not critic_model and not verifier_model:
        return

    proj_config = target_repo / ".opencode" / "opencode.json"
    existing = json.loads(proj_config.read_text())

    agents: dict[str, Any] = existing.get("agent", {})
    if critic_model:
        agents.setdefault("critic", {})["model"] = critic_model
        logger.info("Critic model override: %s", critic_model)
    if verifier_model:
        agents.setdefault("verifier", {})["model"] = verifier_model
        logger.info("Verifier model override: %s", verifier_model)
    existing["agent"] = agents

    proj_config.write_text(json.dumps(existing, indent=2) + "\n")


def inject_omlx_unload_script(
    target_repo: Path,
    model: str,
    base_url: str,
    manifest: InjectionManifest,
) -> None:
    """Write a helper script that unloads the primary oMLX model.

    Called before subagent steps so the critic/verifier models can
    load without hitting the oMLX memory guard.  The script is
    idempotent — calling it when the model is already unloaded is
    a no-op.

    Only written when the primary model uses the oMLX provider.
    The workflow calls ``bash .security-output/omlx-unload.sh``
    before invoking @critic.
    """
    # Extract model ID from provider/model format
    model_id = model.split("/", 1)[1] if "/" in model else model
    unload_url = f"{base_url.rstrip('/')}/models/{model_id}/unload"

    script = f"""\
#!/usr/bin/env bash
# Auto-generated by sast-review runner — unloads the primary model
# from oMLX so subagent models can load without OOM.
set -euo pipefail
URL="{unload_url}"
AUTH="${{SAST_REVIEW_OMLX_API_KEY:-}}"
AUTH_ARGS=()
if [ -n "$AUTH" ]; then
  AUTH_ARGS=(-H "Authorization: Bearer $AUTH")
fi
echo "Unloading primary model: {model_id}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{{http_code}}" \\
  -X POST "${{AUTH_ARGS[@]}}" \\
  -H "Content-Type: application/json" "$URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "404" ]; then
  echo "Primary model unloaded (HTTP $HTTP_CODE)"
  sleep 2  # allow oMLX to release memory before subagent loads
else
  echo "WARNING: unload returned HTTP $HTTP_CODE (continuing anyway)"
fi
"""
    sec_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, sec_out, manifest)
    script_path = sec_out / "omlx-unload.sh"
    _track_backup(script_path, manifest)
    script_path.write_text(script)
    script_path.chmod(0o700)
    logger.info("Wrote oMLX unload script to %s", script_path)


def inject_graphify_plugin(
    runner_dir: Path,
    target_repo: Path,
    manifest: InjectionManifest,
) -> None:
    """Copy the graphify opencode plugin into the target repo.

    The plugin injects a one-time reminder to use graphify query
    when graphify-out/graph.json exists.
    """
    opencode_dir = target_repo / ".opencode"
    _ensure_safe_directory(target_repo, opencode_dir, manifest)
    plugins_dir = opencode_dir / "plugins"
    _ensure_safe_directory(target_repo, plugins_dir, manifest)

    src = runner_dir / "plugins" / "graphify.js"
    if not src.exists():
        logger.debug("No graphify.js plugin to inject (not bundled)")
        return

    dst = plugins_dir / "graphify.js"
    _backup_and_copy(src, dst, manifest)

    # Also register the plugin in opencode.json
    proj_config = target_repo / ".opencode" / "opencode.json"
    config = json.loads(proj_config.read_text())
    plugins: list[str] = config.get("plugin", [])
    plugin_path = ".opencode/plugins/graphify.js"
    if plugin_path not in plugins:
        plugins.append(plugin_path)
        config["plugin"] = plugins
        proj_config.write_text(json.dumps(config, indent=2) + "\n")
        logger.info("Registered graphify plugin in opencode.json")


def run_graphify_preprocess(
    target_repo: Path,
    full_mode: bool = False,
    llm_base_url: str = "",
    llm_model: str = "",
    llm_api_key: str = "sk-noauth",
) -> bool:
    """Run graphify on the target repo as a pre-processing step.

    Args:
        target_repo: path to the repository.
        full_mode: if True, run full semantic extraction with LLM.
            if False (default), run --code-only (AST only, fast).
        llm_base_url: OpenAI-compatible endpoint for full mode.
            Resolved from the primary model's provider when called
            from the runner.
        llm_model: model name for full mode.
        llm_api_key: API key for the LLM endpoint.

    Returns:
        True if graphify completed successfully, False otherwise.
    """
    graphify_out = target_repo / "graphify-out"
    graph_exists = graphify_out.exists() and (graphify_out / "graph.json").exists()

    if full_mode:
        if not llm_base_url or not llm_model:
            logger.error(
                "graphify full mode requires llm_base_url and llm_model"
            )
            return False
        cmd = ["graphify", str(target_repo)]
        env_extra: dict[str, str] = {
            "OPENAI_BASE_URL": llm_base_url,
            "OPENAI_MODEL": llm_model,
            "OPENAI_API_KEY": llm_api_key,
        }
        logger.info(
            "Running graphify full extraction (backend=%s, model=%s)",
            llm_base_url,
            llm_model,
        )
    elif graph_exists:
        cmd = ["graphify", "update", str(target_repo)]
        env_extra = {}
        logger.info("Refreshing existing graphify knowledge graph")
    else:
        cmd = ["graphify", str(target_repo), "--code-only"]
        env_extra = {}
        logger.info("Running graphify --code-only")

    try:
        import os
        env = {**os.environ, **env_extra}
        result = subprocess.run(
            cmd,
            cwd=target_repo,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min max for graphify
            env=env,
            check=False,
        )
        if result.returncode == 0:
            logger.info("graphify completed successfully")
            return True
        logger.warning(
            "graphify exited with code %d: %s",
            result.returncode,
            result.stderr[:500],
        )
    except subprocess.TimeoutExpired:
        logger.warning("graphify timed out after 300s")
    except FileNotFoundError:
        logger.error("graphify binary not found")
    return False


def run_sbom_preprocess(
    target_repo: Path,
    syft_binary: Path | None = None,
    grype_binary: Path | None = None,
) -> tuple[Path | None, Path | None]:
    """Generate SBOM with syft and scan it with grype.

    Runs as a pre-processing step before the opencode review.
    Results are written to .security-output/ so the reviewing
    model can discover and reference them.

    Args:
        target_repo: path to the repository.
        syft_binary: resolved syft binary (auto-detected if None).
        grype_binary: resolved grype binary (auto-detected if None).

    Returns:
        Tuple of (sbom_path, grype_results_path). Either may be None
        if the corresponding tool failed or wasn't available.
    """
    security_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, security_out)

    sbom_path: Path | None = None
    grype_path: Path | None = None

    # Phase 1: SBOM generation with syft
    syft_bin = str(syft_binary) if syft_binary else shutil.which("syft")
    if syft_bin is None:
        logger.debug("syft not available, skipping SBOM generation")
        return None, None

    sbom_path = security_out / "sbom.cyclonedx.json"
    _reject_symlink(sbom_path)
    logger.info("Running syft SBOM generation on %s", target_repo.name)
    try:
        result = subprocess.run(
            [syft_bin, f"dir:{target_repo}", "-o", f"cyclonedx-json={sbom_path}"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode == 0:
            logger.info("SBOM generated: %s", sbom_path)
        else:
            logger.warning("syft exited %d: %s", result.returncode, result.stderr[:300])
            sbom_path = None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("syft failed: %s", exc)
        sbom_path = None

    if sbom_path is None:
        return None, None

    # Phase 2: vulnerability scan with grype
    grype_bin = str(grype_binary) if grype_binary else shutil.which("grype")
    if grype_bin is None:
        logger.debug("grype not available, skipping vulnerability scan")
        return sbom_path, None

    grype_path = security_out / "grype-results.json"
    _reject_symlink(grype_path)
    logger.info("Running grype vulnerability scan against SBOM")
    try:
        result = subprocess.run(
            [grype_bin, f"sbom:{sbom_path}", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode in (0, 1):
            # grype exit 1 = vulnerabilities found (expected)
            grype_path.write_text(result.stdout)
            _write_grype_summary(grype_path)
            vuln_count = _count_grype_vulns(result.stdout)
            logger.info(
                "Grype scan complete: %d vulnerabilities found", vuln_count,
            )
        else:
            logger.warning("grype exited %d: %s", result.returncode, result.stderr[:300])
            grype_path = None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("grype failed: %s", exc)
        grype_path = None

    return sbom_path, grype_path


def _count_grype_vulns(grype_json: str) -> int:
    """Count vulnerabilities in grype JSON output."""
    try:
        data = json.loads(grype_json)
        return len(data.get("matches", []))
    except (json.JSONDecodeError, TypeError):
        return 0


def _write_grype_summary(grype_path: Path) -> None:
    """Write a compact grype-summary.json next to the full results.

    Extracts only the fields the reviewing model needs, preventing
    it from reading the full grype JSON (which can exceed 50k tokens).
    """
    try:
        data = json.loads(grype_path.read_text())
    except (json.JSONDecodeError, OSError):
        return

    summary: list[dict[str, str]] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix_versions = vuln.get("fix", {}).get("versions", [])
        summary.append({
            "package": artifact.get("name", "?"),
            "version": artifact.get("version", "?"),
            "cve": vuln.get("id", "?"),
            "severity": vuln.get("severity", "?"),
            "fixed_in": ", ".join(fix_versions) if fix_versions else "no fix",
            "description": vuln.get("description", "")[:120],
        })

    out = grype_path.parent / "grype-summary.json"
    _reject_symlink(out)
    out.write_text(json.dumps(summary, indent=2) + "\n")
    logger.info("Grype summary written: %d vulnerabilities", len(summary))


def run_trufflehog_preprocess(
    target_repo: Path,
    trufflehog_binary: Path | None = None,
) -> Path | None:
    """Scan for hardcoded secrets with trufflehog.

    Runs as a pre-processing step before the opencode review.
    Results are written to .security-output/trufflehog-results.json
    so the reviewing model can discover and reference them.

    Args:
        target_repo: path to the repository.
        trufflehog_binary: resolved trufflehog binary path.

    Returns:
        Path to trufflehog results file, or None if scan failed.
    """
    th_bin = str(trufflehog_binary) if trufflehog_binary else shutil.which("trufflehog")
    if th_bin is None:
        logger.debug("trufflehog not available, skipping secret scan")
        return None

    security_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, security_out)
    results_path = security_out / "trufflehog-results.json"
    _reject_symlink(results_path)

    # Write exclusion patterns to a temp file (--exclude-paths expects a file)
    exclude_file = security_out / ".trufflehog-excludes"
    _reject_symlink(exclude_file)
    exclude_file.write_text(
        "(?:^|/)\\.(opencode|git|security-output)/\n"
        "(?:^|/)node_modules/\n"
        "(?:^|/)graphify-out/\n"
    )

    logger.info("Running trufflehog secret scan on %s", target_repo.name)
    try:
        result = subprocess.run(
            [
                th_bin, "filesystem", str(target_repo),
                "--json", "--no-update",
                "--exclude-paths", str(exclude_file),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        # trufflehog exits 0 on success regardless of findings
        findings: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        results_path.write_text(json.dumps(findings, indent=2) + "\n")
        logger.info(
            "TruffleHog scan complete: %d candidates found", len(findings),
        )
        return results_path
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("trufflehog failed: %s", exc)
        return None
    finally:
        exclude_file.unlink(missing_ok=True)


def compute_diff_scope(
    target_repo: Path,
    diff_ref: str = "HEAD~1",
) -> list[str]:
    """Compute the set of files affected by a git diff.

    Returns relative paths of files that changed compared to the
    given ref. Only includes files that currently exist (filters
    out deletions).

    Args:
        target_repo: path to the repository (must be a git repo).
        diff_ref: git ref to diff against (default: HEAD~1).

    Returns:
        List of relative file paths that changed.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", diff_ref],
            cwd=target_repo,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(
                "git diff failed (ref=%s): %s", diff_ref, result.stderr[:200],
            )
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("git diff failed: %s", exc)
        return []

    changed = [
        f for f in result.stdout.strip().splitlines()
        if f and (target_repo / f).exists()
    ]
    logger.info(
        "Diff scope (ref=%s): %d changed files", diff_ref, len(changed),
    )
    return changed


def compute_callers(
    target_repo: Path,
    changed_files: list[str],
) -> list[str]:
    """Find files that import or reference the changed files.

    Uses graphify's graph.json if available, falls back to a
    simple grep-based approach for import/require statements.

    Args:
        target_repo: path to the repository.
        changed_files: relative paths of changed files.

    Returns:
        Relative paths of upstream callers (excluding the changed
        files themselves, which are already included).
    """
    if not changed_files:
        return []

    callers: set[str] = set()

    # Try graphify graph.json first (has proper import edges)
    graph_file = target_repo / "graphify-out" / "graph.json"
    if graph_file.exists():
        callers = _callers_from_graphify(graph_file, changed_files)
    else:
        callers = _callers_from_grep(target_repo, changed_files)

    # Exclude the changed files themselves
    result = sorted(callers - set(changed_files))
    if result:
        logger.info("Found %d upstream callers of changed files", len(result))
    return result


def _callers_from_graphify(
    graph_file: Path,
    changed_files: list[str],
) -> set[str]:
    """Extract callers from graphify's graph.json edges."""
    try:
        graph = json.loads(graph_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to read graph.json: %s", exc)
        return set()

    # Build reverse adjacency: target -> set of sources
    changed_set = set(changed_files)
    callers: set[str] = set()
    for edge in graph.get("edges", []):
        source = edge.get("source", "")
        target = edge.get("target", "")
        if target in changed_set and source not in changed_set:
            callers.add(source)
    return callers


def _callers_from_grep(
    target_repo: Path,
    changed_files: list[str],
) -> set[str]:
    """Grep-based fallback: find files importing changed modules."""
    callers: set[str] = set()
    # Extract module names from changed file paths
    module_names = set()
    for f in changed_files:
        stem = Path(f).stem
        if stem != "__init__":
            module_names.add(stem)

    if not module_names:
        return callers

    # Build a grep pattern matching import statements
    pattern = "|".join(module_names)
    try:
        result = subprocess.run(
            ["grep", "-rl", "-E", f"(import|require|from).*({pattern})", "."],
            cwd=target_repo,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode in (0, 1):
            for line in result.stdout.strip().splitlines():
                # Normalize ./path -> path
                rel = line.lstrip("./")
                if rel:
                    callers.add(rel)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return callers


def write_diff_scope_file(
    target_repo: Path,
    changed_files: list[str],
    callers: list[str],
    diff_ref: str,
) -> Path | None:
    """Write a DIFF_SCOPE.md file for the model to discover.

    Placed in .security-output/ so the reviewing model can read it
    during its scan and prioritize changed files + their callers.

    Args:
        target_repo: path to the repository.
        changed_files: relative paths of changed files.
        callers: relative paths of upstream callers.
        diff_ref: git ref used for the diff.

    Returns:
        Path to the written file, or None if no changes.
    """
    if not changed_files:
        return None

    security_out = target_repo / ".security-output"
    _ensure_safe_directory(target_repo, security_out)
    scope_file = security_out / "DIFF_SCOPE.md"
    _reject_symlink(scope_file)

    lines = [
        "# Incremental Scan Scope",
        "",
        f"This review is scoped to changes since `{diff_ref}`.",
        "Prioritize these files. Other files may be reviewed for context.",
        "",
        "## Changed files",
        "",
    ]
    for f in sorted(changed_files):
        lines.append(f"- `{f}`")

    if callers:
        lines.extend([
            "",
            "## Upstream callers (files that import/reference changed files)",
            "",
        ])
        for f in sorted(callers):
            lines.append(f"- `{f}`")

    lines.extend([
        "",
        (
            f"**Total scope:** {len(changed_files)} changed + {len(callers)} callers"
            f" = {len(changed_files) + len(callers)} files"
        ),
        "",
    ])

    scope_file.write_text("\n".join(lines) + "\n")
    logger.info("Wrote diff scope: %s", scope_file)
    return scope_file


def cleanup(manifest: InjectionManifest) -> None:
    """Restore backed-up files and remove injected files with no original."""
    for dst_str, backup in manifest.backups.items():
        dst = Path(dst_str)
        if backup is not None:
            shutil.copy2(backup, dst)
            backup.unlink()
            logger.debug("Restored %s from backup", dst)
        elif dst.exists():
            dst.unlink()
            logger.debug("Removed injected %s", dst)

    # Remove directories we created (if empty)
    for dir_path in reversed(manifest.created_dirs):
        try:
            dir_path.rmdir()
            logger.debug("Removed empty dir %s", dir_path)
        except OSError:
            pass  # not empty, leave it


@contextmanager
def injection_context(
    runner_dir: Path,
    target_repo: Path,
    mcp_config: dict[str, dict[str, Any]],
    detected_tools: list[DetectedTool],
    critic_model: str | None = None,
    verifier_model: str | None = None,
    primary_model: str = "",
    primary_base_url: str = "",
    prior_knowledge: str | None = None,
) -> Generator[InjectionManifest]:
    """Context manager that injects config on entry and cleans up on exit.

    Usage:
        with injection_context(runner_dir, target, mcp, tools) as manifest:
            # run the review
            ...
        # cleanup happens automatically
    """
    manifest = InjectionManifest()
    file_cap = compute_file_cap(primary_model) if primary_model else _DEFAULT_FILE_CAP
    try:
        inject_commands(runner_dir, target_repo, manifest, file_cap=file_cap)
        if prior_knowledge is not None:
            inject_prior_knowledge(target_repo, prior_knowledge, manifest)
        inject_permissions(runner_dir, target_repo, manifest)
        inject_mcp_servers(target_repo, mcp_config, manifest)
        inject_agent_overrides(target_repo, critic_model, verifier_model)

        # Inject oMLX unload script if primary is an oMLX model
        if primary_model and primary_model.startswith("omlx/"):
            inject_omlx_unload_script(
                target_repo,
                primary_model,
                primary_base_url,
                manifest,
            )

        # Inject graphify plugin if graphify was detected
        has_graphify = any(t.name == "graphify" for t in detected_tools)
        if has_graphify:
            inject_graphify_plugin(runner_dir, target_repo, manifest)

        yield manifest
    finally:
        cleanup(manifest)
        logger.info("Injection cleanup complete")
