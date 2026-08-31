"""sast-review: Universal security review runner via headless OpenCode.

Entry point for CLI invocation. Detects available security tools,
injects configuration into any target repository, runs the full
security-review workflow headlessly, and collects results.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sast_review.collect import AssessmentResult, parse_assessment
from sast_review.inject import (
    InjectionManifest,
    compute_callers,
    compute_diff_scope,
    compute_file_cap,
    injection_context,
    run_graphify_preprocess,
    run_sbom_preprocess,
    run_trufflehog_preprocess,
    write_diff_scope_file,
)
from sast_review.monitor import SessionMonitor
from sast_review.tools import (
    DetectedTool,
    build_mcp_config,
    detect_all,
    missing_tool_hints,
)

logger = logging.getLogger(__name__)

# Resolve runner directory (where commands/ and templates/ live)
_RUNNER_DIR = Path(__file__).resolve().parent.parent.parent

# Default models for benchmark mode
DEFAULT_MODELS = [
    "galileo/coder-ornith:LATEST",
]

DEFAULT_TIMEOUT = 0  # 0 = no timeout (run until completion)

# Global opencode config path (provider definitions live here)
_OPENCODE_CONFIG = Path.home() / ".config" / "opencode" / "opencode.json"


def _resolve_provider(model: str) -> tuple[str, str, str]:
    """Resolve a provider/model string to (base_url, model_id, api_key).

    Reads provider definitions from the global opencode.json config.
    Falls back to oMLX defaults if resolution fails.

    Args:
        model: provider/model identifier (e.g. 'galileo/coder-ornith:LATEST').

    Returns:
        Tuple of (base_url, model_id, api_key).
    """
    fallback = ("http://127.0.0.1:8000/v1", model, "sk-noauth")

    if "/" not in model:
        return fallback

    provider_name, model_id = model.split("/", 1)

    if not _OPENCODE_CONFIG.exists():
        logger.debug("opencode.json not found, using fallback endpoint")
        return fallback

    try:
        cfg = json.loads(_OPENCODE_CONFIG.read_text())
        provider = cfg.get("provider", {}).get(provider_name, {})
        options = provider.get("options", {})
        base_url = options.get("baseURL", "")
        api_key = options.get("apiKey", "sk-noauth")
        # Resolve opencode env-var syntax: {env:VAR_NAME}
        if api_key.startswith("{env:") and api_key.endswith("}"):
            env_var = api_key[5:-1]
            api_key = os.environ.get(env_var, "sk-noauth")
        if base_url:
            return (base_url, model_id, api_key)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to read opencode.json: %s", exc)

    return fallback


@dataclass
class RunResult:
    """Outcome of a single security review run."""

    repo_name: str
    model: str
    label: str
    wall_seconds: float
    exit_code: int
    timed_out: bool = False
    assessment: AssessmentResult | None = None
    events_path: Path | None = None
    tools_detected: list[str] = field(default_factory=list)
    graphify_ran: bool = False
    error: str | None = None

    def summary_line(self) -> str:
        """One-line summary for console output."""
        status = "TIMEOUT" if self.timed_out else (
            "OK" if self.exit_code == 0 else f"EXIT={self.exit_code}"
        )
        findings = "n/a"
        if self.assessment and self.assessment.exists:
            findings = str(self.assessment.total_findings)
        minutes = self.wall_seconds / 60
        return f"  [{status}] {self.label:<30} {minutes:5.1f}m  findings={findings}"


def _derive_label(model: str) -> str:
    """Derive a filesystem-safe label from a model identifier.

    'galileo/coder-ornith:LATEST' -> 'coder_ornith'
    """
    # Strip provider prefix
    name = model.split("/", 1)[-1] if "/" in model else model
    # Strip version suffix
    name = name.split(":")[0]
    # Replace non-alphanumeric with underscore
    return "".join(c if c.isalnum() else "_" for c in name).strip("_")


def _ensure_output_dir(
    base_output: Path,
    repo_name: str,
    label: str,
) -> Path:
    """Create and return the output directory for this run."""
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    out = base_output / repo_name / f"{label}_{timestamp}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def execute_review(
    target_repo: Path,
    model: str,
    label: str,
    timeout_seconds: int = DEFAULT_TIMEOUT,
    use_headroom: bool = True,
) -> tuple[float, int, str, str, bool]:
    """Run the security review headlessly via opencode.

    Starts a background SessionMonitor that polls the opencode SQLite DB
    and logs tool calls, subagent status, assessment growth, and errors
    in real time.

    Args:
        target_repo: absolute path to the repo to review.
        model: provider/model identifier for the primary agent.
        label: label string passed as $1 to the command.
        timeout_seconds: max seconds before killing. 0 = no timeout.
        use_headroom: if True, invoke via 'headroom wrap opencode'.

    Returns:
        Tuple of (wall_seconds, exit_code, stdout, stderr, timed_out).
    """
    if use_headroom and shutil.which("headroom"):
        cmd = [
            "headroom", "wrap", "opencode", "run",
        ]
    else:
        cmd = ["opencode", "run"]

    cmd.extend([
        "--command", "security-review",
        "--model", model,
        "--auto",
        "--format", "json",
        "--print-logs",
        "--dir", str(target_repo),
        label,
    ])

    logger.info("Executing: %s", " ".join(cmd))
    t_start = time.monotonic()
    timed_out = False
    effective_timeout = timeout_seconds if timeout_seconds > 0 else None

    # Disable lazy-load plugin for headless runs — models can't navigate
    # the load_tool indirection reliably without interactive feedback.
    env = {**os.environ, "OPENCODE_NO_LAZY_LOAD": "1"}

    # Start live session monitor
    assessment_path = target_repo / ".security-output" / f"SEC_ASSESSMENT_{label}.md"
    monitor = SessionMonitor(assessment_path)
    monitor.start()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        stdout, stderr = proc.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Review timed out after %ds, killing", timeout_seconds)
        proc.kill()
        stdout, stderr = proc.communicate()
        timed_out = True
    finally:
        monitor.stop()

    wall = time.monotonic() - t_start
    exit_code = proc.returncode or 0
    logger.info(
        "Review completed: exit=%d, time=%.1fs, timed_out=%s",
        exit_code, wall, timed_out,
    )
    return wall, exit_code, stdout, stderr, timed_out


def run_single(
    target_repo: Path,
    model: str,
    label: str | None = None,
    output_dir: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    use_headroom: bool = True,
    run_graphify: bool = True,
    graphify_full: bool = False,
    keep_injected: bool = False,
    detected_tools: list[DetectedTool] | None = None,
    diff_ref: str | None = None,
    critic_model: str | None = None,
    verifier_model: str | None = None,
) -> RunResult:
    """Execute a single security review against a target repository.

    This is the main orchestration function. It:
    1. Detects available tools
    2. Optionally runs graphify pre-processing
    3. Optionally runs syft/grype SBOM + vulnerability scan
    4. Optionally computes diff scope for incremental scanning
    5. Injects opencode config (commands, permissions, MCP servers)
    6. Executes the review headlessly
    7. Collects and parses the assessment
    8. Cleans up injected files

    Args:
        target_repo: path to the repo to review.
        model: provider/model for the primary agent.
        label: label for the assessment file (derived from model if None).
        output_dir: base output directory (default: <runner>/output).
        timeout: seconds before killing the review.
        use_headroom: wrap opencode in headroom for cache/compression.
        run_graphify: run graphify pre-processing if available.
        graphify_full: use full LLM extraction (slower, richer).
        keep_injected: don't clean up .opencode files after run.
        detected_tools: pre-detected tools (auto-detected if None).
        diff_ref: git ref for incremental scanning (None = full scan).
        critic_model: override the critic subagent model (None = use default).
        verifier_model: override the verifier subagent model (None = use default).

    Returns:
        RunResult with timing, assessment, and quality data.
    """
    repo_name = target_repo.resolve().name
    if label is None:
        label = _derive_label(model)
    if output_dir is None:
        output_dir = _RUNNER_DIR / "output"
    if detected_tools is None:
        detected_tools = detect_all()

    run_out = _ensure_output_dir(output_dir, repo_name, label)
    tool_names = [t.name for t in detected_tools]

    # Phase 1: graphify pre-processing
    # Resolve the primary model's provider endpoint so graphify uses
    # the same LLM backend as the reviewing agent.
    llm_base_url, llm_model_id, llm_api_key = _resolve_provider(model)
    graphify_ran = False
    if run_graphify:
        has_graphify = any(t.name == "graphify" for t in detected_tools)
        if has_graphify:
            graphify_ran = run_graphify_preprocess(
                target_repo,
                full_mode=graphify_full,
                llm_base_url=llm_base_url,
                llm_model=llm_model_id,
                llm_api_key=llm_api_key,
            )

    # Phase 2: SBOM generation and vulnerability scan
    sbom_path = None
    grype_path = None
    has_syft = any(t.name == "syft" for t in detected_tools)
    if has_syft:
        syft_tool = next(t for t in detected_tools if t.name == "syft")
        grype_tool = next((t for t in detected_tools if t.name == "grype"), None)
        sbom_path, grype_path = run_sbom_preprocess(
            target_repo,
            syft_binary=syft_tool.binary,
            grype_binary=grype_tool.binary if grype_tool else None,
        )

    # Phase 2b: secret scanning with trufflehog
    trufflehog_path = None
    has_trufflehog = any(t.name == "trufflehog" for t in detected_tools)
    if has_trufflehog:
        th_tool = next(t for t in detected_tools if t.name == "trufflehog")
        trufflehog_path = run_trufflehog_preprocess(
            target_repo, trufflehog_binary=th_tool.binary,
        )

    # Phase 3: diff scope for incremental scanning
    if diff_ref is not None:
        changed_files = compute_diff_scope(target_repo, diff_ref)
        callers = compute_callers(target_repo, changed_files)
        write_diff_scope_file(target_repo, changed_files, callers, diff_ref)

    # Phase 4: build MCP config for detected tools
    mcp_config = build_mcp_config(detected_tools, target_repo)

    # Phase 5: inject and execute
    if keep_injected:
        # No cleanup — inject manually
        manifest = InjectionManifest()
        from sast_review.inject import (
            inject_agent_overrides,
            inject_commands,
            inject_graphify_plugin,
            inject_mcp_servers,
            inject_omlx_unload_script,
            inject_permissions,
        )
        inject_commands(
            _RUNNER_DIR, target_repo, manifest,
            file_cap=compute_file_cap(model),
        )
        inject_permissions(_RUNNER_DIR, target_repo, manifest)
        inject_mcp_servers(target_repo, mcp_config, manifest)
        inject_agent_overrides(target_repo, critic_model, verifier_model)
        if model.startswith("omlx/"):
            inject_omlx_unload_script(
                target_repo, model, llm_base_url, llm_api_key,
            )
        if any(t.name == "graphify" for t in detected_tools):
            inject_graphify_plugin(_RUNNER_DIR, target_repo, manifest)

        wall, exit_code, stdout, stderr, timed_out = execute_review(
            target_repo, model, label, timeout, use_headroom,
        )
    else:
        with injection_context(
            _RUNNER_DIR, target_repo, mcp_config, detected_tools,
            critic_model=critic_model,
            verifier_model=verifier_model,
            primary_model=model,
            primary_base_url=llm_base_url,
            primary_api_key=llm_api_key,
        ):
            wall, exit_code, stdout, stderr, timed_out = execute_review(
                target_repo, model, label, timeout, use_headroom,
            )

    # Phase 6: collect results
    # Save raw event log
    events_path = run_out / "events.json"
    events_path.write_text(stdout)

    # Save stderr (logs)
    logs_path = run_out / "stderr.log"
    logs_path.write_text(stderr)

    # Copy SBOM and grype artifacts
    if sbom_path and sbom_path.exists():
        shutil.copy2(sbom_path, run_out / sbom_path.name)
        logger.info("SBOM collected: %s", run_out / sbom_path.name)
    if grype_path and grype_path.exists():
        shutil.copy2(grype_path, run_out / grype_path.name)
        grype_summary = grype_path.parent / "grype-summary.json"
        if grype_summary.exists():
            shutil.copy2(grype_summary, run_out / grype_summary.name)
        logger.info("Grype results collected: %s", run_out / grype_path.name)
    if trufflehog_path and trufflehog_path.exists():
        shutil.copy2(trufflehog_path, run_out / trufflehog_path.name)
        logger.info("TruffleHog results collected: %s", run_out / trufflehog_path.name)

    # Find and copy the assessment file
    assessment_glob = list(
        (target_repo / ".security-output").glob(f"SEC_ASSESSMENT_{label}*")
    )
    assessment: AssessmentResult | None = None
    if assessment_glob:
        src_assessment = assessment_glob[0]
        dst_assessment = run_out / src_assessment.name
        shutil.copy2(src_assessment, dst_assessment)
        assessment = parse_assessment(dst_assessment)
        logger.info("Assessment collected: %s", dst_assessment)
    else:
        logger.warning("No assessment file found for label '%s'", label)
        # Try to parse any assessment file
        security_out = target_repo / ".security-output"
        if security_out.exists():
            all_assessments = list(security_out.glob("SEC_ASSESSMENT_*"))
            if all_assessments:
                src_assessment = all_assessments[0]
                dst_assessment = run_out / src_assessment.name
                shutil.copy2(src_assessment, dst_assessment)
                assessment = parse_assessment(dst_assessment)
                logger.info("Assessment collected (fuzzy match): %s", dst_assessment)

    # Save run metadata
    result = RunResult(
        repo_name=repo_name,
        model=model,
        label=label,
        wall_seconds=wall,
        exit_code=exit_code,
        timed_out=timed_out,
        assessment=assessment,
        events_path=events_path,
        tools_detected=tool_names,
        graphify_ran=graphify_ran,
    )

    metrics = {
        "repo": repo_name,
        "model": model,
        "label": label,
        "wall_seconds": wall,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "tools_detected": tool_names,
        "graphify_ran": graphify_ran,
        "sbom_generated": sbom_path is not None,
        "grype_ran": grype_path is not None,
        "trufflehog_ran": trufflehog_path is not None,
        "diff_ref": diff_ref,
        "assessment_exists": assessment.exists if assessment else False,
        "assessment_lines": assessment.lines if assessment else 0,
        "total_findings": assessment.total_findings if assessment else 0,
        "findings_by_severity": assessment.findings_by_severity if assessment else {},
        "sections_found": assessment.sections_found if assessment else [],
        "sections_missing": assessment.sections_missing if assessment else [],
        "critic_completed": assessment.critic_completed if assessment else False,
        "verifier_completed": assessment.verifier_completed if assessment else False,
        "is_complete": assessment.is_complete if assessment else False,
    }
    (run_out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")

    return result


def run_benchmark(
    target_repo: Path,
    models: list[str],
    output_dir: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    use_headroom: bool = True,
    run_graphify: bool = True,
    graphify_full: bool = False,
    critic_model: str | None = None,
    verifier_model: str | None = None,
) -> list[RunResult]:
    """Run the security review for each model sequentially.

    Args:
        target_repo: path to the repo to review.
        models: list of provider/model identifiers to benchmark.
        output_dir: base output directory.
        timeout: per-run timeout in seconds.
        use_headroom: use headroom wrapping.
        run_graphify: run graphify pre-processing (once, before first run).
        graphify_full: use full graphify mode.
        critic_model: override the critic subagent model.
        verifier_model: override the verifier subagent model.

    Returns:
        List of RunResult, one per model.
    """
    detected_tools = detect_all()

    # Run graphify once before any reviews, using the first model's provider
    if run_graphify:
        has_graphify = any(t.name == "graphify" for t in detected_tools)
        if has_graphify:
            base_url, model_id, api_key = _resolve_provider(models[0])
            run_graphify_preprocess(
                target_repo,
                full_mode=graphify_full,
                llm_base_url=base_url,
                llm_model=model_id,
                llm_api_key=api_key,
            )

    results: list[RunResult] = []
    for i, model in enumerate(models, 1):
        label = _derive_label(model)
        logger.info(
            "=== Benchmark run %d/%d: %s ===",
            i, len(models), model,
        )

        # Clean .security-output between runs
        security_out = target_repo / ".security-output"
        if security_out.exists():
            shutil.rmtree(security_out)
            logger.debug("Cleaned .security-output/ for fresh run")

        result = run_single(
            target_repo=target_repo,
            model=model,
            label=label,
            output_dir=output_dir,
            timeout=timeout,
            use_headroom=use_headroom,
            run_graphify=False,  # already ran above
            detected_tools=detected_tools,
            critic_model=critic_model,
            verifier_model=verifier_model,
        )
        _append_runner_summary(result)
        results.append(result)
        print(result.summary_line())

    # Generate benchmark report
    if output_dir is None:
        output_dir = _RUNNER_DIR / "output"
    _write_benchmark_report(results, output_dir / target_repo.name)
    return results


def _write_benchmark_report(results: list[RunResult], out_dir: Path) -> None:
    """Write a markdown comparison report for benchmark results."""
    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Security Review Benchmark — {timestamp}",
        "",
        "## Summary",
        "",
        "| Model | Time | Exit | Findings | Critic | Verifier | Complete |",
        "|-------|------|------|----------|--------|----------|----------|",
    ]
    for r in results:
        minutes = f"{r.wall_seconds / 60:.1f}m"
        findings = str(r.assessment.total_findings) if r.assessment and r.assessment.exists else "n/a"
        critic = "yes" if r.assessment and r.assessment.critic_completed else "no"
        verifier = "yes" if r.assessment and r.assessment.verifier_completed else "no"
        complete = "yes" if r.assessment and r.assessment.is_complete else "no"
        exit_str = "TIMEOUT" if r.timed_out else str(r.exit_code)
        lines.append(
            f"| {r.label} | {minutes} | {exit_str} | {findings} "
            f"| {critic} | {verifier} | {complete} |"
        )
    lines.extend(["", "## Tools detected", ""])
    if results:
        for name in results[0].tools_detected:
            lines.append(f"- {name}")
        lines.append(f"- graphify pre-processing: {'yes' if results[0].graphify_ran else 'no'}")

    lines.extend(["", "## Per-model details", ""])
    for r in results:
        lines.append(f"### {r.label}")
        lines.append(f"- Model: `{r.model}`")
        lines.append(f"- Wall time: {r.wall_seconds / 60:.1f} minutes")
        lines.append(f"- Exit code: {r.exit_code}")
        if r.assessment and r.assessment.exists:
            a = r.assessment
            lines.append(f"- Assessment: {a.lines} lines")
            lines.append(f"- Findings: {a.total_findings}")
            if a.findings_by_severity:
                sev_str = ", ".join(
                    f"{k}: {v}" for k, v in sorted(a.findings_by_severity.items())
                )
                lines.append(f"- Severity breakdown: {sev_str}")
            lines.append(f"- Sections present: {len(a.sections_found)}/{len(a.sections_found) + len(a.sections_missing)}")
            if a.sections_missing:
                lines.append(f"- Sections missing: {', '.join(a.sections_missing)}")
            lines.append(f"- Critic: {'completed' if a.critic_completed else 'missing'}")
            lines.append(f"- Verifier: {'completed' if a.verifier_completed else 'missing'}")
        elif r.error:
            lines.append(f"- Error: {r.error}")
        lines.append("")

    report_path = out_dir / f"benchmark_{datetime.now(tz=UTC).strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n")
    logger.info("Benchmark report: %s", report_path)
    print(f"\nBenchmark report written to: {report_path}")


def _format_summary(result: RunResult) -> str:
    """Build the runner summary block used for both stdout and the assessment."""
    lines = [
        "Security Review Complete",
        f"  Repo:       {result.repo_name}",
        f"  Model:      {result.model}",
        f"  Time:       {result.wall_seconds / 60:.1f} minutes",
        f"  Exit code:  {result.exit_code}",
    ]
    if result.timed_out:
        lines.append("  Status:     TIMED OUT")

    if result.assessment and result.assessment.exists:
        a = result.assessment
        lines.append(f"  Assessment: {a.path}")
        lines.append(f"  Lines:      {a.lines}")
        sev = a.findings_by_severity
        sev_str = (
            ", ".join(f"{k}: {v}" for k, v in sorted(sev.items())) or "none"
        )
        lines.append(f"  Findings:   {a.total_findings} ({sev_str})")
        total_sections = len(a.sections_found) + len(a.sections_missing)
        lines.append(f"  Sections:   {len(a.sections_found)}/{total_sections}")
        if a.sections_missing:
            lines.append(f"  Missing:    {', '.join(a.sections_missing)}")
        lines.append(
            f"  Critic:     {'completed' if a.critic_completed else 'not found'}"
        )
        lines.append(
            f"  Verifier:   {'completed' if a.verifier_completed else 'not found'}"
        )
    else:
        lines.append("  Assessment: NOT PRODUCED")

    lines.append(f"  Tools:      {', '.join(result.tools_detected) or 'none'}")
    lines.append(f"  Graphify:   {'ran' if result.graphify_ran else 'skipped'}")
    return "\n".join(lines)


def _append_runner_summary(result: RunResult) -> None:
    """Append the runner summary block to the assessment markdown file."""
    if not result.assessment or not result.assessment.exists:
        return
    summary = _format_summary(result)
    block = f"\n\n## Runner summary\n\n```\n{summary}\n```\n"
    with result.assessment.path.open("a") as fh:
        fh.write(block)
    logger.info("Runner summary appended to %s", result.assessment.path)


def _print_result(result: RunResult) -> None:
    """Pretty-print a single run result to stdout."""
    print(f"\n{_format_summary(result)}")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sast-review",
        description="Universal security review runner via headless OpenCode",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="Target repository to review (absolute or relative path)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="galileo/coder-ornith:LATEST",
        help="Model for the primary agent (provider/model format)",
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Label for $1 in the command (derived from model if omitted)",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run all configured models sequentially",
    )
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help="Comma-separated model list for benchmark mode",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Per-run timeout in seconds (default: 0 = no timeout)",
    )
    parser.add_argument(
        "--no-headroom",
        action="store_true",
        help="Bypass headroom wrapper",
    )
    parser.add_argument(
        "--no-graphify",
        action="store_true",
        help="Skip graphify pre-processing",
    )
    parser.add_argument(
        "--graphify-full",
        action="store_true",
        help="Run full graphify with LLM (slower, richer context)",
    )
    parser.add_argument(
        "--diff",
        type=str,
        nargs="?",
        const="HEAD~1",
        default=None,
        metavar="REF",
        help="Incremental scan: only review files changed since REF (default: HEAD~1)",
    )
    parser.add_argument(
        "--critic",
        type=str,
        default=None,
        metavar="PROVIDER/MODEL",
        help="Override critic subagent model (default: from opencode config)",
    )
    parser.add_argument(
        "--verifier",
        type=str,
        default=None,
        metavar="PROVIDER/MODEL",
        help="Override verifier subagent model (default: from opencode config)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: <runner>/output)",
    )
    parser.add_argument(
        "--keep-injected",
        action="store_true",
        help="Don't clean up injected .opencode files after run",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List detected tools and exit",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Resolve repo path
    target_repo = args.repo.resolve()
    if not target_repo.is_dir():
        logger.error("Target repo does not exist: %s", target_repo)
        sys.exit(1)

    # Tool detection (always runs)
    detected = detect_all()
    print(f"Tools detected: {', '.join(t.name for t in detected) or 'none'}")
    hints = missing_tool_hints(detected)
    if hints:
        print("Not installed (optional):")
        for hint in hints:
            print(hint)

    if args.list_tools:
        sys.exit(0)

    # Validate opencode is available
    if not shutil.which("opencode"):
        logger.error("opencode CLI not found in PATH")
        sys.exit(1)

    print(f"\nTarget: {target_repo}")
    print(f"Runner: {_RUNNER_DIR}")
    if args.diff is not None:
        print(f"Diff:   incremental scan (ref={args.diff})")
    if args.critic:
        print(f"Critic: {args.critic} (override)")
    if args.verifier:
        print(f"Verifier: {args.verifier} (override)")

    if args.benchmark:
        # Benchmark mode
        models = (
            args.models.split(",") if args.models
            else DEFAULT_MODELS
        )
        print(f"Benchmark mode: {len(models)} model(s)")
        run_benchmark(
            target_repo=target_repo,
            models=models,
            output_dir=args.output_dir,
            timeout=args.timeout,
            use_headroom=not args.no_headroom,
            run_graphify=not args.no_graphify,
            graphify_full=args.graphify_full,
            critic_model=args.critic,
            verifier_model=args.verifier,
        )
    else:
        # Single run mode
        result = run_single(
            target_repo=target_repo,
            model=args.model,
            label=args.label,
            output_dir=args.output_dir,
            timeout=args.timeout,
            use_headroom=not args.no_headroom,
            run_graphify=not args.no_graphify,
            graphify_full=args.graphify_full,
            keep_injected=args.keep_injected,
            detected_tools=detected,
            diff_ref=args.diff,
            critic_model=args.critic,
            verifier_model=args.verifier,
        )
        _append_runner_summary(result)
        _print_result(result)
        sys.exit(0 if result.exit_code == 0 and not result.timed_out else 1)
