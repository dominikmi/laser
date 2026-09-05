"""Auto-detection and MCP configuration for security review tools.

Detects which tools are installed on the system and generates
the appropriate MCP server configuration entries for injection
into a target repository's .opencode/opencode.json.

Supported tools:
  - graphify   : codebase knowledge graph (pre-processing step, not MCP)
  - semgrep    : deterministic SAST with 10k+ rules, 30+ languages
  - serena     : LSP-powered semantic symbol navigation, 40+ languages
  - trufflehog : secret scanning with verification (pre-processing step)
  - osv-scanner: dependency vulnerability scanning from lockfiles
  - syft       : SBOM generation (pre-processing step, not MCP)
  - grype      : vulnerability scanning against SBOMs (pre-processing step)
"""

from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ToolKind(Enum):
    """Classification of tool integration mode."""

    MCP = "mcp"            # runs as an MCP server during the opencode session
    PREPROCESSOR = "pre"   # runs before opencode as a pre-processing step


@dataclass(frozen=True)
class DetectedTool:
    """A tool that was found on the system."""

    name: str
    kind: ToolKind
    binary: Path
    version: str
    mcp_config: dict[str, Any] = field(default_factory=dict)
    install_hint: str = ""


# --- detection helpers ---------------------------------------------------

def _run_quiet(cmd: list[str], timeout: int = 10) -> str | None:
    """Run a command and return stripped stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _detect_graphify() -> DetectedTool | None:
    """Detect graphify CLI."""
    binary = shutil.which("graphify")
    if binary is None:
        return None
    version = _run_quiet(["graphify", "--version"]) or "unknown"
    return DetectedTool(
        name="graphify",
        kind=ToolKind.PREPROCESSOR,
        binary=Path(binary),
        version=version,
        install_hint='uv tool install "graphifyy[openai]"',
    )


def _detect_semgrep() -> DetectedTool | None:
    """Detect semgrep CLI with MCP support."""
    binary = shutil.which("semgrep")
    if binary is None:
        return None
    binary_path = Path(binary).resolve()
    version = _run_quiet(["semgrep", "--version"]) or "unknown"
    # Verify MCP subcommand exists
    mcp_check = _run_quiet(["semgrep", "mcp", "--version"])
    if mcp_check is None:
        logger.warning("semgrep found but 'semgrep mcp' subcommand unavailable")
        return None
    return DetectedTool(
        name="semgrep",
        kind=ToolKind.MCP,
        binary=binary_path,
        version=version,
        mcp_config={
            "type": "local",
            "command": [str(binary_path), "mcp"],
            "enabled": True,
        },
        install_hint="brew install semgrep",
    )


def _detect_serena() -> DetectedTool | None:
    """Detect serena-agent (LSP-powered code navigation)."""
    binary = shutil.which("serena")
    if binary is None:
        return None
    version = _run_quiet(["serena", "--version"]) or "unknown"
    binary_path = Path(binary).resolve()
    # Serena MCP needs --project at runtime; placeholder is replaced during injection.
    # Use 'oaicompat-agent' context (opencode uses OpenAI-compatible API).
    # Use absolute binary path to avoid PATH resolution issues in opencode.
    return DetectedTool(
        name="serena",
        kind=ToolKind.MCP,
        binary=binary_path,
        version=version,
        mcp_config={
            "type": "local",
            "command": [
                str(binary_path), "start-mcp-server",
                "--project", "__TARGET_REPO__",
                "--context", "oaicompat-agent",
            ],
            "enabled": True,
        },
        install_hint="uv tool install -p 3.13 serena-agent",
    )


def _detect_trufflehog() -> DetectedTool | None:
    """Detect trufflehog (secret scanner)."""
    binary = shutil.which("trufflehog")
    if binary is None:
        return None
    raw = _run_quiet(["trufflehog", "--version"]) or "unknown"
    # "trufflehog 3.92.2" -> "3.92.2"
    version = raw.split()[-1] if " " in raw else raw
    return DetectedTool(
        name="trufflehog",
        kind=ToolKind.PREPROCESSOR,
        binary=Path(binary).resolve(),
        version=version,
        install_hint="brew install trufflehog",
    )


def _detect_osv_scanner() -> DetectedTool | None:
    """Detect osv-scanner with experimental MCP support."""
    binary = shutil.which("osv-scanner")
    if binary is None:
        return None
    binary_path = Path(binary).resolve()
    raw = _run_quiet(["osv-scanner", "--version"]) or "unknown"
    # osv-scanner --version outputs multiple lines; extract version from first
    version_out = raw.split("\n")[0].removeprefix("osv-scanner version: ").strip()
    return DetectedTool(
        name="osv-scanner",
        kind=ToolKind.MCP,
        binary=binary_path,
        version=version_out,
        mcp_config={
            "type": "local",
            "command": [str(binary_path), "experimental-mcp"],
            "enabled": True,
        },
        install_hint="brew install osv-scanner",
    )


def _detect_syft() -> DetectedTool | None:
    """Detect syft (SBOM generator)."""
    binary = shutil.which("syft")
    if binary is None:
        return None
    raw = _run_quiet(["syft", "--version"]) or "unknown"
    # "syft 1.51.0" -> "1.51.0"
    version = raw.split()[-1] if " " in raw else raw
    return DetectedTool(
        name="syft",
        kind=ToolKind.PREPROCESSOR,
        binary=Path(binary).resolve(),
        version=version,
        install_hint="brew install syft",
    )


def _detect_grype() -> DetectedTool | None:
    """Detect grype (vulnerability scanner for SBOMs)."""
    binary = shutil.which("grype")
    if binary is None:
        return None
    raw = _run_quiet(["grype", "--version"]) or "unknown"
    # "grype 0.117.0" -> "0.117.0"
    version = raw.split()[-1] if " " in raw else raw
    return DetectedTool(
        name="grype",
        kind=ToolKind.PREPROCESSOR,
        binary=Path(binary).resolve(),
        version=version,
        install_hint="brew install grype",
    )


# --- public API ----------------------------------------------------------

_DETECTORS: list[tuple[str, type[None]]] = []  # unused, kept for pattern


def detect_all() -> list[DetectedTool]:
    """Run all tool detectors and return found tools.

    Returns:
        List of DetectedTool instances for every tool found on the system.
    """
    detectors = [
        _detect_graphify,
        _detect_semgrep,
        _detect_serena,
        _detect_trufflehog,
        _detect_osv_scanner,
        _detect_syft,
        _detect_grype,
    ]
    found: list[DetectedTool] = []
    for detector in detectors:
        tool = detector()
        if tool is not None:
            logger.info("Detected %s %s at %s", tool.name, tool.version, tool.binary)
            found.append(tool)
        else:
            name = detector.__name__.removeprefix("_detect_")
            logger.debug("%s not found", name)
    return found


def build_mcp_config(
    tools: list[DetectedTool],
    target_repo: Path,
) -> dict[str, dict[str, Any]]:
    """Build the MCP server entries for injection into opencode.json.

    Args:
        tools: detected tools (only MCP-kind tools produce entries).
        target_repo: absolute path to the target repo, used to resolve
            placeholders like __TARGET_REPO__ in serena's command.

    Returns:
        Dict mapping server name to its MCP config block.
    """
    mcp: dict[str, dict[str, Any]] = {}
    target_str = str(target_repo.resolve())
    for tool in tools:
        if tool.kind != ToolKind.MCP or not tool.mcp_config:
            continue
        config = dict(tool.mcp_config)
        # Resolve target-repo placeholder in command args
        if "command" in config:
            config["command"] = [
                arg.replace("__TARGET_REPO__", target_str)
                for arg in config["command"]
            ]
        mcp[tool.name] = config
    return mcp


def build_knowledge_mcp_config(
    url: str,
    timeout_seconds: float = 0.25,
    database_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a remote MCP entry or a local stdio fallback.

    Args:
        url: Streamable HTTP MCP endpoint.
        timeout_seconds: Maximum TCP connection time.
        database_path: Knowledge database used by the local stdio fallback.

    Returns:
        A single read-only knowledge MCP entry, or an empty mapping when neither
        a daemon nor a fallback database is available.

    Raises:
        ValueError: If the URL is not an HTTP loopback endpoint.
    """
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("knowledge MCP URL must use HTTP on a loopback host")
    if parsed.path != "/mcp" or parsed.query or parsed.fragment:
        raise ValueError("knowledge MCP URL must use the /mcp endpoint")
    port = parsed.port or 80
    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout_seconds):
            pass
    except OSError:
        if database_path is None:
            return {}
        return {
            "laser-knowledge": {
                "type": "local",
                "command": [
                    sys.executable,
                    "-m",
                    "sast_review.knowledge_mcp",
                    "--database",
                    str(database_path.expanduser().resolve()),
                    "--transport",
                    "stdio",
                ],
                "enabled": True,
                "timeout": 5000,
            }
        }
    return {
        "laser-knowledge": {
            "type": "remote",
            "url": url,
            "enabled": True,
            "oauth": False,
            "timeout": 5000,
        }
    }


def missing_tool_hints(found: list[DetectedTool]) -> list[str]:
    """Return install hints for tools that were NOT detected.

    Useful for printing a "you could also install..." message.
    """
    all_names = {
        "graphify", "semgrep", "serena", "trufflehog",
        "osv-scanner", "syft", "grype",
    }
    found_names = {t.name for t in found}
    hints_map: dict[str, str] = {
        "graphify": 'uv tool install "graphifyy[openai]"',
        "semgrep": "brew install semgrep",
        "serena": "uv tool install -p 3.13 serena-agent",
        "trufflehog": "brew install trufflehog",
        "osv-scanner": "brew install osv-scanner",
        "syft": "brew install syft",
        "grype": "brew install grype",
    }
    return [
        f"  {name}: {hints_map[name]}"
        for name in sorted(all_names - found_names)
    ]
