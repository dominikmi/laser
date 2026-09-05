"""Orchestration boundary for persistent review knowledge."""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import UUID

from sast_review.knowledge_collect import (
    CollectionWarning,
    collect_review_evidence,
    load_latest_same_repo_findings,
    render_prior_knowledge,
)
from sast_review.knowledge_models import ReviewEvidenceBundle, VerdictState
from sast_review.knowledge_store import IngestResult, KnowledgeStore
from sast_review.okf_export import OKFExporter

logger = logging.getLogger(__name__)
DEFAULT_KNOWLEDGE_DATABASE = (
    Path.home() / ".local" / "share" / "sast-review" / "knowledge.sqlite3"
)
DEFAULT_KNOWLEDGE_MCP_URL = "http://127.0.0.1:8765/mcp"
KNOWLEDGE_OPERATION_ERRORS = (OSError, RuntimeError, ValueError, sqlite3.Error)


@dataclass(frozen=True, slots=True)
class KnowledgePreparation:
    """Pre-review knowledge context and store handle."""

    store: KnowledgeStore
    prior_markdown: str
    active_count: int
    stale_count: int
    warnings: tuple[CollectionWarning, ...]


@dataclass(frozen=True, slots=True)
class KnowledgeArtifacts:
    """Post-review bundle, export, and optional ingestion outcome."""

    bundle: ReviewEvidenceBundle
    bundle_path: Path
    okf_path: Path
    ingest_result: IngestResult | None
    warnings: tuple[CollectionWarning, ...]


def _tool_version() -> str:
    try:
        return version("sast-review")
    except PackageNotFoundError:
        return "unknown"


def open_knowledge_store(database_path: Path) -> KnowledgeStore:
    """Open the authoritative store after creating its private parent directory.

    Args:
        database_path: SQLite database path.

    Returns:
        Initialized knowledge store.
    """
    resolved = database_path.expanduser()
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if resolved.parent == DEFAULT_KNOWLEDGE_DATABASE.parent:
        resolved.parent.chmod(0o700)
    return KnowledgeStore(resolved)


def prepare_knowledge(
    repository: Path,
    repository_id: UUID,
    database_path: Path,
) -> KnowledgePreparation:
    """Refresh same-repository knowledge and render bounded review context.

    Args:
        repository: Current target repository.
        repository_id: Stable user-supplied repository UUID.
        database_path: Authoritative SQLite database.

    Returns:
        Prepared store and same-repository context.
    """
    store = open_knowledge_store(database_path)
    prior = load_latest_same_repo_findings(store, repository_id, repository)
    active_count = sum(
        finding.state is VerdictState.VERIFIED_ACTIVE for finding in prior.findings
    )
    stale_count = sum(finding.state is VerdictState.STALE for finding in prior.findings)
    return KnowledgePreparation(
        store=store,
        prior_markdown=render_prior_knowledge(prior.findings),
        active_count=active_count,
        stale_count=stale_count,
        warnings=prior.warnings,
    )


def collect_knowledge_artifacts(
    assessment_path: Path,
    repository: Path,
    run_output: Path,
    repository_id: UUID,
    store: KnowledgeStore,
    *,
    primary_model_id: str,
    critic_model_id: str | None,
    verifier_model_id: str | None,
    prompt_text: str,
    detected_tool_versions: dict[str, str],
    ingest: bool,
) -> KnowledgeArtifacts:
    """Collect, export, and optionally ingest one completed assessment.

    Args:
        assessment_path: Final assessment Markdown.
        repository: Reviewed repository root.
        run_output: Timestamped persistent run directory.
        repository_id: Stable user-supplied repository UUID.
        store: Open authoritative store.
        primary_model_id: Primary review model.
        critic_model_id: Critic model, when explicitly known.
        verifier_model_id: Verifier model, when explicitly known.
        prompt_text: Exact review contract text for provenance hashing.
        detected_tool_versions: Locally detected tool versions.
        ingest: Whether to commit this bundle to shared state.

    Returns:
        Paths, validated bundle, warnings, and optional ingestion result.
    """
    assessment = assessment_path.read_text(encoding="utf-8")
    result = collect_review_evidence(
        assessment,
        repository,
        repository_id,
        repository_id,
        latest_revisions=store.latest_revisions(repository_id),
        tool_name="sast-review",
        tool_version=_tool_version(),
        primary_model_id=primary_model_id,
        critic_model_id=critic_model_id,
        verifier_model_id=verifier_model_id,
        prompt_text=prompt_text,
        detected_tool_versions=detected_tool_versions,
    )
    bundle_path = run_output / "review-evidence.json"
    bundle_path.write_text(
        json.dumps(result.bundle.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    okf_path = OKFExporter().export(result.bundle, run_output / "okf")
    ingest_result = store.ingest_bundle(result.bundle) if ingest else None
    for warning in result.warnings:
        logger.warning("Knowledge collection [%s]: %s", warning.code, warning.message)
    return KnowledgeArtifacts(
        bundle=result.bundle,
        bundle_path=bundle_path,
        okf_path=okf_path,
        ingest_result=ingest_result,
        warnings=result.warnings,
    )
