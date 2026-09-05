"""Tests for the authoritative persistent review knowledge core."""

from __future__ import annotations

import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

from pydantic import ValidationError

from sast_review.fingerprint import (
    derive_repository_id,
    normalized_text_hash,
    refresh_evidence,
    stable_finding_id,
)
from sast_review.knowledge_models import (
    Confidence,
    EvidenceRef,
    EvidenceRole,
    FindingClaim,
    FindingKind,
    Impact,
    Likelihood,
    Reachability,
    ReviewEvidenceBundle,
    ReviewMetadata,
    SecurityPattern,
    Severity,
    VerdictState,
    VerificationCheck,
    VerificationRecord,
    VerificationResult,
)
from sast_review.knowledge_store import KnowledgeStore

_NAMESPACE = UUID("12345678-1234-5678-1234-567812345678")
_REPOSITORY = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


def _evidence(content: str = "dangerous(input)") -> EvidenceRef:
    return EvidenceRef(
        evidence_id="sink",
        role=EvidenceRole.SINK,
        path="src/service.py",
        start_line=20,
        end_line=20,
        content_hash=normalized_text_hash(content),
    )


def _finding(
    finding_id: str,
    *,
    severity: Severity = Severity.HIGH,
    state: VerdictState = VerdictState.CANDIDATE,
    evidence: EvidenceRef | None = None,
    title: str = "Command injection",
) -> FindingClaim:
    return FindingClaim(
        finding_id=finding_id,
        revision=1,
        affected_symbol="Runner.execute",
        kind=FindingKind.FIRST_PARTY,
        title=title,
        summary="Untrusted input reaches a process invocation.",
        rule_id="python.command-injection",
        cwe="CWE-78",
        reachability=Reachability.ACTIVE,
        impact=Impact.HIGH,
        likelihood=Likelihood.HIGH,
        confidence=Confidence.CONFIRMED,
        severity=severity,
        evidence=(evidence or _evidence(),),
        state=state,
    )


def _verification(
    finding: FindingClaim,
    hashes: frozenset[str] | None = None,
    *,
    result: VerificationResult = VerificationResult.VERIFIED,
    run_finding_id: str = "F-001",
) -> VerificationRecord:
    return VerificationRecord(
        verification_id=uuid4(),
        finding_id=run_finding_id,
        canonical_finding_id=finding.finding_id,
        verifier="unit-verifier/1",
        checks_performed=frozenset(
            {VerificationCheck.PATH, VerificationCheck.LINE, VerificationCheck.SNIPPET}
        ),
        evidence_locations=("src/service.py:20",),
        result=result,
        observed_evidence_hashes=hashes
        if hashes is not None
        else finding.required_evidence_hashes,
        detail="Evidence was checked against the current source.",
    )


def _bundle(
    repository_id: UUID,
    findings: tuple[FindingClaim, ...],
    verifications: tuple[VerificationRecord, ...] = (),
    patterns: tuple[SecurityPattern, ...] = (),
) -> ReviewEvidenceBundle:
    return ReviewEvidenceBundle(
        metadata=ReviewMetadata(
            bundle_id=uuid4(),
            namespace=_NAMESPACE,
            repository_id=repository_id,
            created_at=datetime.now(tz=UTC),
            tool_name="test-reviewer",
            tool_version="1.0",
        ),
        findings=findings,
        verifications=verifications,
        patterns=patterns,
    )


class FingerprintTests(unittest.TestCase):
    """Verify semantic and content-addressed fingerprint behavior."""

    def test_finding_id_ignores_paths_and_lines(self) -> None:
        first = {
            "kind": "first_party",
            "rule_id": "python.command-injection",
            "symbol": "Runner.execute",
            "sink": "process invocation",
            "path": "src/old.py",
            "line": 10,
        }
        moved = {
            **first,
            "path": "services/new.py",
            "line": 900,
            "start_line": 900,
        }
        self.assertEqual(stable_finding_id(_NAMESPACE, first), stable_finding_id(_NAMESPACE, moved))

    def test_namespace_isolation_and_validation(self) -> None:
        identity = {"kind": "dependency", "rule_id": "CVE-2025-0001", "package": "example"}
        self.assertNotEqual(
            stable_finding_id(_NAMESPACE, identity),
            stable_finding_id(uuid4(), identity),
        )
        with self.assertRaises(ValueError):
            stable_finding_id("not-a-uuid", identity)
        with self.assertRaises(ValueError):
            stable_finding_id(_NAMESPACE, {"path": "only/location.py", "line": 1})

    @patch("sast_review.fingerprint._git")
    def test_repository_id_is_stable_across_clones(self, git: object) -> None:
        git.side_effect = [
            subprocess.CompletedProcess([], 0, b"https://user:secret@www.example.com/org/repo.git\n", b""),
            subprocess.CompletedProcess([], 0, b"git@example.com:org/repo.git\n", b""),
        ]
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self.assertEqual(
                derive_repository_id(Path(first)),
                derive_repository_id(Path(second)),
            )

    @patch("sast_review.fingerprint._git")
    def test_shallow_repository_without_remote_requires_override(self, git: object) -> None:
        git.side_effect = [
            subprocess.CompletedProcess([], 2, b"", b""),
            subprocess.CompletedProcess([], 0, b"true\n", b""),
        ]
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            derive_repository_id(Path(temporary))

    def test_refresh_evidence_hashes_current_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "service.py"
            source.write_text("safe()\n dangerous(value)  \n", encoding="utf-8")
            original = _evidence().model_copy(
                update={"path": "service.py", "start_line": 2, "end_line": 2}
            )
            refreshed = refresh_evidence(original, root)
            self.assertEqual(refreshed.content_hash, normalized_text_hash(" dangerous(value)"))
            self.assertEqual(refreshed.file_hash, normalized_text_hash(source.read_text()))
            with self.assertRaises(ValueError):
                refresh_evidence(original.model_copy(update={"path": "../outside.py"}), root)


class KnowledgeModelTests(unittest.TestCase):
    """Verify malformed persisted input is rejected."""

    def test_invalid_models_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            EvidenceRef.model_validate(
                {
                    **_evidence().model_dump(),
                    "content_hash": "bad",
                }
            )
        with self.assertRaises(ValidationError):
            ReviewMetadata(
                bundle_id=uuid4(),
                namespace=_NAMESPACE,
                repository_id=_REPOSITORY,
                created_at=datetime.fromisoformat("2026-01-01T00:00:00"),
                tool_name="reviewer",
                tool_version="1",
            )
        finding = _finding("finding:known")
        with self.assertRaises(ValidationError):
            _bundle(
                _REPOSITORY,
                (finding,),
                (
                    VerificationRecord(
                        verification_id=uuid4(),
                        finding_id="F-999",
                        canonical_finding_id="finding:unknown",
                        verifier="verifier",
                        checks_performed=frozenset({VerificationCheck.TRACE}),
                        evidence_locations=("src/service.py:20",),
                        result=VerificationResult.VERIFIED,
                        observed_evidence_hashes=finding.required_evidence_hashes,
                        detail="Unknown canonical finding.",
                    ),
                ),
            )

    def test_revision_metadata_and_verifier_contract(self) -> None:
        finding = _finding("finding:contract")
        self.assertEqual(finding.revision, 1)
        self.assertEqual(finding.affected_symbol, "Runner.execute")
        with self.assertRaises(ValidationError):
            FindingClaim.model_validate({**finding.model_dump(), "revision": 0})

        metadata = ReviewMetadata(
            bundle_id=uuid4(),
            namespace=_NAMESPACE,
            repository_id=_REPOSITORY,
            primary_model_id="primary/model",
            critic_model_id="critic/model",
            verifier_model_id="verifier/model",
            prompt_digest=normalized_text_hash("prompt"),
            detected_tool_versions={"semgrep": "1.2.3"},
        )
        self.assertIsNone(metadata.tool_name)
        self.assertEqual(metadata.detected_tool_versions["semgrep"], "1.2.3")

        record = _verification(finding)
        self.assertEqual(record.finding_id, "F-001")
        self.assertEqual(record.canonical_finding_id, finding.finding_id)
        with self.assertRaises(ValidationError):
            VerificationRecord.model_validate(
                {**record.model_dump(), "checks_performed": []}
            )
        with self.assertRaises(ValidationError):
            VerificationRecord.model_validate(
                {**record.model_dump(), "evidence_locations": []}
            )
        with self.assertRaises(ValidationError):
            VerificationRecord.model_validate(
                {**record.model_dump(), "finding_id": finding.finding_id}
            )


class KnowledgeStoreTests(unittest.TestCase):
    """Verify promotion, freshness, isolation, and persistence behavior."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "knowledge.sqlite3"
        self.store = KnowledgeStore(self.database)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_promotion_requires_high_severity_and_exact_success_coverage(self) -> None:
        promoted = _finding("finding:promoted")
        extra_hash = normalized_text_hash("unrequired")
        extra = _finding("finding:extra")
        low = _finding("finding:low", severity=Severity.LOW)
        bundle = _bundle(
            _REPOSITORY,
            (promoted, extra, low),
            (
                _verification(promoted),
                _verification(extra, extra.required_evidence_hashes | {extra_hash}),
                _verification(low),
            ),
        )
        result = self.store.ingest_bundle(bundle)
        self.assertEqual(result.finding_states[promoted.finding_id], VerdictState.VERIFIED_ACTIVE)
        self.assertEqual(result.finding_states[extra.finding_id], VerdictState.CANDIDATE)
        self.assertEqual(result.finding_states[low.finding_id], VerdictState.CANDIDATE)

    def test_corrected_and_removed_verifier_semantics(self) -> None:
        corrected_evidence = _evidence("corrected_sink(input)")
        corrected = _finding("finding:corrected", evidence=corrected_evidence).model_copy(
            update={"revision": 2}
        )
        stale_hashes = frozenset({_evidence().content_hash})
        stale_correction = _finding("finding:stale-correction", evidence=corrected_evidence)
        removed = _finding("finding:removed")
        result = self.store.ingest_bundle(
            _bundle(
                _REPOSITORY,
                (corrected, stale_correction, removed),
                (
                    _verification(
                        corrected,
                        result=VerificationResult.CORRECTED,
                        run_finding_id="F-001",
                    ),
                    _verification(
                        stale_correction,
                        stale_hashes,
                        result=VerificationResult.CORRECTED,
                        run_finding_id="F-002",
                    ),
                    _verification(
                        removed,
                        result=VerificationResult.REMOVED,
                        run_finding_id="F-003",
                    ),
                ),
            )
        )
        self.assertEqual(
            result.finding_states[corrected.finding_id], VerdictState.VERIFIED_ACTIVE
        )
        self.assertEqual(
            result.finding_states[stale_correction.finding_id], VerdictState.CANDIDATE
        )
        self.assertEqual(result.finding_states[removed.finding_id], VerdictState.REJECTED)

    def test_changed_evidence_invalidates_verified_context(self) -> None:
        finding = _finding("finding:freshness")
        self.store.ingest_bundle(_bundle(_REPOSITORY, (finding,), (_verification(finding),)))
        fresh = self.store.same_repo_context(
            _REPOSITORY, {finding.finding_id: finding.required_evidence_hashes}
        )
        changed = self.store.same_repo_context(
            _REPOSITORY,
            {finding.finding_id: {normalized_text_hash("changed evidence")}},
        )
        self.assertEqual(fresh[0].state, VerdictState.VERIFIED_ACTIVE)
        self.assertEqual(changed[0].state, VerdictState.STALE)

    def test_context_orders_by_latest_materialization(self) -> None:
        first = _finding("finding:first")
        second = _finding("finding:second")
        self.store.ingest_bundle(_bundle(_REPOSITORY, (first,)))
        self.store.ingest_bundle(_bundle(_REPOSITORY, (second,)))
        updated_first = first.model_copy(update={"revision": 2, "title": "Updated first"})
        self.store.ingest_bundle(_bundle(_REPOSITORY, (updated_first,)))
        context = self.store.same_repo_context(_REPOSITORY, {}, limit=1)
        self.assertEqual(context[0].finding_id, first.finding_id)
        self.assertEqual(context[0].revision, 2)

    def test_rejected_state_is_preserved(self) -> None:
        rejected = _finding("finding:rejected", state=VerdictState.REJECTED)
        self.store.ingest_bundle(_bundle(_REPOSITORY, (rejected,)))
        retry = rejected.model_copy(update={"state": VerdictState.CANDIDATE})
        result = self.store.ingest_bundle(
            _bundle(_REPOSITORY, (retry,), (_verification(retry),))
        )
        self.assertEqual(result.finding_states[retry.finding_id], VerdictState.REJECTED)
        context = self.store.same_repo_context(
            _REPOSITORY, {retry.finding_id: retry.required_evidence_hashes}
        )
        self.assertEqual(context[0].state, VerdictState.REJECTED)

        changed = retry.model_copy(
            update={"revision": 2, "evidence": (_evidence("changed sink"),)}
        )
        changed_result = self.store.ingest_bundle(
            _bundle(_REPOSITORY, (changed,), (_verification(changed),))
        )
        self.assertEqual(
            changed_result.finding_states[changed.finding_id],
            VerdictState.VERIFIED_ACTIVE,
        )

    def test_cross_repo_search_returns_patterns_never_verdicts(self) -> None:
        other_repository = uuid4()
        pattern = SecurityPattern(
            pattern_id="pattern:command-injection",
            name="Process invocation with untrusted input",
            description="Generalized command injection data flow",
            kind=FindingKind.FIRST_PARTY,
            rule_id="python.command-injection",
            cwe="CWE-78",
            tags=("process", "injection"),
        )
        decoy = SecurityPattern(
            pattern_id="pattern:separated-terms",
            name="Command boundary checks",
            description="Safe handling with unrelated injection controls",
            kind=FindingKind.CONFIGURATION,
        )
        finding = _finding("finding:private", title="Private command verdict")
        self.store.ingest_bundle(
            _bundle(other_repository, (finding,), patterns=(pattern, decoy))
        )
        results = self.store.search_patterns('"command injection"', _REPOSITORY)
        special_results = self.store.search_patterns(
            "command-injection (CWE-78)", _REPOSITORY
        )
        self.assertEqual(results, [pattern])
        self.assertEqual(special_results, [pattern])
        self.assertFalse(hasattr(results[0], "state"))
        self.assertEqual(self.store.search_patterns("command", other_repository), [])
        with closing(sqlite3.connect(self.database)) as connection:
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?",
                ("pattern_fts",),
            ).fetchone()
        self.assertIsNotNone(definition)
        self.assertIn("VIRTUAL TABLE", definition[0].upper())
        self.assertIn("fts5", definition[0].casefold())

    def test_database_persists_and_enforces_schema_settings(self) -> None:
        finding = _finding("finding:persistent")
        self.store.ingest_bundle(_bundle(_REPOSITORY, (finding,)))
        reopened = KnowledgeStore(self.database)
        self.assertEqual(reopened.bundle_count(), 1)
        self.assertEqual(reopened.latest_revisions(_REPOSITORY), {finding.finding_id: 1})
        context = reopened.same_repo_context(
            _REPOSITORY, {finding.finding_id: finding.required_evidence_hashes}
        )
        self.assertEqual(context[0].finding_id, finding.finding_id)
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_invalid_limits_and_bundle_types_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.same_repo_context(_REPOSITORY, {}, limit=0)
        with self.assertRaises(ValueError):
            self.store.search_patterns(" ", _REPOSITORY)
        with self.assertRaises(TypeError):
            self.store.ingest_bundle({})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
