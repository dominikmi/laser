"""Tests for fail-closed assessment knowledge collection."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from uuid import UUID, uuid4

from sast_review.fingerprint import normalized_text_hash
from sast_review.knowledge_collect import (
    _parse_locations,
    collect_review_evidence,
    load_latest_same_repo_findings,
    parse_assessment_findings,
    parse_verifier_records,
    refresh_prior_findings,
    render_prior_knowledge,
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
    Severity,
    VerdictState,
    VerificationCheck,
    VerificationRecord,
    VerificationResult,
)
from sast_review.knowledge_store import KnowledgeStore

_REPOSITORY_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_NAMESPACE = UUID("12345678-1234-5678-1234-567812345678")


def _first_party(path: str = "src/service.py", title: str = "Command injection") -> str:
    return f"""## Findings
### {path}:2 — {title}
**Finding ID:** F-001
**CWE:** CWE-78
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     {path}:1 — request input
Transform:  {path}:1 — handler
Sink:       {path}:2 — process invocation

```python
run(value)
```

**Exploit:** Attacker controls a command.
**Mitigations:** None
**Fix:** Avoid a shell.
"""


def _verifier_comment(
    *,
    finding_id: str = "F-001",
    checks: list[str] | None = None,
    locations: list[str] | None = None,
    detail: str = "Checked current source.",
) -> str:
    payload = {
        "finding_id": finding_id,
        "result": "verified",
        "checks_performed": checks or ["path", "line", "snippet", "trace"],
        "evidence_locations": locations or ["src/service.py:1", "src/service.py:2"],
        "detail": detail,
    }
    return f"<!-- verifier-record: {json.dumps(payload, separators=(',', ':'))} -->"


def _claim(path: str, content: str, state: VerdictState) -> FindingClaim:
    return FindingClaim(
        finding_id="finding:prior",
        revision=1,
        kind=FindingKind.FIRST_PARTY,
        title="Historical injection",
        summary="General historical claim.",
        cwe="CWE-78",
        reachability=Reachability.ACTIVE,
        impact=Impact.HIGH,
        likelihood=Likelihood.HIGH,
        confidence=Confidence.CONFIRMED,
        severity=Severity.HIGH,
        evidence=(
            EvidenceRef(
                evidence_id="sink",
                role=EvidenceRole.SINK,
                path=path,
                start_line=1,
                end_line=1,
                content_hash=normalized_text_hash(content),
                file_hash=normalized_text_hash(content),
            ),
        ),
        state=state,
    )


class FindingParsingTests(unittest.TestCase):
    """Exercise all report finding formats and safe evidence resolution."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/service.py").write_text("value = request\nrun(value)\n", encoding="utf-8")
        (self.root / "Dockerfile").write_text("FROM python:latest\nRUN app\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_location_parser_handles_files_ranges_and_adversarial_paths(self) -> None:
        self.assertEqual(
            list(_parse_locations("src/service.py:1-2 Dockerfile.prod:3")),
            [("src/service.py", 1, 2), ("Dockerfile.prod", 3, 3)],
        )
        adversarial = "!/" * 50_000 + "not-a-file:1"
        self.assertEqual(list(_parse_locations(adversarial)), [])

    def test_parses_first_party_container_and_dependency_blocks(self) -> None:
        assessment = _first_party() + """
## Container findings
### Dockerfile:1 — Unpinned image
**Finding ID:** F-002
**CWE:** CWE-OTHER
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood HIGH = LOW (ACTIVE, no adjustment)

```dockerfile
FROM python:latest
```
**Risk:** Mutable image content.
**Fix:** Pin the digest.

## Dependency findings
### unsafe-lib@1.0 — Vulnerable parser
**Finding ID:** F-003
**CVE:** CVE-2025-12345
**CWE:** CWE-502
**Reachability:** ACTIVE — called at src/service.py:2
**Impact:** CRITICAL
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood MEDIUM = HIGH (ACTIVE, no adjustment)

**Vulnerable path:** unsafe_lib -> parse at src/service.py:2
**Fixed in:** 1.1
**Fix:** upgrade
"""
        parsed = parse_assessment_findings(assessment, self.root, _REPOSITORY_ID)
        self.assertEqual([item.kind for item in parsed.findings], [
            FindingKind.FIRST_PARTY,
            FindingKind.CONTAINER,
            FindingKind.DEPENDENCY,
        ])
        self.assertEqual(parsed.findings[2].rule_id, "CVE-2025-12345")
        self.assertEqual(parsed.findings[2].affected_symbol, "unsafe-lib@1.0")
        self.assertTrue(all(item.file_hash for finding in parsed.findings for item in finding.evidence))
        self.assertEqual(parsed.warnings, ())

    def test_traversal_missing_and_malformed_blocks_are_skipped(self) -> None:
        outside = self.root.parent / "outside_collect.py"
        outside.write_text("bad\n", encoding="utf-8")
        try:
            traversal = _first_party("../outside_collect.py", "Traversal evidence")
            missing = _first_party("src/missing.py", "Missing evidence").replace("F-001", "F-002")
            malformed = _first_party(title="Missing confidence").replace(
                "**Confidence:** CONFIRMED\n", ""
            ).replace("F-001", "F-003")
            parsed = parse_assessment_findings(
                traversal + missing + malformed, self.root, _REPOSITORY_ID
            )
            self.assertEqual(parsed.findings, ())
            self.assertEqual(len(parsed.warnings), 3)
            self.assertTrue(all(item.code == "malformed_finding" for item in parsed.warnings))
        finally:
            outside.unlink(missing_ok=True)

    def test_only_finding_sections_are_parsed_and_rejections_are_typed(self) -> None:
        rejected = _first_party(title="Rejected command injection").replace(
            "## Findings", "## Rejected findings"
        ).replace("F-001", "F-002")
        unrelated = _first_party(title="Disputed prose").replace(
            "## Findings", "## Disputed findings"
        ).replace("F-001", "F-003")
        parsed = parse_assessment_findings(
            _first_party() + rejected + unrelated,
            self.root,
            _REPOSITORY_ID,
        )
        self.assertEqual(len(parsed.findings), 2)
        self.assertEqual(parsed.findings[0].state, VerdictState.CANDIDATE)
        self.assertEqual(parsed.findings[1].state, VerdictState.REJECTED)
        self.assertNotIn("F-003", parsed.run_to_canonical)

    def test_canonical_id_has_no_path_or_line_dependence_and_revision_increments(self) -> None:
        first = parse_assessment_findings(_first_party(), self.root, _REPOSITORY_ID)
        moved = self.root / "moved"
        moved.mkdir()
        (moved / "renamed.py").write_text("value = request\nrun(value)\n", encoding="utf-8")
        moved_assessment = _first_party("moved/renamed.py").replace(":2 —", ":1-2 —", 1)
        second = parse_assessment_findings(moved_assessment, self.root, _REPOSITORY_ID)
        self.assertEqual(first.findings[0].finding_id, second.findings[0].finding_id)
        revisions = {first.findings[0].finding_id: 7}
        third = parse_assessment_findings(_first_party(), self.root, _REPOSITORY_ID, revisions)
        self.assertEqual(third.findings[0].revision, 8)


class VerifierTests(unittest.TestCase):
    """Validate literal comment parsing and verifier coverage gates."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/service.py").write_text("value = request\nrun(value)\n", encoding="utf-8")
        self.parsed = parse_assessment_findings(_first_party(), self.root, _REPOSITORY_ID)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_requires_appropriate_checks_and_all_evidence_locations(self) -> None:
        accepted = parse_verifier_records(
            _verifier_comment(),
            self.parsed.findings,
            self.parsed.run_to_canonical,
            "verifier/1",
            self.root,
        )
        self.assertEqual(len(accepted.records), 1)
        self.assertEqual(
            accepted.records[0].observed_evidence_hashes,
            self.parsed.findings[0].required_evidence_hashes,
        )
        missing_check = parse_verifier_records(
            _verifier_comment(checks=["path", "line", "snippet"]),
            self.parsed.findings,
            self.parsed.run_to_canonical,
            "verifier/1",
            self.root,
        )
        missing_location = parse_verifier_records(
            _verifier_comment(locations=["src/service.py:2"]),
            self.parsed.findings,
            self.parsed.run_to_canonical,
            "verifier/1",
            self.root,
        )
        self.assertEqual(missing_check.records, ())
        self.assertEqual(missing_location.records, ())
        self.assertTrue(any(item.code == "missing_verifier_coverage" for item in missing_check.warnings))

    def test_verifier_hashes_are_reobserved_from_current_source(self) -> None:
        (self.root / "src/service.py").write_text(
            "value = request\nrun(changed_value)\n",
            encoding="utf-8",
        )
        result = parse_verifier_records(
            _verifier_comment(),
            self.parsed.findings,
            self.parsed.run_to_canonical,
            "verifier/1",
            self.root,
        )
        self.assertEqual(len(result.records), 1)
        self.assertNotEqual(
            result.records[0].observed_evidence_hashes,
            self.parsed.findings[0].required_evidence_hashes,
        )

    def test_malformed_duplicate_and_nonliteral_records_do_not_crash(self) -> None:
        valid = _verifier_comment()
        malformed = "<!-- verifier-record: {not-json} -->"
        nonliteral = " <!-- verifier-record: {} -->"
        result = parse_verifier_records(
            f"{malformed}\n{nonliteral}\n{valid}\n{valid}",
            self.parsed.findings,
            self.parsed.run_to_canonical,
            "verifier/1",
            self.root,
        )
        self.assertEqual(len(result.records), 1)
        self.assertGreaterEqual(len(result.warnings), 2)


class BundleAndPriorKnowledgeTests(unittest.TestCase):
    """Cover bundle metadata, freshness, store loading, and bounded rendering."""

    def test_bundle_is_graceful_outside_git_and_patterns_are_generalized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/service.py").write_text("value = request\nrun(value)\n", encoding="utf-8")
            assessment = _first_party() + "\n" + _verifier_comment()
            result = collect_review_evidence(
                assessment,
                root,
                _NAMESPACE,
                _REPOSITORY_ID,
                primary_model_id="primary/1",
                verifier_model_id="verifier/1",
                prompt_text="review prompt",
                detected_tool_versions={"semgrep": "1.0"},
            )
            self.assertIsNone(result.bundle.metadata.git)
            self.assertTrue(any(item.code == "git_unavailable" for item in result.warnings))
            self.assertEqual(len(result.bundle.patterns), 1)
            serialized = result.bundle.patterns[0].model_dump_json()
            self.assertNotIn("src/service.py", serialized)
            self.assertNotIn("run(value)", serialized)

    def test_refresh_classifies_active_and_stale_fail_closed_and_renders_only_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "live.py").write_text("same\n", encoding="utf-8")
            active = _claim("live.py", "same", VerdictState.VERIFIED_ACTIVE)
            missing = _claim("gone.py", "old", VerdictState.VERIFIED_ACTIVE).model_copy(
                update={"finding_id": "finding:missing"}
            )
            candidate = _claim("live.py", "same", VerdictState.CANDIDATE).model_copy(
                update={"finding_id": "finding:candidate"}
            )
            refreshed = refresh_prior_findings((active, missing, candidate), root)
            states = {item.finding_id: item.state for item in refreshed.findings}
            self.assertEqual(states[active.finding_id], VerdictState.VERIFIED_ACTIVE)
            self.assertEqual(states[missing.finding_id], VerdictState.STALE)
            rendered = render_prior_knowledge(refreshed.findings, max_items=2, max_chars=500)
            self.assertIn("Same-repo ACTIVE VERIFIED", rendered)
            self.assertIn("## STALE", rendered)
            self.assertNotIn("finding:candidate", rendered)
            self.assertIn("Cross-repo patterns — INVESTIGATIVE LEADS NOT VERDICTS", rendered)
            self.assertIn("search_security_patterns", rendered)

    def test_load_latest_same_repo_refreshes_store_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "live.py").write_text("same\n", encoding="utf-8")
            database = root / "knowledge.sqlite3"
            store = KnowledgeStore(database)
            finding = _claim("live.py", "same", VerdictState.CANDIDATE)
            verification = VerificationRecord(
                verification_id=uuid4(),
                finding_id="F-001",
                canonical_finding_id=finding.finding_id,
                verifier="unit",
                checks_performed=frozenset({
                    VerificationCheck.PATH,
                    VerificationCheck.LINE,
                    VerificationCheck.SNIPPET,
                    VerificationCheck.TRACE,
                }),
                evidence_locations=("live.py:1",),
                result=VerificationResult.VERIFIED,
                observed_evidence_hashes=finding.required_evidence_hashes,
                detail="Checked.",
            )
            bundle = ReviewEvidenceBundle(
                metadata=ReviewMetadata(
                    bundle_id=uuid4(), namespace=_NAMESPACE, repository_id=_REPOSITORY_ID
                ),
                findings=(finding,),
                verifications=(verification,),
            )
            store.ingest_bundle(bundle)
            loaded = load_latest_same_repo_findings(store, _REPOSITORY_ID, root)
            self.assertEqual(loaded.findings[0].state, VerdictState.VERIFIED_ACTIVE)


if __name__ == "__main__":
    unittest.main()
