"""Tests for the deterministic, one-way OKF v0.2 exporter."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from ruamel.yaml import YAML

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
from sast_review.okf_export import (
    OKFConformanceError,
    export_okf,
    validate_okf_bundle,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_BUNDLE_ID = UUID("11111111-1111-4111-8111-111111111111")
_NAMESPACE = UUID("22222222-2222-4222-8222-222222222222")
_REPOSITORY = UUID("33333333-3333-4333-8333-333333333333")
_VERIFICATION_ID = UUID("44444444-4444-4444-8444-444444444444")
_CREATED = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
_VERIFIED = datetime(2026, 2, 4, 5, 6, 7, tzinfo=UTC)


def _bundle(
    *,
    finding_id: str = "finding:command/injection",
    state: VerdictState = VerdictState.VERIFIED_ACTIVE,
    pattern_description: str = "Validate untrusted values before process execution.",
) -> ReviewEvidenceBundle:
    evidence = EvidenceRef(
        evidence_id="sink/../primary",
        role=EvidenceRole.SINK,
        path="src/service.py",
        start_line=20,
        end_line=21,
        content_hash=_HASH_A,
        file_hash=_HASH_B,
    )
    finding = FindingClaim(
        finding_id=finding_id,
        revision=3,
        affected_symbol="Runner.execute",
        kind=FindingKind.FIRST_PARTY,
        title="Command injection",
        summary="Untrusted input reaches a process invocation.",
        rule_id="python.command-injection",
        cwe="CWE-78",
        reachability=Reachability.ACTIVE,
        impact=Impact.HIGH,
        likelihood=Likelihood.HIGH,
        confidence=Confidence.CONFIRMED,
        severity=Severity.HIGH,
        evidence=(evidence,),
        state=state,
    )
    verification = VerificationRecord(
        verification_id=_VERIFICATION_ID,
        finding_id="F-001",
        canonical_finding_id=finding_id,
        verifier="unit-verifier/1",
        checks_performed=frozenset(
            {VerificationCheck.PATH, VerificationCheck.LINE, VerificationCheck.SNIPPET}
        ),
        evidence_locations=("src/service.py:20-21",),
        result=VerificationResult.VERIFIED,
        observed_evidence_hashes=frozenset({_HASH_A}),
        verified_at=_VERIFIED,
        detail="Evidence metadata was checked against the repository.",
    )
    pattern = SecurityPattern(
        pattern_id="pattern:process/injection",
        name="Process injection",
        description=pattern_description,
        kind=FindingKind.FIRST_PARTY,
        rule_id="python.command-injection",
        cwe="CWE-78",
        tags=("injection", "process"),
    )
    return ReviewEvidenceBundle(
        metadata=ReviewMetadata(
            bundle_id=_BUNDLE_ID,
            namespace=_NAMESPACE,
            repository_id=_REPOSITORY,
            created_at=_CREATED,
            tool_name="unit-reviewer",
            tool_version="2.0",
            primary_model_id="model-a",
            prompt_digest=_HASH_B,
        ),
        findings=(finding,),
        verifications=(verification,),
        patterns=(pattern,),
    )


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    yaml_text = text.split("---\n", 2)[1]
    value = YAML(typ="safe", pure=True).load(yaml_text)
    if not isinstance(value, dict):
        raise TypeError("frontmatter was not a mapping")
    return value


class OKFExportTests(unittest.TestCase):
    """Exercise deterministic output, mappings, and disclosure boundaries."""

    def test_export_is_byte_deterministic_and_keeps_unrelated_files(self) -> None:
        bundle = _bundle()
        with (
            tempfile.TemporaryDirectory() as first_name,
            tempfile.TemporaryDirectory() as second_name,
        ):
            first = Path(first_name)
            second = Path(second_name)
            unrelated = first / "keep.me"
            unrelated.write_text("caller-owned", encoding="utf-8")

            export_okf(bundle, first)
            export_okf(bundle, second)
            second_tree = _tree(second)
            first_tree = _tree(first)
            first_tree.pop("keep.me")

            self.assertEqual(first_tree, second_tree)
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "caller-owned")
            index_text = (first / "index.md").read_text(encoding="utf-8")
            self.assertIn("Open Knowledge Format: 0.2", index_text)

    def test_finding_maps_okf_and_preserves_laser_extensions(self) -> None:
        bundle = _bundle()
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(bundle, directory)
            concept = next((root / "findings").glob("*.md"))
            metadata = _frontmatter(concept)

            self.assertEqual(
                metadata["generated"],
                {
                    "by": "agent:unit-reviewer/2.0",
                    "at": "2026-02-03T04:05:06Z",
                },
            )
            self.assertEqual(metadata["status"], "stable")
            self.assertEqual(metadata["laser_status"], "verified_active")
            self.assertEqual(metadata["laser_repository_id"], str(_REPOSITORY))
            self.assertEqual(metadata["laser_finding_id"], "finding:command/injection")
            self.assertEqual(metadata["laser_revision"], 3)
            hashes = metadata["laser_hashes"]
            self.assertIsInstance(hashes, dict)
            self.assertEqual(
                hashes["sink/../primary"]["content"], _HASH_A  # type: ignore[index]
            )
            classification = metadata["laser_classification"]
            self.assertIsInstance(classification, dict)
            self.assertEqual(classification["severity"], "high")  # type: ignore[index]
            self.assertEqual(
                classification["confidence"], "confirmed"  # type: ignore[index]
            )
            verified = metadata["verified"]
            self.assertIsInstance(verified, list)
            self.assertEqual(
                verified[0]["at"], "2026-02-04T05:06:07Z"  # type: ignore[index]
            )
            sources = metadata["sources"]
            self.assertIsInstance(sources, list)
            resource = sources[0]["resource"]  # type: ignore[index]
            self.assertIn("references/evidence", resource)

    def test_lossy_status_mapping_retains_exact_state(self) -> None:
        expected = {
            VerdictState.CANDIDATE: "draft",
            VerdictState.VERIFIED_ACTIVE: "stable",
            VerdictState.STALE: "deprecated",
            VerdictState.REJECTED: "deprecated",
            VerdictState.SUPERSEDED: "deprecated",
            VerdictState.WITHDRAWN: "deprecated",
        }
        for state, okf_status in expected.items():
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = export_okf(_bundle(state=state), directory)
                metadata = _frontmatter(next((root / "findings").glob("*.md")))
                self.assertEqual(metadata["status"], okf_status)
                self.assertEqual(metadata["laser_status"], state.value)

    def test_unsafe_identifiers_are_sanitized_and_cannot_escape(self) -> None:
        bundle = _bundle(finding_id="../../outside\\finding")
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "export"
            export_okf(bundle, root)

            finding_files = list((root / "findings").glob("*.md"))
            self.assertEqual(len(finding_files), 1)
            self.assertEqual(finding_files[0].parent, root / "findings")
            self.assertNotIn("..", finding_files[0].name)
            self.assertFalse((parent / "outside").exists())
            self.assertTrue(all(path.is_relative_to(root) for path in root.rglob("*")))

    def test_pattern_removes_repository_paths(self) -> None:
        bundle = _bundle(
            pattern_description="The code at src/service.py should validate values."
        )
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(bundle, directory)
            pattern = next((root / "patterns").glob("*.md"))
            text = pattern.read_text(encoding="utf-8")

            self.assertNotIn("src/service.py", text)
            self.assertIn("[repository path]", text)
            self.assertNotIn("laser_repository_id", text)

    def test_reference_json_is_semantically_equivalent_to_models(self) -> None:
        bundle = _bundle()
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(bundle, directory)
            evidence_file = next((root / "references" / "evidence").glob("*.json"))
            attestation_file = next(
                (root / "references" / "attestations").glob("*.json")
            )

            self.assertEqual(
                json.loads(evidence_file.read_text(encoding="utf-8")),
                bundle.findings[0].evidence[0].model_dump(mode="json"),
            )
            self.assertEqual(
                json.loads(attestation_file.read_text(encoding="utf-8")),
                bundle.verifications[0].model_dump(mode="json"),
            )

    def test_generated_bundle_is_conformant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(_bundle(), directory)
            validate_okf_bundle(root)
            concepts = [
                *(root / "findings").glob("*.md"),
                *(root / "patterns").glob("*.md"),
            ]
            for concept in concepts:
                self.assertTrue(_frontmatter(concept)["type"])


class OKFConformanceTests(unittest.TestCase):
    """Ensure malformed structures and escaping references are rejected."""

    def test_validator_rejects_missing_frontmatter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(_bundle(), directory)
            concept = next((root / "patterns").glob("*.md"))
            concept.write_text("# No metadata\n", encoding="utf-8")

            with self.assertRaisesRegex(
                OKFConformanceError, "missing YAML frontmatter"
            ):
                validate_okf_bundle(root)

    def test_validator_rejects_escaping_and_external_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(_bundle(), directory)
            concept = next((root / "patterns").glob("*.md"))
            concept.write_text(
                concept.read_text(encoding="utf-8")
                + "\n[escape](../../outside.txt)\n[web](https://example.invalid/)\n",
                encoding="utf-8",
            )

            with self.assertRaises(OKFConformanceError) as context:
                validate_okf_bundle(root)
            message = str(context.exception)
            self.assertIn("escapes export root", message)
            self.assertIn("must stay within export root", message)

    def test_validator_rejects_reserved_file_frontmatter_and_bad_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = export_okf(_bundle(), directory)
            (root / "index.md").write_text(
                "---\ntype: invalid\n---\n# Index\n", encoding="utf-8"
            )
            (root / "log.md").write_text("# Log\n\n## someday\n* changed\n")

            with self.assertRaises(OKFConformanceError) as context:
                validate_okf_bundle(root)
            message = str(context.exception)
            self.assertIn("index.md must not contain frontmatter", message)
            self.assertIn("ISO 8601 date heading", message)


if __name__ == "__main__":
    unittest.main()
