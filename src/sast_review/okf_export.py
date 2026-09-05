"""Deterministic, one-way Open Knowledge Format v0.2 export.

The exporter deliberately has no import operation: OKF is a publication view and
must never be read back into LASER's authoritative review state.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from sast_review.knowledge_models import (
    FindingClaim,
    ReviewEvidenceBundle,
    SecurityPattern,
    VerdictState,
    VerificationRecord,
)

OKF_VERSION = "0.2"
_RESERVED_MARKDOWN = frozenset({"index.md", "log.md"})
_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---(?:\n|\Z)", re.DOTALL)
_MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_DATE_HEADING = re.compile(r"^## \d{4}-\d{2}-\d{2}$")
_SAFE_COMPONENT = re.compile(r"[^a-z0-9._-]+")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_REPOSITORY_PATH = re.compile(
    r"(?<![\w])(?:[A-Za-z]:[\\/]|\.{0,2}[\\/])?"
    r"(?:[A-Za-z0-9_.-]+[\\/])+[A-Za-z0-9_.-]+"
)


class OKFConformanceError(ValueError):
    """Raised when an exported directory violates required OKF constraints."""


class OKFExporter:
    """Publish immutable review models as a deterministic OKF v0.2 directory."""

    def export(
        self, bundle: ReviewEvidenceBundle, output_directory: Path | str
    ) -> Path:
        """Export ``bundle`` without reading or changing authoritative state.

        Args:
            bundle: Validated authoritative review evidence bundle.
            output_directory: Caller-owned destination. Unrelated files are retained.

        Returns:
            The resolved export root.

        Raises:
            ValueError: If identifiers collide after safe filename normalization or a
                destination component would escape the export root.
        """
        root = Path(output_directory).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        root = root.resolve()

        finding_names = self._unique_names(
            [(finding.finding_id, finding.finding_id) for finding in bundle.findings],
            "finding",
        )
        pattern_names = self._unique_names(
            [(pattern.pattern_id, pattern.pattern_id) for pattern in bundle.patterns],
            "pattern",
        )
        evidence_items = [
            (f"{finding.finding_id}\0{evidence.evidence_id}", evidence.evidence_id)
            for finding in bundle.findings
            for evidence in finding.evidence
        ]
        evidence_names = self._unique_names(evidence_items, "evidence")
        attestation_names = self._unique_names(
            [
                (str(record.verification_id), str(record.verification_id))
                for record in bundle.verifications
            ],
            "attestation",
        )

        directories = (
            "findings",
            "patterns",
            "references/evidence",
            "references/attestations",
        )
        for relative in directories:
            self._safe_path(root, relative).mkdir(parents=True, exist_ok=True)

        evidence_links: dict[tuple[str, str], str] = {}
        for finding in sorted(bundle.findings, key=lambda item: item.finding_id):
            for evidence in sorted(finding.evidence, key=lambda item: item.evidence_id):
                key = f"{finding.finding_id}\0{evidence.evidence_id}"
                filename = f"{evidence_names[key]}.json"
                relative = f"references/evidence/{filename}"
                evidence_key = (finding.finding_id, evidence.evidence_id)
                evidence_links[evidence_key] = f"../{relative}"
                self._write_json(root, relative, evidence.model_dump(mode="json"))

        attestation_links: dict[str, str] = {}
        ordered_records = sorted(
            bundle.verifications, key=lambda item: str(item.verification_id)
        )
        for record in ordered_records:
            identifier = str(record.verification_id)
            relative = f"references/attestations/{attestation_names[identifier]}.json"
            attestation_links[identifier] = f"../{relative}"
            self._write_json(root, relative, record.model_dump(mode="json"))

        for finding in sorted(bundle.findings, key=lambda item: item.finding_id):
            records = sorted(
                (
                    record
                    for record in bundle.verifications
                    if record.canonical_finding_id == finding.finding_id
                ),
                key=lambda item: (item.verified_at, str(item.verification_id)),
            )
            frontmatter = self._finding_frontmatter(
                bundle, finding, records, evidence_links, attestation_links
            )
            body = self._finding_body(
                finding, records, evidence_links, attestation_links
            )
            relative = f"findings/{finding_names[finding.finding_id]}.md"
            self._write_concept(root, relative, frontmatter, body)

        repository_paths = tuple(
            evidence.path
            for finding in bundle.findings
            for evidence in finding.evidence
        )
        for pattern in sorted(bundle.patterns, key=lambda item: item.pattern_id):
            frontmatter, body = self._pattern_concept(bundle, pattern, repository_paths)
            relative = f"patterns/{pattern_names[pattern.pattern_id]}.md"
            self._write_concept(root, relative, frontmatter, body)

        index = self._index(bundle, finding_names, pattern_names)
        self._atomic_write(root, "index.md", index)
        self._atomic_write(root, "log.md", self._log(bundle))
        validate_okf_bundle(root)
        return root

    @staticmethod
    def _unique_names(items: Sequence[tuple[str, str]], kind: str) -> dict[str, str]:
        result: dict[str, str] = {}
        owners: dict[str, str] = {}
        for key, identifier in sorted(items):
            base = _safe_filename(identifier)
            name = base
            if name in owners and owners[name] != key:
                digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
                name = f"{base}-{digest}"
            if name in owners and owners[name] != key:
                raise ValueError(f"duplicate {kind} export filename: {name}")
            owners[name] = key
            result[key] = name
        return result

    @staticmethod
    def _generator(bundle: ReviewEvidenceBundle) -> dict[str, str]:
        metadata = bundle.metadata
        actor = metadata.tool_name or "sast-review"
        if metadata.tool_version:
            actor = f"{actor}/{metadata.tool_version}"
        return {"by": f"agent:{actor}", "at": _iso_datetime(metadata.created_at)}

    def _finding_frontmatter(
        self,
        bundle: ReviewEvidenceBundle,
        finding: FindingClaim,
        records: Sequence[VerificationRecord],
        evidence_links: Mapping[tuple[str, str], str],
        attestation_links: Mapping[str, str],
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "type": "LASER Security Finding",
            "title": finding.title,
            "description": finding.summary,
            "generated": self._generator(bundle),
            "sources": [
                {
                    "id": evidence.evidence_id,
                    "resource": evidence_links[
                        (finding.finding_id, evidence.evidence_id)
                    ],
                    "title": f"{evidence.role.value} evidence metadata",
                }
                for evidence in sorted(
                    finding.evidence, key=lambda item: item.evidence_id
                )
            ],
            "status": _okf_status(finding.state),
            "laser_status": finding.state.value,
            "laser_repository_id": str(bundle.metadata.repository_id),
            "laser_finding_id": finding.finding_id,
            "laser_revision": finding.revision,
            "laser_hashes": {
                evidence.evidence_id: {
                    "content": evidence.content_hash,
                    "file": evidence.file_hash,
                }
                for evidence in sorted(
                    finding.evidence, key=lambda item: item.evidence_id
                )
            },
            "laser_classification": {
                "kind": finding.kind.value,
                "reachability": finding.reachability.value,
                "impact": finding.impact.value,
                "likelihood": finding.likelihood.value,
                "confidence": finding.confidence.value,
                "severity": finding.severity.value,
                "rule_id": finding.rule_id,
                "cwe": finding.cwe,
            },
        }
        if records:
            metadata["verified"] = [
                {
                    "by": f"agent:{record.verifier}",
                    "at": _iso_datetime(record.verified_at),
                    "resource": attestation_links[str(record.verification_id)],
                }
                for record in records
            ]
        return metadata

    @staticmethod
    def _finding_body(
        finding: FindingClaim,
        records: Sequence[VerificationRecord],
        evidence_links: Mapping[tuple[str, str], str],
        attestation_links: Mapping[str, str],
    ) -> str:
        lines = [
            f"# {_markdown_text(finding.title)}",
            "",
            finding.summary,
            "",
            "## Classification",
            "",
        ]
        lines.extend(
            [
                f"- Kind: `{finding.kind.value}`",
                f"- Severity: `{finding.severity.value}`",
                f"- Reachability: `{finding.reachability.value}`",
                f"- Confidence: `{finding.confidence.value}`",
            ]
        )
        lines.extend(["", "# Citations", ""])
        ordered_evidence = sorted(
            finding.evidence, key=lambda item: item.evidence_id
        )
        for index, evidence in enumerate(ordered_evidence, 1):
            link = evidence_links[(finding.finding_id, evidence.evidence_id)]
            lines.append(f"{index}. [{_markdown_text(evidence.evidence_id)}]({link})")
        if records:
            lines.extend(["", "## Attestations", ""])
            for record in records:
                link = attestation_links[str(record.verification_id)]
                lines.append(f"- [{record.result.value}]({link})")
        return "\n".join(lines).rstrip() + "\n"

    def _pattern_concept(
        self,
        bundle: ReviewEvidenceBundle,
        pattern: SecurityPattern,
        repository_paths: Sequence[str],
    ) -> tuple[dict[str, Any], str]:
        name = _remove_repository_paths(pattern.name, repository_paths)
        description = _remove_repository_paths(pattern.description, repository_paths)
        tags = [_remove_repository_paths(tag, repository_paths) for tag in pattern.tags]
        frontmatter: dict[str, Any] = {
            "type": "LASER Security Pattern",
            "title": name,
            "description": description,
            "generated": self._generator(bundle),
            "status": "stable",
            "laser_pattern_id": pattern.pattern_id,
            "laser_classification": {
                "kind": pattern.kind.value,
                "rule_id": pattern.rule_id,
                "cwe": pattern.cwe,
            },
        }
        if tags:
            frontmatter["tags"] = tags
        body = f"# {_markdown_text(name)}\n\n{description}\n"
        return frontmatter, body

    @staticmethod
    def _index(
        bundle: ReviewEvidenceBundle,
        finding_names: Mapping[str, str],
        pattern_names: Mapping[str, str],
    ) -> str:
        metadata = bundle.metadata
        lines = [
            "# LASER Review Evidence Export",
            "",
            f"Open Knowledge Format: {OKF_VERSION}",
            f"Bundle ID: `{metadata.bundle_id}`",
            f"Repository ID: `{metadata.repository_id}`",
            f"Namespace: `{metadata.namespace}`",
            f"Generated: {_iso_datetime(metadata.created_at)}",
            "",
            "## Findings",
            "",
        ]
        lines.extend(
            "* "
            f"[{_markdown_text(finding.title)}]"
            f"(findings/{finding_names[finding.finding_id]}.md) - "
            f"{_single_line(finding.summary)}"
            for finding in sorted(bundle.findings, key=lambda item: item.finding_id)
        )
        lines.extend(["", "## Patterns", ""])
        repository_paths = tuple(
            evidence.path
            for finding in bundle.findings
            for evidence in finding.evidence
        )
        for pattern in sorted(bundle.patterns, key=lambda item: item.pattern_id):
            name = _remove_repository_paths(pattern.name, repository_paths)
            description = _remove_repository_paths(
                pattern.description, repository_paths
            )
            lines.append(
                f"* [{_markdown_text(name)}]"
                f"(patterns/{pattern_names[pattern.pattern_id]}.md) - "
                f"{_single_line(description)}"
            )
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _log(bundle: ReviewEvidenceBundle) -> str:
        day = bundle.metadata.created_at.date().isoformat()
        entry = (
            f"* **Export**: Published LASER bundle "
            f"`{bundle.metadata.bundle_id}` as OKF v{OKF_VERSION}.\n"
        )
        return f"# Directory Update Log\n\n## {day}\n{entry}"

    def _write_concept(
        self, root: Path, relative: str, frontmatter: Mapping[str, Any], body: str
    ) -> None:
        yaml = YAML(typ="safe", pure=True)
        yaml.default_flow_style = False
        yaml.allow_unicode = True
        stream = io.StringIO()
        yaml.dump(dict(frontmatter), stream)
        content = f"---\n{stream.getvalue()}---\n\n{body}"
        self._atomic_write(root, relative, content)

    def _write_json(self, root: Path, relative: str, value: Mapping[str, Any]) -> None:
        content = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self._atomic_write(root, relative, content)

    @staticmethod
    def _safe_path(root: Path, relative: str) -> Path:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError(f"unsafe export path: {relative!r}")
        candidate = root.joinpath(*pure.parts)
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise ValueError(f"export path escapes destination: {relative!r}")
        return candidate

    def _atomic_write(self, root: Path, relative: str, content: str) -> None:
        destination = self._safe_path(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        parent_is_unsafe = (
            destination.parent.resolve() != destination.parent
            or not destination.parent.is_relative_to(root)
        )
        if parent_is_unsafe:
            raise ValueError(f"unsafe destination directory: {destination.parent}")
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_name = temporary.name
            os.replace(temporary_name, destination)
        finally:
            if temporary_name is not None:
                Path(temporary_name).unlink(missing_ok=True)


class OKFConformanceValidator:
    """Validate generated OKF structure without importing it as review state."""

    def validate(self, export_root: Path | str) -> None:
        """Validate concepts, reserved files, and local links.

        Args:
            export_root: Existing OKF export directory.

        Raises:
            OKFConformanceError: If one or more conformance errors are found.
        """
        root = Path(export_root).resolve()
        errors: list[str] = []
        if not root.is_dir():
            raise OKFConformanceError(f"export root is not a directory: {root}")

        index = root / "index.md"
        log = root / "log.md"
        if not index.is_file():
            errors.append("missing root index.md")
        if not log.is_file():
            errors.append("missing root log.md")

        yaml = YAML(typ="safe", pure=True)
        for markdown in sorted(root.rglob("*.md")):
            relative = markdown.relative_to(root).as_posix()
            text = markdown.read_text(encoding="utf-8")
            if markdown.name in _RESERVED_MARKDOWN:
                errors.extend(self._validate_reserved(markdown, text, relative))
            else:
                match = _FRONTMATTER.match(text)
                if match is None:
                    errors.append(f"{relative}: missing YAML frontmatter")
                else:
                    try:
                        metadata = yaml.load(match.group(1))
                    except YAMLError as error:
                        error_name = error.__class__.__name__
                        errors.append(f"{relative}: invalid YAML ({error_name})")
                    else:
                        valid_mapping = isinstance(metadata, Mapping)
                        concept_type = metadata.get("type", "") if valid_mapping else ""
                        if not str(concept_type).strip():
                            errors.append(
                                f"{relative}: frontmatter type must be non-empty"
                            )
                        errors.extend(
                            self._validate_resources(
                                root, markdown, metadata, relative
                            )
                        )
            errors.extend(self._validate_links(root, markdown, relative))

        if errors:
            detail = "OKF conformance failed:\n- " + "\n- ".join(errors)
            raise OKFConformanceError(detail)

    @staticmethod
    def _validate_reserved(
        document: Path, text: str, relative: str
    ) -> list[str]:
        errors: list[str] = []
        if _FRONTMATTER.match(text):
            errors.append(f"reserved {relative} must not contain frontmatter")
        lines = text.splitlines()
        if not lines or not lines[0].startswith("# "):
            errors.append(f"{relative} must start with a level-one heading")
        if document.name == "log.md" and not any(
            _DATE_HEADING.fullmatch(line) for line in lines
        ):
            errors.append(f"{relative} must contain an ISO 8601 date heading")
        return errors

    @staticmethod
    def _validate_resources(
        root: Path, document: Path, metadata: Any, relative: str
    ) -> list[str]:
        if not isinstance(metadata, Mapping):
            return []
        errors: list[str] = []
        sources = metadata.get("sources", [])
        if not isinstance(sources, list):
            return [f"{relative}: sources must be a list"]
        for source in sources:
            valid_source = isinstance(source, Mapping) and isinstance(
                source.get("resource"), str
            )
            if not valid_source:
                errors.append(f"{relative}: each source requires a string resource")
                continue
            error = _local_reference_error(root, document, source["resource"])
            if error:
                errors.append(f"{relative}: source {error}")
        verified = metadata.get("verified", [])
        events = verified if isinstance(verified, list) else [verified]
        for event in events:
            if isinstance(event, Mapping) and isinstance(event.get("resource"), str):
                error = _local_reference_error(root, document, event["resource"])
                if error:
                    errors.append(f"{relative}: attestation {error}")
        return errors

    @staticmethod
    def _validate_links(root: Path, document: Path, relative: str) -> list[str]:
        errors: list[str] = []
        text = document.read_text(encoding="utf-8")
        for raw_target in _MARKDOWN_LINK.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            error = _local_reference_error(root, document, target)
            if error:
                errors.append(f"{relative}: link {error}")
        return errors


def export_okf(bundle: ReviewEvidenceBundle, output_directory: Path | str) -> Path:
    """Export a review evidence bundle as a one-way OKF v0.2 publication."""
    return OKFExporter().export(bundle, output_directory)


def validate_okf_bundle(export_root: Path | str) -> None:
    """Raise :class:`OKFConformanceError` if an OKF export is nonconformant."""
    OKFConformanceValidator().validate(export_root)


def _safe_filename(identifier: str) -> str:
    normalized = unicodedata.normalize("NFKC", identifier).strip().lower()
    normalized = normalized.replace("/", "-").replace("\\", "-")
    normalized = _SAFE_COMPONENT.sub("-", normalized).strip(".-_")
    if not normalized or normalized in {"index", "log"}:
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:12]
        normalized = f"id-{digest}"
    return normalized[:120].rstrip(".-_")


def _okf_status(state: VerdictState) -> str:
    if state is VerdictState.CANDIDATE:
        return "draft"
    if state is VerdictState.VERIFIED_ACTIVE:
        return "stable"
    return "deprecated"


def _iso_datetime(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _markdown_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _single_line(value: str) -> str:
    return " ".join(value.split())


def _remove_repository_paths(value: str, repository_paths: Sequence[str]) -> str:
    sanitized = value
    posix_paths = {path for path in repository_paths if path}
    windows_paths = {
        path.replace("/", "\\") for path in repository_paths if path
    }
    variants = sorted(posix_paths | windows_paths, key=len, reverse=True)
    for path in variants:
        sanitized = sanitized.replace(path, "[repository path]")
    return _REPOSITORY_PATH.sub("[repository path]", sanitized)


def _local_reference_error(root: Path, document: Path, target: str) -> str | None:
    parsed = urlsplit(unquote(target))
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return f"must stay within export root: {target!r}"
    path_text = parsed.path
    if not path_text or path_text.startswith("#"):
        return None
    if path_text.startswith("/") or _WINDOWS_DRIVE.match(path_text):
        return f"is absolute: {target!r}"
    candidate = (document.parent / path_text).resolve(strict=False)
    if not candidate.is_relative_to(root):
        return f"escapes export root: {target!r}"
    if not candidate.exists():
        return f"does not exist: {target!r}"
    return None
