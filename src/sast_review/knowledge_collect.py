"""Fail-closed collection of persistent knowledge from security assessments."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sast_review.fingerprint import (
    capture_git_state,
    normalized_span_hash,
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

_FINDING_BLOCK = re.compile(r"(?ms)^###\s+(.+?)\n(.*?)(?=^###\s|\Z)")
_FINDING_SECTION = re.compile(
    r"(?ms)^##\s+(Findings|Container findings|Dead code findings|"
    r"Test-only findings|Dependency findings|Rejected findings)\s*\n"
    r"(.*?)(?=^##\s|\Z)"
)
_RUN_ID = re.compile(r"^F-[0-9]{3}$")
_FIELD = re.compile(r"(?m)^\*\*(?P<name>[^*]+):\*\*\s*(?P<value>.+?)\s*$")
_LOCATION_SUFFIX = re.compile(
    r":(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?"
)
_LOCATION_BOUNDARIES = frozenset(" \t\r\n:[]()<>")
_HEADER_LOCATION = re.compile(
    r"^\[?(?P<path>.+?):(?P<start>[1-9][0-9]*)"
    r"(?:-(?P<end>[1-9][0-9]*))?\]?\s+[—-]\s+(?P<title>.+)$"
)
_DEPENDENCY_HEADER = re.compile(
    r"^(?P<package>[^\s@]+)@(?P<version>[^\s]+)\s+[—-]\s+(?P<title>.+)$"
)
_VERIFIER_LINE = re.compile(r"(?m)^<!-- verifier-record: (\{[^\r\n]*\}) -->$")
_VERIFIER_KEYS = (
    "finding_id",
    "result",
    "checks_performed",
    "evidence_locations",
    "detail",
)
_PATTERN_NAMESPACE = UUID("8dd93409-4e99-4c50-bc58-9cc45306ec3f")


class CollectionWarning(BaseModel):
    """Structured warning for input rejected without aborting collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str
    message: str
    finding_id: str | None = None


class FindingParseResult(BaseModel):
    """Findings parsed from an assessment and their run-local ID mapping."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)
    findings: tuple[FindingClaim, ...] = ()
    run_to_canonical: dict[str, str] = Field(default_factory=dict)
    warnings: tuple[CollectionWarning, ...] = ()


class VerificationParseResult(BaseModel):
    """Verifier records accepted after contract and evidence coverage checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    records: tuple[VerificationRecord, ...] = ()
    warnings: tuple[CollectionWarning, ...] = ()


class KnowledgeCollectionResult(BaseModel):
    """Complete evidence bundle plus all non-fatal collection warnings."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    bundle: ReviewEvidenceBundle
    warnings: tuple[CollectionWarning, ...] = ()


class PriorKnowledgeResult(BaseModel):
    """Same-repository findings refreshed against a current worktree."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    findings: tuple[FindingClaim, ...] = ()
    warnings: tuple[CollectionWarning, ...] = ()


def _warning(code: str, message: str, finding_id: str | None = None) -> CollectionWarning:
    return CollectionWarning(code=code, message=message, finding_id=finding_id)


def _finding_blocks(
    assessment: str,
) -> Iterator[tuple[re.Match[str], VerdictState]]:
    for section in _FINDING_SECTION.finditer(assessment):
        state = (
            VerdictState.REJECTED
            if section.group(1).casefold() == "rejected findings"
            else VerdictState.CANDIDATE
        )
        for block in _FINDING_BLOCK.finditer(section.group(2)):
            yield block, state


def _fields(body: str) -> dict[str, str]:
    return {match["name"].strip().casefold(): match["value"].strip() for match in _FIELD.finditer(body)}


def _enum_value(value: str, aliases: Mapping[str, str] | None = None) -> str:
    token = value.strip().split()[0].strip("[](),").casefold().replace("-", "_")
    return aliases.get(token, token) if aliases else token


def _severity(fields: Mapping[str, str]) -> Severity:
    expression = fields["severity"]
    match = re.fullmatch(
        r"Impact\s+(CRITICAL|HIGH|MODERATE|LOW)\s+x\s+Likelihood\s+"
        r"(HIGH|MEDIUM|LOW)\s+=\s+(CRITICAL|HIGH|MEDIUM|LOW)\s+"
        r"\((ACTIVE|CONDITIONAL|DEAD|TEST-ONLY),\s*.+\)",
        expression,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise ValueError("severity does not use the required derived format")
    if match.group(1).casefold() != _enum_value(fields["impact"]):
        raise ValueError("severity impact disagrees with the impact axis")
    if match.group(2).casefold() != _enum_value(fields["likelihood"]):
        raise ValueError("severity likelihood disagrees with the likelihood axis")
    impact = Impact(match.group(1).casefold())
    likelihood = Likelihood(match.group(2).casefold())
    matrix = {
        Impact.CRITICAL: {
            Likelihood.HIGH: Severity.CRITICAL,
            Likelihood.MEDIUM: Severity.HIGH,
            Likelihood.LOW: Severity.MEDIUM,
        },
        Impact.HIGH: {
            Likelihood.HIGH: Severity.HIGH,
            Likelihood.MEDIUM: Severity.HIGH,
            Likelihood.LOW: Severity.MEDIUM,
        },
        Impact.MODERATE: {
            Likelihood.HIGH: Severity.MEDIUM,
            Likelihood.MEDIUM: Severity.MEDIUM,
            Likelihood.LOW: Severity.LOW,
        },
        Impact.LOW: {
            Likelihood.HIGH: Severity.LOW,
            Likelihood.MEDIUM: Severity.LOW,
            Likelihood.LOW: Severity.LOW,
        },
    }
    derived = Severity(match.group(3).casefold())
    reachability = _enum_value(fields["reachability"])
    if match.group(4).casefold().replace("-", "_") != reachability:
        raise ValueError("severity reachability disagrees with the reachability axis")
    expected = matrix[impact][likelihood]
    if reachability == "dead" and expected in {Severity.CRITICAL, Severity.HIGH}:
        expected = Severity.MEDIUM
    elif reachability == "test_only":
        expected = Severity.LOW
    if derived is not expected:
        raise ValueError("severity disagrees with the required derivation matrix")
    return derived


def _kind_and_header(header: str) -> tuple[FindingKind, str, str | None, tuple[str, int, int] | None]:
    dependency = _DEPENDENCY_HEADER.fullmatch(header.strip("[] "))
    if dependency is not None:
        identity = f"{dependency['package']}@{dependency['version']}"
        return FindingKind.DEPENDENCY, dependency["title"].strip(), identity, None
    location = _HEADER_LOCATION.fullmatch(header.strip())
    if location is None:
        raise ValueError("finding header has no valid file or dependency location")
    path = location["path"].strip("[] ")
    start = int(location["start"])
    end = int(location["end"] or start)
    name = Path(path).name.casefold()
    kind = (
        FindingKind.CONTAINER
        if name.startswith(("dockerfile", "compose", "docker-compose"))
        else FindingKind.FIRST_PARTY
    )
    return kind, location["title"].strip(), None, (path, start, end)


def _resolve_evidence(
    repository: Path,
    path: str,
    start_line: int,
    end_line: int,
    role: EvidenceRole,
    evidence_id: str,
    *,
    required: bool,
) -> EvidenceRef:
    root = repository.resolve(strict=True)
    relative = Path(path)
    if relative.is_absolute():
        raise ValueError("evidence path must be repository-relative")
    candidate = (root / relative).resolve(strict=True)
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise ValueError("evidence path must resolve to a repository text file")
    text = candidate.read_text(encoding="utf-8")
    if "\x00" in text:
        raise ValueError("evidence path must resolve to a repository text file")
    canonical_path = candidate.relative_to(root).as_posix()
    return EvidenceRef(
        evidence_id=evidence_id,
        role=role,
        path=canonical_path,
        start_line=start_line,
        end_line=end_line,
        content_hash=normalized_span_hash(text, start_line, end_line),
        file_hash=normalized_text_hash(text),
        required=required,
    )


def _parse_locations(value: str) -> Iterator[tuple[str, int, int]]:
    for suffix in _LOCATION_SUFFIX.finditer(value):
        path_end = suffix.start()
        path_start = path_end
        while path_start > 0 and value[path_start - 1] not in _LOCATION_BOUNDARIES:
            path_start -= 1
        path = value[path_start:path_end]
        filename = path.rsplit("/", 1)[-1]
        _, separator, extension = filename.rpartition(".")
        is_file = filename.startswith("Dockerfile") or (
            bool(separator and extension)
            and all(character.isalnum() or character in "_+-" for character in extension)
        )
        if not path or ":" in path or not is_file:
            continue
        start = int(suffix["start"])
        yield path, start, int(suffix["end"] or start)


def _raw_locations(
    kind: FindingKind,
    header_location: tuple[str, int, int] | None,
    body: str,
) -> list[tuple[str, int, int, EvidenceRole]]:
    locations: list[tuple[str, int, int, EvidenceRole]] = []
    if header_location is not None:
        header_role = EvidenceRole.CONFIGURATION if kind is FindingKind.CONTAINER else EvidenceRole.TRACE
        locations.append((*header_location, header_role))
    labels = (
        (("source",), EvidenceRole.SOURCE),
        (("transform",), EvidenceRole.TRACE),
        (("sink",), EvidenceRole.SINK),
        (("vulnerable path",), EvidenceRole.TRACE),
    )
    for names, role in labels:
        label = "|".join(re.escape(name) for name in names)
        for line_match in re.finditer(rf"(?mi)^\s*(?:\*\*)?(?:{label}):(?:\*\*)?\s*(.+)$", body):
            for path, start, end in _parse_locations(line_match.group(1)):
                locations.append((path, start, end, role))
    unique: dict[tuple[str, int, int, EvidenceRole], None] = {}
    for raw_location in locations:
        unique.setdefault(raw_location, None)
    return list(unique)


def _semantic_identity(
    kind: FindingKind,
    title: str,
    fields: Mapping[str, str],
    dependency: str | None,
) -> dict[str, str]:
    identity = {
        "kind": kind.value,
        "title": title,
        "cwe": fields["cwe"].split()[0],
        "rule_id": fields.get("rule", fields.get("cve", "")),
    }
    if dependency is not None:
        package, _, version = dependency.partition("@")
        identity.update({"package": package, "version": version})
    return identity


def parse_assessment_findings(
    assessment: str,
    repository: Path,
    repository_id: UUID,
    latest_revisions: Mapping[str, int] | None = None,
) -> FindingParseResult:
    """Parse validated findings and recompute all evidence hashes locally.

    Args:
        assessment: Complete assessment Markdown.
        repository: Root containing every accepted evidence file.
        repository_id: Stable repository UUID used as the ID namespace.
        latest_revisions: Latest persisted revision keyed by canonical finding ID.

    Returns:
        Accepted claims, run-local mappings, and structured warnings.
    """
    revisions = latest_revisions or {}
    findings: list[FindingClaim] = []
    mapping: dict[str, str] = {}
    warnings: list[CollectionWarning] = []
    seen_run_ids: set[str] = set()
    for match, initial_state in _finding_blocks(assessment):
        body = match.group(2)
        values = _fields(body)
        run_id = values.get("finding id")
        if run_id is None:
            try:
                _kind_and_header(match.group(1))
            except ValueError:
                continue
            warnings.append(
                _warning("malformed_finding", "finding omits required Finding ID")
            )
            continue
        try:
            if _RUN_ID.fullmatch(run_id) is None or run_id in seen_run_ids:
                raise ValueError("finding ID is malformed or duplicated")
            seen_run_ids.add(run_id)
            required = {"cwe", "reachability", "impact", "likelihood", "confidence", "severity"}
            if not required.issubset(values):
                raise ValueError("finding omits one or more required classification fields")
            kind, title, dependency, header_location = _kind_and_header(match.group(1))
            if kind is FindingKind.FIRST_PARTY and (
                "risk" in values or "```dockerfile" in body.casefold()
            ):
                kind = FindingKind.CONTAINER
            if kind is FindingKind.DEPENDENCY and "cve" not in values:
                raise ValueError("dependency finding omits required CVE field")
            cwe = values["cwe"].split()[0].strip("[]")
            severity = _severity(values)
            reachability = Reachability(
                _enum_value(values["reachability"], {"test": "test_only", "test_only": "test_only"})
            )
            impact = Impact(_enum_value(values["impact"]))
            likelihood = Likelihood(_enum_value(values["likelihood"]))
            confidence = Confidence(_enum_value(values["confidence"]))
            raw_locations = _raw_locations(kind, header_location, body)
            if not raw_locations:
                raise ValueError("finding has no repository evidence location")
            has_non_trace_evidence = any(role is not EvidenceRole.TRACE for *_, role in raw_locations)
            evidence = tuple(
                _resolve_evidence(
                    repository,
                    path,
                    start,
                    end,
                    role,
                    f"evidence-{index:03d}",
                    required=(
                        role is not EvidenceRole.TRACE
                        or kind is FindingKind.DEPENDENCY
                        or not has_non_trace_evidence and index == 1
                    ),
                )
                for index, (path, start, end, role) in enumerate(raw_locations, start=1)
            )
            identity = _semantic_identity(kind, title, values, dependency)
            canonical_id = stable_finding_id(repository_id, identity)
            revision = revisions.get(canonical_id, 0) + 1
            rule_id = values.get("rule") or values.get("cve")
            if rule_id is not None and rule_id.casefold().startswith("no cve"):
                rule_id = None
            summary = values.get("risk") or values.get("exploit") or values.get("fix") or title
            claim = FindingClaim(
                finding_id=canonical_id,
                revision=revision,
                affected_symbol=dependency,
                kind=kind,
                title=title,
                summary=summary,
                rule_id=rule_id,
                cwe=cwe,
                reachability=reachability,
                impact=impact,
                likelihood=likelihood,
                confidence=confidence,
                severity=severity,
                evidence=evidence,
                state=initial_state,
            )
            findings.append(claim)
            mapping[run_id] = canonical_id
        except (KeyError, OSError, UnicodeError, ValueError) as exc:
            warnings.append(_warning("malformed_finding", str(exc), run_id))
    return FindingParseResult(
        findings=tuple(findings), run_to_canonical=mapping, warnings=tuple(warnings)
    )


def _required_checks(kind: FindingKind) -> frozenset[VerificationCheck]:
    common = {VerificationCheck.PATH, VerificationCheck.LINE}
    if kind is FindingKind.DEPENDENCY:
        common.add(VerificationCheck.DEPENDENCY_VERSION)
    elif kind is FindingKind.FIRST_PARTY:
        common.update({VerificationCheck.SNIPPET, VerificationCheck.TRACE})
    else:
        common.add(VerificationCheck.SNIPPET)
    return frozenset(common)


def _location_tuples(locations: Sequence[str]) -> set[tuple[str, int, int]]:
    parsed: set[tuple[str, int, int]] = set()
    for value in locations:
        for path, start, end in _parse_locations(value):
            parsed.add((Path(path).as_posix(), start, end))
    return parsed


def parse_verifier_records(
    assessment: str,
    findings: Sequence[FindingClaim],
    run_to_canonical: Mapping[str, str],
    verifier: str,
    repository: Path,
) -> VerificationParseResult:
    """Parse literal verifier comments and gate them on checks and evidence.

    Args:
        assessment: Complete assessment containing literal verifier comments.
        findings: Claims created from the same assessment.
        run_to_canonical: Mapping from run-local IDs to canonical IDs.
        verifier: Non-empty verifier model or tool identifier.
        repository: Current repository used to re-observe reported evidence.

    Returns:
        Accepted immutable records and warnings for every rejected comment.
    """
    by_id = {finding.finding_id: finding for finding in findings}
    covered_in_order = [
        run_id
        for run_id, canonical in run_to_canonical.items()
        if canonical in by_id
        and by_id[canonical].severity in {Severity.CRITICAL, Severity.HIGH}
    ][:15]
    covered_run_ids = set(covered_in_order)
    records: list[VerificationRecord] = []
    warnings: list[CollectionWarning] = []
    seen: set[str] = set()
    candidate_lines = [
        line for line in assessment.splitlines() if "verifier-record" in line
    ]
    for line in candidate_lines:
        run_id: str | None = None
        try:
            match = _VERIFIER_LINE.fullmatch(line)
            if match is None or "-->" in match.group(1):
                raise ValueError("verifier record does not satisfy the literal comment contract")
            payload = json.loads(match.group(1))
            if not isinstance(payload, dict) or tuple(payload) != _VERIFIER_KEYS:
                raise ValueError("verifier record keys or key order violate the literal contract")
            run_id_value = payload["finding_id"]
            if not isinstance(run_id_value, str):
                raise TypeError("verifier finding_id must be a string")
            run_id = run_id_value
            if run_id in seen or run_id not in covered_run_ids:
                raise ValueError("verifier finding_id is duplicate or outside required coverage")
            seen.add(run_id)
            result = VerificationResult(payload["result"])
            raw_checks = payload["checks_performed"]
            raw_locations = payload["evidence_locations"]
            detail = payload["detail"]
            if (
                not isinstance(raw_checks, list)
                or not raw_checks
                or any(not isinstance(item, str) for item in raw_checks)
                or not isinstance(raw_locations, list)
                or not raw_locations
                or any(not isinstance(item, str) or not item for item in raw_locations)
                or not isinstance(detail, str)
                or not detail.strip()
            ):
                raise ValueError("verifier record fields have invalid types or are empty")
            checks = frozenset(VerificationCheck(item) for item in raw_checks)
            canonical = run_to_canonical[run_id]
            finding = by_id[canonical]
            if not _required_checks(finding.kind).issubset(checks):
                raise ValueError("verifier did not perform all checks required for this finding kind")
            reported_locations = _location_tuples(raw_locations)
            required_locations = {
                (item.path, item.start_line, item.end_line)
                for item in finding.evidence
                if item.required
            }
            if not required_locations.issubset(reported_locations):
                raise ValueError("verifier locations do not cover all required evidence")
            observed_hashes = frozenset(
                _resolve_evidence(
                    repository,
                    item.path,
                    item.start_line,
                    item.end_line,
                    item.role,
                    item.evidence_id,
                    required=True,
                ).content_hash
                for item in finding.evidence
                if item.required
            )
            records.append(
                VerificationRecord(
                    verification_id=uuid4(),
                    finding_id=run_id,
                    canonical_finding_id=canonical,
                    verifier=verifier,
                    checks_performed=checks,
                    evidence_locations=tuple(raw_locations),
                    result=result,
                    observed_evidence_hashes=observed_hashes,
                    detail=detail,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            warnings.append(_warning("malformed_verifier_record", str(exc), run_id))
    accepted = {record.finding_id for record in records}
    for missing in sorted(covered_run_ids - accepted):
        warnings.append(_warning("missing_verifier_coverage", "required finding has no valid verifier record", missing))
    return VerificationParseResult(records=tuple(records), warnings=tuple(warnings))


def _patterns(
    findings: Sequence[FindingClaim], records: Sequence[VerificationRecord]
) -> tuple[SecurityPattern, ...]:
    successful = {
        record.canonical_finding_id
        for record in records
        if record.result in {VerificationResult.VERIFIED, VerificationResult.CORRECTED}
    }
    patterns: list[SecurityPattern] = []
    seen_pattern_ids: set[str] = set()
    for finding in findings:
        if finding.finding_id not in successful or finding.severity not in {
            Severity.CRITICAL,
            Severity.HIGH,
        }:
            continue
        safe_rule = finding.rule_id
        if safe_rule is not None and (
            "/" in safe_rule
            or "\\" in safe_rule
            or any(character.isspace() for character in safe_rule)
        ):
            safe_rule = None
        identity = {
            "kind": finding.kind.value,
            "cwe": finding.cwe or "",
            "rule": safe_rule or "",
        }
        pattern_id = stable_finding_id(_PATTERN_NAMESPACE, identity).replace(
            "finding:", "pattern:"
        )
        if pattern_id in seen_pattern_ids:
            continue
        seen_pattern_ids.add(pattern_id)
        category = finding.cwe or safe_rule or "security weakness"
        patterns.append(
            SecurityPattern(
                pattern_id=pattern_id,
                name=f"Verified {finding.kind.value.replace('_', ' ')} {category}",
                description=f"Generalized verified {finding.kind.value.replace('_', ' ')} weakness associated with {category}.",
                kind=finding.kind,
                rule_id=safe_rule,
                cwe=finding.cwe,
                tags=(finding.severity.value, finding.reachability.value),
            )
        )
    return tuple(patterns)


def collect_review_evidence(
    assessment: str,
    repository: Path,
    namespace: UUID,
    repository_id: UUID,
    *,
    latest_revisions: Mapping[str, int] | None = None,
    tool_name: str | None = None,
    tool_version: str | None = None,
    primary_model_id: str | None = None,
    critic_model_id: str | None = None,
    verifier_model_id: str | None = None,
    prompt_text: str | None = None,
    detected_tool_versions: Mapping[str, str] | None = None,
) -> KnowledgeCollectionResult:
    """Build a review bundle from assessment text without trusting its hashes.

    Args:
        assessment: Complete final assessment Markdown.
        repository: Current repository root.
        namespace: Knowledge namespace UUID.
        repository_id: Stable UUID for this repository.
        latest_revisions: Latest revision keyed by canonical finding ID.
        tool_name: Producing tool name.
        tool_version: Producing tool version.
        primary_model_id: Primary model identifier.
        critic_model_id: Critic model identifier.
        verifier_model_id: Verifier model identifier and record provenance.
        prompt_text: Prompt content to hash locally, if available.
        detected_tool_versions: Locally detected tool metadata.

    Returns:
        Validated bundle and structured non-fatal warnings.
    """
    parsed = parse_assessment_findings(assessment, repository, repository_id, latest_revisions)
    verifier_name = verifier_model_id or "unknown-verifier"
    verified = parse_verifier_records(
        assessment,
        parsed.findings,
        parsed.run_to_canonical,
        verifier_name,
        repository,
    )
    warnings = [*parsed.warnings, *verified.warnings]
    git = None
    try:
        git = capture_git_state(repository)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        warnings.append(_warning("git_unavailable", f"Git state unavailable: {type(exc).__name__}"))
    metadata = ReviewMetadata(
        bundle_id=uuid4(),
        namespace=namespace,
        repository_id=repository_id,
        tool_name=tool_name,
        tool_version=tool_version,
        primary_model_id=primary_model_id,
        critic_model_id=critic_model_id,
        verifier_model_id=verifier_model_id,
        prompt_digest=normalized_text_hash(prompt_text) if prompt_text is not None else None,
        detected_tool_versions=dict(detected_tool_versions or {}),
        git=git,
    )
    bundle = ReviewEvidenceBundle(
        metadata=metadata,
        findings=parsed.findings,
        verifications=verified.records,
        patterns=_patterns(parsed.findings, verified.records),
    )
    return KnowledgeCollectionResult(bundle=bundle, warnings=tuple(warnings))


def refresh_prior_findings(
    findings: Sequence[FindingClaim], repository: Path
) -> PriorKnowledgeResult:
    """Refresh historical evidence and classify freshness fail-closed.

    Args:
        findings: Latest same-repository claims.
        repository: Current repository root.

    Returns:
        Claims with active/stale classifications and refresh warnings.
    """
    refreshed: list[FindingClaim] = []
    warnings: list[CollectionWarning] = []
    for finding in findings:
        try:
            evidence = tuple(refresh_evidence(item, repository) for item in finding.evidence)
            current_hashes = frozenset(item.content_hash for item in evidence if item.required)
            state = finding.state
            if state in {VerdictState.VERIFIED_ACTIVE, VerdictState.STALE}:
                state = (
                    VerdictState.VERIFIED_ACTIVE
                    if current_hashes == finding.required_evidence_hashes
                    else VerdictState.STALE
                )
            refreshed.append(finding.model_copy(update={"evidence": evidence, "state": state}))
        except (OSError, UnicodeError, ValueError) as exc:
            refreshed.append(finding.model_copy(update={"state": VerdictState.STALE}))
            warnings.append(_warning("evidence_refresh_failed", str(exc), finding.finding_id))
    return PriorKnowledgeResult(findings=tuple(refreshed), warnings=tuple(warnings))


def load_latest_same_repo_findings(
    store: KnowledgeStore,
    repository_id: UUID,
    repository: Path,
    limit: int = 50,
) -> PriorKnowledgeResult:
    """Load and refresh only latest findings belonging to one repository.

    Args:
        store: Authoritative knowledge store.
        repository_id: Repository UUID used to isolate verdicts.
        repository: Current repository root.
        limit: Maximum latest findings to load.

    Returns:
        Same-repository findings with deterministic freshness classification.
    """
    historical = store.same_repo_context(repository_id, {}, limit=limit)
    return refresh_prior_findings(historical, repository)


def render_prior_knowledge(
    findings: Sequence[FindingClaim], *, max_items: int = 20, max_chars: int = 8_000
) -> str:
    """Render bounded same-repository active/stale prior knowledge Markdown.

    Args:
        findings: Already isolated and refreshed same-repository findings.
        max_items: Maximum total list items.
        max_chars: Maximum output length.

    Returns:
        PRIOR_KNOWLEDGE.md content without cross-repository patterns.

    Raises:
        ValueError: If either bound is not positive.
    """
    if max_items < 1 or max_chars < 1:
        raise ValueError("render bounds must be positive")
    eligible = [
        finding
        for finding in findings
        if finding.state in {VerdictState.VERIFIED_ACTIVE, VerdictState.STALE}
    ][:max_items]
    sections: list[str] = ["# Prior Knowledge", "", "## Same-repo ACTIVE VERIFIED"]
    active = [item for item in eligible if item.state is VerdictState.VERIFIED_ACTIVE]
    stale = [item for item in eligible if item.state is VerdictState.STALE]
    for group in (active, stale):
        if group is stale:
            sections.extend(["", "## STALE"])
        if not group:
            sections.append("None")
        else:
            sections.extend(
                (
                    f"- {item.finding_id} | {item.severity.value.upper()} | "
                    f"{item.title} | files: "
                    f"{', '.join(dict.fromkeys(evidence.path for evidence in item.evidence))}"
                )
                for item in group
            )
    sections.extend(
        [
            "",
            "## Cross-repo patterns — INVESTIGATIVE LEADS NOT VERDICTS",
            "Available only through the explicit `search_security_patterns` MCP tool.",
        ]
    )
    rendered = "\n".join(sections) + "\n"
    if len(rendered) <= max_chars:
        return rendered
    marker = "\n[Truncated]\n"
    truncated = rendered[: max(0, max_chars - len(marker))].rstrip() + marker
    return truncated[:max_chars]
