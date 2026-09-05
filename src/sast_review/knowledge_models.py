"""Versioned, validated models for persistent security-review knowledge."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class FindingKind(StrEnum):
    """Kind of security finding."""

    FIRST_PARTY = "first_party"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    SECRET = "secret"
    CONFIGURATION = "configuration"


class EvidenceRole(StrEnum):
    """Role played by an evidence location in a finding."""

    SOURCE = "source"
    TRACE = "trace"
    SINK = "sink"
    MITIGATION = "mitigation"
    CONFIGURATION = "configuration"
    MANIFEST = "manifest"


class VerdictState(StrEnum):
    """Lifecycle state of a finding verdict."""

    CANDIDATE = "candidate"
    VERIFIED_ACTIVE = "verified_active"
    STALE = "stale"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class VerificationResult(StrEnum):
    """Outcome emitted by the review verifier contract."""

    VERIFIED = "verified"
    CORRECTED = "corrected"
    REMOVED = "removed"


class VerificationCheck(StrEnum):
    """Concrete check performed by a verifier."""

    PATH = "path"
    LINE = "line"
    SNIPPET = "snippet"
    TRACE = "trace"
    DEPENDENCY_VERSION = "dependency_version"


class Reachability(StrEnum):
    """Reachability classification axis."""

    ACTIVE = "active"
    CONDITIONAL = "conditional"
    DEAD = "dead"
    TEST_ONLY = "test_only"


class Impact(StrEnum):
    """Impact classification axis."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class Likelihood(StrEnum):
    """Likelihood classification axis."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    """Confidence classification axis."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"


class Severity(StrEnum):
    """Derived severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class KnowledgeModel(BaseModel):
    """Strict base class shared by persisted knowledge models."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)
    schema_version: Literal[1] = 1


class GitRepositoryState(KnowledgeModel):
    """Non-sensitive snapshot of a Git worktree state."""

    commit: NonEmptyText
    tree: NonEmptyText
    branch: NonEmptyText | None = None
    dirty_digest: Sha256


class ReviewMetadata(KnowledgeModel):
    """Identity and provenance metadata for one review bundle."""

    bundle_id: UUID
    namespace: UUID
    repository_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    tool_name: NonEmptyText | None = None
    tool_version: NonEmptyText | None = None
    primary_model_id: NonEmptyText | None = None
    critic_model_id: NonEmptyText | None = None
    verifier_model_id: NonEmptyText | None = None
    prompt_digest: Sha256 | None = None
    detected_tool_versions: dict[NonEmptyText, NonEmptyText] = Field(default_factory=dict)
    git: GitRepositoryState | None = None

    @field_validator("created_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware timestamp to UTC.

        Args:
            value: Timestamp supplied by the producer.

        Returns:
            The timestamp represented in UTC.

        Raises:
            ValueError: If the timestamp has no timezone.
        """
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(UTC)


class EvidenceRef(KnowledgeModel):
    """Content-addressed reference to repository evidence."""

    evidence_id: NonEmptyText
    role: EvidenceRole
    path: NonEmptyText
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    content_hash: Sha256
    file_hash: Sha256 | None = None
    required: bool = True

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        """Ensure the evidence line range is ordered."""
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class FindingClaim(KnowledgeModel):
    """A classified security finding and its evidence requirements."""

    finding_id: NonEmptyText
    revision: int = Field(ge=1)
    affected_symbol: NonEmptyText | None = None
    kind: FindingKind
    title: NonEmptyText
    summary: NonEmptyText
    rule_id: NonEmptyText | None = None
    cwe: Annotated[str, StringConstraints(pattern=r"^CWE-(?:[1-9][0-9]*|OTHER)$")] | None = None
    reachability: Reachability
    impact: Impact
    likelihood: Likelihood
    confidence: Confidence
    severity: Severity
    evidence: tuple[EvidenceRef, ...] = Field(min_length=1)
    state: VerdictState = VerdictState.CANDIDATE
    supersedes: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_evidence_ids(self) -> Self:
        """Reject duplicate evidence identifiers within a finding."""
        identifiers = [item.evidence_id for item in self.evidence]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence_id values must be unique within a finding")
        if not any(item.required for item in self.evidence):
            raise ValueError("at least one evidence reference must be required")
        return self

    @property
    def required_evidence_hashes(self) -> frozenset[str]:
        """Return hashes that a successful verifier must cover exactly."""
        return frozenset(item.content_hash for item in self.evidence if item.required)


class VerificationRecord(KnowledgeModel):
    """Immutable result preserving the complete verifier output contract."""

    verification_id: UUID
    finding_id: Annotated[str, StringConstraints(pattern=r"^F-[0-9]{3}$")]
    canonical_finding_id: NonEmptyText
    verifier: NonEmptyText
    checks_performed: frozenset[VerificationCheck] = Field(min_length=1)
    evidence_locations: tuple[NonEmptyText, ...] = Field(min_length=1)
    result: VerificationResult
    observed_evidence_hashes: frozenset[Sha256] = Field(min_length=1)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    detail: NonEmptyText

    @field_validator("verified_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware verification timestamp to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verified_at must be timezone-aware")
        return value.astimezone(UTC)


class SecurityPattern(KnowledgeModel):
    """Generalized, repository-independent security pattern."""

    pattern_id: NonEmptyText
    name: NonEmptyText
    description: NonEmptyText
    kind: FindingKind
    rule_id: NonEmptyText | None = None
    cwe: Annotated[str, StringConstraints(pattern=r"^CWE-(?:[1-9][0-9]*|OTHER)$")] | None = None
    tags: tuple[NonEmptyText, ...] = ()


class ReviewEvidenceBundle(KnowledgeModel):
    """Atomic transport unit for review claims, verification, and patterns."""

    metadata: ReviewMetadata
    findings: tuple[FindingClaim, ...]
    verifications: tuple[VerificationRecord, ...] = ()
    patterns: tuple[SecurityPattern, ...] = ()

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        """Ensure IDs are unique and verification references are local."""
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique within a bundle")
        known = set(finding_ids)
        if any(
            record.canonical_finding_id not in known for record in self.verifications
        ):
            raise ValueError("verification references an unknown canonical finding")
        verification_ids = [record.verification_id for record in self.verifications]
        if len(verification_ids) != len(set(verification_ids)):
            raise ValueError("verification_id values must be unique within a bundle")
        return self
