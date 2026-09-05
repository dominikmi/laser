"""Transactional SQLite store for persistent security-review knowledge."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from sast_review.knowledge_models import (
    FindingClaim,
    ReviewEvidenceBundle,
    SecurityPattern,
    Severity,
    VerdictState,
    VerificationResult,
)

_SCHEMA_VERSION = 3
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500
_PERMANENT_TERMINAL_STATES = frozenset(
    {VerdictState.SUPERSEDED, VerdictState.WITHDRAWN}
)


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Summary of a committed bundle ingestion."""

    bundle_id: UUID
    finding_states: Mapping[str, VerdictState]


class KnowledgeStore:
    """SQLite-backed authoritative store with per-operation connections."""

    def __init__(self, database_path: Path) -> None:
        """Open or create a knowledge database and apply migrations.

        Args:
            database_path: SQLite database file. Its parent must exist.

        Raises:
            ValueError: If the path does not identify a usable database file.
        """
        path = database_path.expanduser()
        if not path.parent.exists() or not path.parent.is_dir():
            raise ValueError("database parent directory must exist")
        if path.exists() and path.is_dir():
            raise ValueError("database path must not be a directory")
        self._path = path.resolve()
        self._migrate()
        self._path.chmod(0o600)

    @property
    def database_path(self) -> Path:
        """Return the absolute database path."""
        return self._path

    def _secure_database_files(self) -> None:
        for path in (
            self._path,
            self._path.with_name(f"{self._path.name}-wal"),
            self._path.with_name(f"{self._path.name}-shm"),
        ):
            try:
                path.chmod(0o600)
            except FileNotFoundError:
                pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        self._secure_database_files()
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._secure_database_files()

    @contextmanager
    def _reading(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()
            self._secure_database_files()

    def _migrate(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise RuntimeError("database schema is newer than this application")
            if version == 0:
                connection.executescript(
                    """
                    CREATE TABLE bundles (
                        bundle_id TEXT PRIMARY KEY,
                        repository_id TEXT NOT NULL,
                        namespace TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE finding_versions (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                        repository_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        required_hashes TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE findings_latest (
                        repository_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                        state TEXT NOT NULL,
                        required_hashes TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (repository_id, finding_id)
                    );
                    CREATE TABLE verification_records (
                        verification_id TEXT PRIMARY KEY,
                        bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                        repository_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        result TEXT NOT NULL,
                        observed_hashes TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                        repository_id TEXT NOT NULL,
                        finding_id TEXT,
                        event_type TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    );
                    CREATE TABLE pattern_records (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                        source_repository_id TEXT NOT NULL,
                        pattern_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        searchable_text TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        UNIQUE (bundle_id, pattern_id)
                    );
                    CREATE INDEX findings_repo_state
                        ON findings_latest(repository_id, state);
                    CREATE INDEX patterns_source
                        ON pattern_records(source_repository_id);
                    """
                )
                version = 1
            if version < 2:
                try:
                    connection.executescript(
                        """
                        CREATE VIRTUAL TABLE pattern_fts USING fts5(
                            searchable_text,
                            source_repository_id UNINDEXED,
                            pattern_sequence UNINDEXED,
                            tokenize = 'unicode61'
                        );
                        INSERT INTO pattern_fts(
                            rowid, searchable_text, source_repository_id,
                            pattern_sequence
                        )
                        SELECT sequence, searchable_text, source_repository_id, sequence
                        FROM pattern_records;
                        """
                    )
                except sqlite3.OperationalError as exc:
                    raise RuntimeError("SQLite FTS5 support is required") from exc
                version = 2
            if version < 3:
                connection.execute(
                    "CREATE INDEX finding_versions_latest "
                    "ON finding_versions(repository_id, finding_id, sequence DESC)"
                )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _limit(limit: int) -> int:
        if isinstance(limit, bool) or limit < 1 or limit > _MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")
        return limit

    @staticmethod
    def _fts_match_query(query: str) -> str:
        if len(query) > 512:
            raise ValueError("query is too complex")
        clauses: list[str] = []
        token_count = 0
        for match in re.finditer(r'"([^"]*)"|([^"\s]+)', query.casefold()):
            quoted, unquoted = match.groups()
            tokens = re.findall(r"[^\W_]+", quoted or unquoted, flags=re.UNICODE)
            token_count += len(tokens)
            if quoted is not None and tokens:
                clauses.append(f'"{" ".join(tokens)}"')
            else:
                clauses.extend(f'"{token}"' for token in tokens)
        if not clauses:
            raise ValueError("query must contain searchable text")
        if token_count > 32:
            raise ValueError("query is too complex")
        return " AND ".join(clauses)

    @staticmethod
    def _promotion_state(
        finding: FindingClaim,
        successful_observations: Collection[str],
        was_removed: bool,
        previous_state: VerdictState | None,
        previous_hashes: frozenset[str],
    ) -> VerdictState:
        if previous_state in _PERMANENT_TERMINAL_STATES:
            return previous_state
        if (
            previous_state is VerdictState.REJECTED
            and previous_hashes == finding.required_evidence_hashes
        ):
            return VerdictState.REJECTED
        if finding.state in {
            VerdictState.REJECTED,
            *_PERMANENT_TERMINAL_STATES,
        }:
            return finding.state
        if was_removed:
            return VerdictState.REJECTED
        exact_coverage = finding.required_evidence_hashes == frozenset(
            successful_observations
        )
        if finding.severity in {Severity.CRITICAL, Severity.HIGH} and exact_coverage:
            return VerdictState.VERIFIED_ACTIVE
        return VerdictState.CANDIDATE

    def ingest_bundle(self, bundle: ReviewEvidenceBundle) -> IngestResult:
        """Transactionally append a bundle and update materialized findings.

        Only critical/high claims whose verified/corrected hash coverage exactly
        equals the required hash set are promoted. Removed claims are rejected;
        exact rejected fingerprints remain rejected while changed evidence reopens them.

        Args:
            bundle: Fully validated evidence bundle.

        Returns:
            The states materialized by this ingestion.

        Raises:
            TypeError: If ``bundle`` is not a validated bundle model.
            sqlite3.IntegrityError: If immutable record IDs already exist.
        """
        if not isinstance(bundle, ReviewEvidenceBundle):
            raise TypeError("bundle must be a ReviewEvidenceBundle")
        metadata = bundle.metadata
        bundle_id = str(metadata.bundle_id)
        repository_id = str(metadata.repository_id)
        successful: dict[str, set[str]] = {}
        removed: set[str] = set()
        for record in bundle.verifications:
            canonical_id = record.canonical_finding_id
            if record.result in {
                VerificationResult.VERIFIED,
                VerificationResult.CORRECTED,
            }:
                successful.setdefault(canonical_id, set()).update(
                    record.observed_evidence_hashes
                )
            elif record.result is VerificationResult.REMOVED:
                removed.add(canonical_id)

        states: dict[str, VerdictState] = {}
        now = datetime.now(tz=UTC).isoformat()
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO bundles VALUES (?, ?, ?, ?, ?)",
                (
                    bundle_id,
                    repository_id,
                    str(metadata.namespace),
                    metadata.created_at.isoformat(),
                    bundle.model_dump_json(),
                ),
            )
            connection.execute(
                "INSERT INTO events (bundle_id, repository_id, finding_id, "
                "event_type, occurred_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
                (bundle_id, repository_id, None, "bundle_ingested", now, "{}"),
            )
            for finding in bundle.findings:
                previous = connection.execute(
                    "SELECT state, required_hashes FROM findings_latest "
                    "WHERE repository_id = ? AND finding_id = ?",
                    (repository_id, finding.finding_id),
                ).fetchone()
                previous_state = VerdictState(previous["state"]) if previous else None
                previous_hashes = (
                    frozenset(json.loads(previous["required_hashes"]))
                    if previous
                    else frozenset()
                )
                state = self._promotion_state(
                    finding,
                    successful.get(finding.finding_id, set()),
                    finding.finding_id in removed,
                    previous_state,
                    previous_hashes,
                )
                states[finding.finding_id] = state
                materialized = finding.model_copy(update={"state": state})
                payload = materialized.model_dump_json()
                hashes = json.dumps(sorted(finding.required_evidence_hashes))
                connection.execute(
                    "INSERT INTO finding_versions "
                    "(bundle_id, repository_id, finding_id, state, required_hashes, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (bundle_id, repository_id, finding.finding_id, state.value, hashes, payload),
                )
                connection.execute(
                    "INSERT INTO findings_latest "
                    "(repository_id, finding_id, bundle_id, state, required_hashes, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(repository_id, finding_id) DO UPDATE SET "
                    "bundle_id=excluded.bundle_id, state=excluded.state, "
                    "required_hashes=excluded.required_hashes, payload=excluded.payload",
                    (repository_id, finding.finding_id, bundle_id, state.value, hashes, payload),
                )
                connection.execute(
                    "INSERT INTO events (bundle_id, repository_id, finding_id, "
                    "event_type, occurred_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        bundle_id,
                        repository_id,
                        finding.finding_id,
                        "finding_materialized",
                        now,
                        json.dumps(
                            {
                                "previous_state": previous_state.value
                                if previous_state
                                else None,
                                "state": state.value,
                            },
                            separators=(",", ":"),
                        ),
                    ),
                )
            for record in bundle.verifications:
                connection.execute(
                    "INSERT INTO verification_records "
                    "(verification_id, bundle_id, repository_id, finding_id, result, "
                    "observed_hashes, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(record.verification_id),
                        bundle_id,
                        repository_id,
                        record.canonical_finding_id,
                        record.result.value,
                        json.dumps(sorted(record.observed_evidence_hashes)),
                        record.model_dump_json(),
                    ),
                )
            for pattern in bundle.patterns:
                searchable = " ".join(
                    filter(
                        None,
                        (
                            pattern.name,
                            pattern.description,
                            pattern.rule_id or "",
                            pattern.cwe or "",
                            " ".join(pattern.tags),
                        ),
                    )
                ).casefold()
                cursor = connection.execute(
                    "INSERT INTO pattern_records "
                    "(bundle_id, source_repository_id, pattern_id, name, "
                    "searchable_text, payload) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        bundle_id,
                        repository_id,
                        pattern.pattern_id,
                        pattern.name,
                        searchable,
                        pattern.model_dump_json(),
                    ),
                )
                sequence = cursor.lastrowid
                if sequence is None:
                    raise RuntimeError("SQLite did not return a pattern sequence")
                connection.execute(
                    "INSERT INTO pattern_fts "
                    "(rowid, searchable_text, source_repository_id, pattern_sequence) "
                    "VALUES (?, ?, ?, ?)",
                    (sequence, searchable, repository_id, sequence),
                )
        return IngestResult(metadata.bundle_id, states)

    def same_repo_context(
        self,
        repository_id: UUID,
        current_evidence_hashes: Mapping[str, Collection[str]],
        limit: int = _DEFAULT_LIMIT,
    ) -> list[FindingClaim]:
        """Return latest same-repository findings with freshness classification.

        A verified finding is returned as stale unless its current hash set
        exactly matches every required evidence hash stored with the claim.

        Args:
            repository_id: Repository whose verdict context may be reused.
            current_evidence_hashes: Current hashes keyed by finding ID.
            limit: Result bound from 1 through 500.

        Returns:
            Latest finding claims ordered newest first.
        """
        bounded = self._limit(limit)
        with self._reading() as connection:
            rows = connection.execute(
                "SELECT finding_id, state, required_hashes, payload "
                "FROM findings_latest AS latest WHERE repository_id = ? "
                "ORDER BY (SELECT MAX(version.sequence) FROM finding_versions AS version "
                "WHERE version.repository_id = latest.repository_id "
                "AND version.finding_id = latest.finding_id) DESC LIMIT ?",
                (str(repository_id), bounded),
            ).fetchall()
        findings: list[FindingClaim] = []
        for row in rows:
            finding = FindingClaim.model_validate_json(row["payload"])
            state = VerdictState(row["state"])
            if state is VerdictState.VERIFIED_ACTIVE:
                required = frozenset(json.loads(row["required_hashes"]))
                current = frozenset(current_evidence_hashes.get(row["finding_id"], ()))
                if current != required:
                    state = VerdictState.STALE
            findings.append(finding.model_copy(update={"state": state}))
        return findings

    def search_patterns(
        self,
        query: str,
        current_repository_id: UUID,
        limit: int = _DEFAULT_LIMIT,
    ) -> list[SecurityPattern]:
        """Search generalized patterns originating only from other repositories.

        Verdict and finding tables are never consulted or returned.

        Args:
            query: Non-empty case-insensitive search text.
            current_repository_id: Repository to exclude from results.
            limit: Result bound from 1 through 500.

        Returns:
            Distinct generalized security patterns.
        """
        match_query = self._fts_match_query(query)
        bounded = self._limit(limit)
        repository_id = str(current_repository_id)
        with self._reading() as connection:
            rows = connection.execute(
                "SELECT current.payload FROM pattern_fts "
                "JOIN pattern_records AS current "
                "ON current.sequence = pattern_fts.rowid "
                "WHERE pattern_fts MATCH ? "
                "AND current.source_repository_id <> ? "
                "AND current.sequence = (SELECT MAX(candidate.sequence) "
                "FROM pattern_records AS candidate "
                "WHERE candidate.pattern_id = current.pattern_id "
                "AND candidate.source_repository_id <> ?) "
                "ORDER BY bm25(pattern_fts), current.sequence DESC LIMIT ?",
                (match_query, repository_id, repository_id, bounded),
            ).fetchall()
        return [SecurityPattern.model_validate_json(row["payload"]) for row in rows]

    def latest_revisions(self, repository_id: UUID) -> dict[str, int]:
        """Return latest finding revisions for one repository.

        Args:
            repository_id: Stable repository UUID.

        Returns:
            Canonical finding IDs mapped to their latest positive revision.
        """
        with self._reading() as connection:
            rows = connection.execute(
                "SELECT finding_id, payload FROM findings_latest WHERE repository_id = ?",
                (str(repository_id),),
            ).fetchall()
        return {
            row["finding_id"]: FindingClaim.model_validate_json(row["payload"]).revision
            for row in rows
        }

    def bundle_count(self) -> int:
        """Return the number of immutable bundles in the database."""
        with self._reading() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM bundles").fetchone()[0])
