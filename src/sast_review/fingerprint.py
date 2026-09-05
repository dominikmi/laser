"""Content and semantic fingerprints for persistent review knowledge."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from sast_review.knowledge_models import EvidenceRef, FindingKind, GitRepositoryState

_LOCATION_KEYS = frozenset(
    {"path", "file", "filename", "line", "line_number", "start_line", "end_line"}
)
_REPOSITORY_ID_NAMESPACE = UUID("2ba58d53-3044-4e50-9b28-7fb93b80d7d4")


def _canonical_remote(remote: str) -> str:
    value = remote.strip()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme == "file" or not parsed.hostname:
            return ""
        host = parsed.hostname.casefold().removeprefix("www.")
        return f"{host}/{parsed.path.strip('/').removesuffix('.git')}"
    if ":" in value:
        host, path = value.rsplit("@", 1)[-1].split(":", 1)
        return f"{host.casefold().removeprefix('www.')}/{path.strip('/').removesuffix('.git')}"
    return ""


def derive_repository_id(repository: Path) -> UUID:
    """Derive a clone-stable repository UUID from Git identity.

    Args:
        repository: Git worktree whose identity should be derived.

    Returns:
        Deterministic repository UUID. A supplied remote distinguishes forks;
        root commits identify full repositories without a remote.

    Raises:
        ValueError: If the path is not a directory or Git has no root commit.
        subprocess.SubprocessError: If Git cannot inspect the repository.
    """
    repo = repository.resolve(strict=True)
    if not repo.is_dir():
        raise ValueError("repository must be a directory")
    remote_result = _git(repo, "remote", "get-url", "origin", check=False)
    remote = _canonical_remote(remote_result.stdout.decode("utf-8"))
    if remote:
        return uuid5(_REPOSITORY_ID_NAMESPACE, f"remote:{remote}")
    shallow = _git(repo, "rev-parse", "--is-shallow-repository").stdout.decode("ascii").strip()
    if shallow == "true":
        raise ValueError("cannot derive a clone-stable identity for a shallow repository without origin")
    roots = _git(repo, "rev-list", "--max-parents=0", "HEAD").stdout.decode("ascii").split()
    if not roots:
        raise ValueError("repository has no root commit")
    return uuid5(_REPOSITORY_ID_NAMESPACE, f"roots:{','.join(sorted(roots))}")


def normalize_text(text: str) -> str:
    """Normalize source text without discarding semantically relevant spacing.

    Args:
        text: Source text to normalize.

    Returns:
        Unicode-normalized text with canonical newlines and trailing horizontal
        whitespace removed from each line.
    """
    canonical = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip(" \t") for line in canonical.split("\n")).strip("\n")


def normalized_text_hash(text: str) -> str:
    """Return the SHA-256 digest of normalized text.

    Args:
        text: Text to hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def normalized_span_hash(text: str, start_line: int, end_line: int) -> str:
    """Hash an inclusive, one-based line span from text.

    Args:
        text: Complete file text.
        start_line: First one-based line in the span.
        end_line: Last one-based line in the span.

    Returns:
        Lowercase hexadecimal SHA-256 digest.

    Raises:
        ValueError: If the requested span is invalid or outside the text.
    """
    lines = text.splitlines()
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise ValueError("invalid text span")
    return normalized_text_hash("\n".join(lines[start_line - 1 : end_line]))


def normalized_file_hash(path: Path) -> str:
    """Hash a UTF-8 text file after normalization.

    Args:
        path: File to read.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return normalized_text_hash(path.read_text(encoding="utf-8"))


def _semantic_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _semantic_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key).lower() not in _LOCATION_KEYS
        }
    if isinstance(value, (set, frozenset)):
        normalized_items = [_semantic_value(item) for item in value]
        return sorted(
            normalized_items,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, (list, tuple)):
        return [_semantic_value(item) for item in value]
    if isinstance(value, FindingKind):
        return value.value
    if isinstance(value, str):
        return " ".join(unicodedata.normalize("NFC", value).casefold().split())
    return value


def stable_finding_id(namespace: UUID | str, semantic_identity: Mapping[str, Any]) -> str:
    """Build a namespaced ID from normalized semantic identity.

    Location keys such as paths and line numbers are intentionally discarded.
    Callers should include stable properties such as finding kind, rule/CWE,
    affected symbol, source category, and sink category.

    Args:
        namespace: User-supplied UUID namespace.
        semantic_identity: JSON-compatible semantic identity properties.

    Returns:
        A ``finding:<sha256>`` identifier.

    Raises:
        ValueError: If the namespace or identity is invalid.
        TypeError: If identity values are not JSON serializable.
    """
    namespace_uuid = namespace if isinstance(namespace, UUID) else UUID(namespace)
    normalized = _semantic_value(semantic_identity)
    if not isinstance(normalized, dict) or not normalized:
        raise ValueError("semantic_identity must contain non-location properties")
    encoded = json.dumps(
        {"namespace": str(namespace_uuid), "identity": normalized},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"finding:{hashlib.sha256(encoded).hexdigest()}"


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    }
    return subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        check=check,
        capture_output=True,
        env=environment,
        timeout=10,
    )


def capture_git_state(repository: Path) -> GitRepositoryState:
    """Capture commit, tree, branch, and a digest of dirty worktree state.

    Git configuration and command diagnostics are neither read nor returned.
    Dirty paths are consumed locally and represented only by a SHA-256 digest.

    Args:
        repository: Repository worktree path.

    Returns:
        Validated Git repository state.

    Raises:
        ValueError: If ``repository`` is not a directory.
        subprocess.SubprocessError: If Git cannot inspect the repository.
    """
    repo = repository.resolve(strict=True)
    if not repo.is_dir():
        raise ValueError("repository must be a directory")
    commit = _git(repo, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    tree = _git(repo, "rev-parse", "HEAD^{tree}").stdout.decode("ascii").strip()
    branch_output = _git(
        repo, "symbolic-ref", "--quiet", "--short", "HEAD", check=False
    ).stdout
    branch = branch_output.decode("utf-8").strip() or None
    dirty = _git(
        repo, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    ).stdout
    return GitRepositoryState(
        commit=commit,
        tree=tree,
        branch=branch,
        dirty_digest=hashlib.sha256(dirty).hexdigest(),
    )


def refresh_evidence(evidence: EvidenceRef, repository: Path) -> EvidenceRef:
    """Refresh one evidence reference from its repository file.

    Args:
        evidence: Existing evidence location and role.
        repository: Root that must contain the referenced path.

    Returns:
        A copy carrying current normalized span and file hashes.

    Raises:
        ValueError: If an absolute or escaping evidence path is supplied.
        OSError: If the evidence file cannot be read.
    """
    root = repository.resolve(strict=True)
    relative = Path(evidence.path)
    if relative.is_absolute():
        raise ValueError("evidence path must be repository-relative")
    unresolved_path = (root / relative).resolve()
    if not unresolved_path.is_relative_to(root):
        raise ValueError("evidence path must resolve to a repository file")
    file_path = unresolved_path.resolve(strict=True)
    if not file_path.is_file():
        raise ValueError("evidence path must resolve to a repository file")
    text = file_path.read_text(encoding="utf-8")
    return evidence.model_copy(
        update={
            "path": file_path.relative_to(root).as_posix(),
            "content_hash": normalized_span_hash(text, evidence.start_line, evidence.end_line),
            "file_hash": normalized_text_hash(text),
        }
    )


def refresh_evidence_from_files(
    evidence_items: Iterable[EvidenceRef], repository: Path
) -> tuple[EvidenceRef, ...]:
    """Refresh multiple evidence references from repository files.

    Args:
        evidence_items: Evidence references to refresh.
        repository: Repository root.

    Returns:
        Refreshed evidence in input order.
    """
    return tuple(refresh_evidence(item, repository) for item in evidence_items)
