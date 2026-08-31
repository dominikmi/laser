"""Assessment collection and validation.

Parses the security assessment output file, validates required sections,
extracts findings, and determines whether subagent delegation completed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Self


class Severity(Enum):
    """Finding severity levels from the reference specification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Reachability(Enum):
    """Finding reachability categories from the reference specification."""

    ACTIVE = "ACTIVE"
    CONDITIONAL = "CONDITIONAL"
    DEAD = "DEAD"
    TEST_ONLY = "TEST-ONLY"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    """A single security finding extracted from the assessment."""

    file_location: str
    title: str
    cwe: str
    severity: Severity
    reachability: Reachability = Reachability.UNKNOWN
    confidence: str = ""


@dataclass
class AssessmentResult:
    """Parsed and validated assessment output."""

    path: Path
    exists: bool
    lines: int = 0
    sections_found: list[str] = field(default_factory=list)
    sections_missing: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    critic_completed: bool = False
    verifier_completed: bool = False
    validation_section: bool = False
    summary_table: bool = False

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Count findings per severity level."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def is_complete(self) -> bool:
        """Whether the assessment has all required elements."""
        return (
            self.exists
            and not self.sections_missing
            and self.critic_completed
            and self.verifier_completed
            and self.validation_section
        )

    @classmethod
    def from_missing(cls, path: Path) -> Self:
        """Create a result for a missing assessment file."""
        return cls(path=path, exists=False)


# --- required sections from the reference spec --------------------------

REQUIRED_SECTIONS = [
    "Security Assessment",
    "Context",
    "Scope",
    "Attack Surface",
    "Source Inventory",
    "Findings",
    "Dependencies",
    "Summary",
    # Critic/Verifier are NOT required as section headers — models commonly
    # merge subagent results into a single ## Validation section.  Subagent
    # completion is tracked independently via _check_subagent().
    "Validation",
]

# --- parsing helpers -----------------------------------------------------

_SEVERITY_PATTERN = re.compile(
    r"\b(CRITICAL|HIGH|MODERATE|MEDIUM|LOW)\b",
    re.IGNORECASE,
)

_CWE_PATTERN = re.compile(r"CWE-\d+")

_FINDING_HEADER_PATTERN = re.compile(
    # Match H3 finding headers with file:line or pkg@version locations.
    # Accepts both [bracketed] and unbracketed location forms.
    # Examples:
    #   ### [routes/account.py:118] — Pickle deserialization
    #   ### routes/account.py:118 — Pickle deserialization
    #   ### click@8.1.7 — Command injection
    r"^###\s+\[?([^\]\n]*?(?::\d+|@[\d.]+)[^\]\n]*?)\]?\s*[—\-]+\s*(.+)",
    re.MULTILINE,
)

_SECTION_HEADER_PATTERN = re.compile(
    r"^##\s+(.+)",
    re.MULTILINE,
)


def _extract_sections(content: str) -> list[str]:
    """Extract all ## section headers from the markdown."""
    return [m.group(1).strip() for m in _SECTION_HEADER_PATTERN.finditer(content)]


_SECTION_ALIASES: dict[str, list[str]] = {
    "Security Assessment": ["security assessment"],
    "Context": ["context", "project context", "overview"],
    "Scope": [
        "scope", "semgrep baseline", "graphify context",
        # Models often cover scope implicitly via attack surface + scanned files
        "attack surface", "scanned files",
    ],
    "Attack Surface": ["attack surface", "entry points"],
    "Source Inventory": ["source inventory", "scanned files", "file list"],
    "Dependencies": ["dependencies", "dependency"],
    "Summary": ["summary", "summaries"],
    "Validation": ["validation"],
}


def _check_section_presence(
    found_headers: list[str],
    required: list[str],
    full_content: str = "",
) -> tuple[list[str], list[str]]:
    """Match found headers against required section keywords.

    Supports aliases so reasonable naming variations still match.
    Also checks the H1 header for 'Security Assessment'.

    Returns (found, missing) lists of required section names.
    """
    headers_lower = " ".join(found_headers).lower()
    # Include H1 in matching so '# Security Assessment — ...' counts
    h1_match = re.search(r"^#\s+(.+)", full_content, re.MULTILINE)
    if h1_match:
        headers_lower = h1_match.group(1).lower() + " " + headers_lower

    present: list[str] = []
    absent: list[str] = []
    for req in required:
        aliases = _SECTION_ALIASES.get(req, [req.lower()])
        if any(alias in headers_lower for alias in aliases):
            present.append(req)
        else:
            absent.append(req)
    return present, absent


def _extract_findings(content: str) -> list[Finding]:
    """Extract individual findings from the assessment markdown."""
    findings: list[Finding] = []
    for match in _FINDING_HEADER_PATTERN.finditer(content):
        location = match.group(1).strip()
        title = match.group(2).strip()
        # Look ahead in the next ~500 chars for CWE and severity
        context = content[match.start():match.start() + 500]
        cwe_match = _CWE_PATTERN.search(context)
        cwe = cwe_match.group(0) if cwe_match else "unknown"
        sev_match = _SEVERITY_PATTERN.search(context)
        severity = Severity.UNKNOWN
        if sev_match:
            raw = sev_match.group(1).upper()
            if raw == "MEDIUM":
                raw = "MODERATE"
            try:
                severity = Severity(raw)
            except ValueError:
                pass

        # Detect reachability
        reachability = Reachability.UNKNOWN
        context_lower = context.lower()
        for reach in Reachability:
            if reach.value.lower() in context_lower:
                reachability = reach
                break

        findings.append(Finding(
            file_location=location,
            title=title,
            cwe=cwe,
            severity=severity,
            reachability=reachability,
        ))
    return findings


def _check_subagent(content: str, agent_name: str) -> bool:
    """Check if a subagent's feedback is present and non-trivial.

    Detection layers (any match = True):
    1. Checkpoint HTML comment written by the processing step (11b/12b).
    2. Dedicated ``## Critic`` / ``## Verifier`` section header.
    3. Substantive mention inside ``## Validation``.
    """
    # Map agent name to its checkpoint tag
    checkpoint_tag = {
        "critic": "critic-checkpoint",
        "verifier": "verifier-checkpoint",
    }.get(agent_name.lower(), f"{agent_name.lower()}-checkpoint")

    # 1) Checkpoint comment (most reliable — written by the harness step)
    checkpoint_pattern = re.compile(
        rf"<!--\s*{re.escape(checkpoint_tag)}:\s*.+?-->",
    )
    cp_match = checkpoint_pattern.search(content)
    if cp_match:
        # Present and not a FAILED marker = completed successfully
        return "FAILED" not in cp_match.group(0)

    # 2) Dedicated section header (original check)
    header_pattern = re.compile(
        rf"##\s+.*{agent_name}.*",
        re.IGNORECASE,
    )
    match = header_pattern.search(content)
    if match:
        after = content[match.end():match.end() + 200].strip()
        if len(after) > 20:
            return True

    # 3) Substantive mention inside ## Validation (common model behaviour:
    #    critic + verifier results combined under a single Validation header).
    #    Tolerate numbered prefixes like "## 13. Validation block".
    val_match = re.search(
        r"^##\s+(?:\d+[a-z]?\.\s+)?Validation\b",
        content, re.MULTILINE | re.IGNORECASE,
    )
    if val_match:
        val_text = content[val_match.end():val_match.end() + 2000]
        # Require the agent name AND some evidence of actual feedback
        # (e.g. "reviewed by @critic", "critic issues: 5 raised",
        #  "verified against", "file:line", bullet points, etc.)
        if re.search(rf"@?{agent_name}", val_text, re.IGNORECASE):
            # Must have substantive content, not just a passing mention
            return len(val_text.strip()) > 50

    return False


def parse_assessment(assessment_path: Path) -> AssessmentResult:
    """Parse and validate a security assessment markdown file.

    Args:
        assessment_path: path to the SEC_ASSESSMENT_*.md file.

    Returns:
        AssessmentResult with parsed data and validation status.
    """
    if not assessment_path.exists():
        return AssessmentResult.from_missing(assessment_path)

    content = assessment_path.read_text()
    lines = content.count("\n") + 1
    section_headers = _extract_sections(content)
    found, missing = _check_section_presence(
        section_headers, REQUIRED_SECTIONS, full_content=content,
    )
    findings = _extract_findings(content)

    return AssessmentResult(
        path=assessment_path,
        exists=True,
        lines=lines,
        sections_found=found,
        sections_missing=missing,
        findings=findings,
        critic_completed=_check_subagent(content, "critic"),
        verifier_completed=_check_subagent(content, "verifier"),
        validation_section="Validation" in found,
        summary_table=bool(re.search(r"\|.*\|.*\|.*\|", content)),
    )
