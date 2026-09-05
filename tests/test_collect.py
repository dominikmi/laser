"""Tests for assessment collection behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sast_review.collect import parse_assessment


class RejectedFindingTests(unittest.TestCase):
    """Verify verifier-rejected audit entries do not inflate report findings."""

    def test_rejected_section_is_excluded_from_finding_metrics(self) -> None:
        content = """# Security Assessment — test
## Context
## Scope
## Attack surface
## Scanned files
## Findings
### src/live.py:10 — Live issue
**CWE:** CWE-78
**Severity:** HIGH
## Dependencies
## Summary
## Rejected findings
### src/rejected.py:20 — False positive
**CWE:** CWE-89
**Severity:** CRITICAL
**Rejection reason:** Data does not reach the sink.
## Validation
Reviewed by @critic and @verifier with substantive independent results.
<!-- critic-checkpoint: 0 items, 0 accepted, 0 disputed -->
<!-- verifier-checkpoint: 1 items, 0 verified, 0 corrected, 1 removed, 0 unverified -->
"""
        with tempfile.TemporaryDirectory() as temporary:
            assessment = Path(temporary) / "assessment.md"
            assessment.write_text(content)
            result = parse_assessment(assessment)
        self.assertEqual(result.total_findings, 1)
        self.assertEqual(result.findings[0].file_location, "src/live.py:10")
        self.assertTrue(result.verifier_completed)

    def test_metrics_use_computed_severity_and_accept_non_location_heading(self) -> None:
        content = """# Security Assessment — test
## Context
## Scope
## Attack surface
## Scanned files
## Findings
### state-changing POST routes — Missing CSRF protection
**Finding ID:** F-001
**CWE:** CWE-OTHER
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** LOW
**Severity:** Impact HIGH x Likelihood LOW = MEDIUM (ACTIVE, no adjustment)
## Dependencies
## Summary
## Validation
Reviewed by @critic and @verifier with substantive independent results.
<!-- critic-checkpoint: 0 items, 0 accepted, 0 disputed -->
<!-- verifier-checkpoint: 0 items, 0 verified, 0 corrected, 0 removed, 0 unverified -->
"""
        with tempfile.TemporaryDirectory() as temporary:
            assessment = Path(temporary) / "assessment.md"
            assessment.write_text(content)
            result = parse_assessment(assessment)
        self.assertEqual(result.total_findings, 1)
        self.assertEqual(result.findings[0].file_location, "state-changing POST routes")
        self.assertEqual(result.findings[0].cwe, "CWE-OTHER")
        self.assertEqual(result.findings_by_severity, {"MEDIUM": 1})
        self.assertTrue(result.is_complete)


if __name__ == "__main__":
    unittest.main()
