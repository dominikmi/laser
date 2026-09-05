"""Tests for review orchestration completion behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sast_review import _execute_with_completion_repair, execute_review

_INCOMPLETE_ASSESSMENT = """# Security Assessment — test
## Context
## Scope
## Attack Surface
## Source Inventory
## Findings
## Dependencies
## Summary
"""

_VALIDATION = """## Validation
Reviewed by @critic and @verifier with substantive independent results.
<!-- critic-checkpoint: 0 items, 0 accepted, 0 disputed -->
<!-- verifier-checkpoint: 0 items, 0 verified, 0 corrected, 0 removed, 0 unverified -->
"""


class SessionRecoveryTests(unittest.TestCase):
    """Verify OpenCode DB discovery backs up missing JSON session events."""

    @patch("sast_review.subprocess.Popen")
    @patch("sast_review.SessionMonitor")
    def test_monitor_session_is_added_to_empty_events(
        self, monitor_type: object, popen: object
    ) -> None:
        monitor = monitor_type.return_value
        monitor.session_id = "session-from-db"
        process = popen.return_value
        process.communicate.return_value = "", ""
        process.returncode = 0
        with tempfile.TemporaryDirectory() as temporary:
            result = execute_review(
                Path(temporary),
                "provider/model",
                "test",
                use_headroom=False,
            )
        self.assertEqual(result[1], 0)
        self.assertIn('"sessionID": "session-from-db"', result[2])


class CompletionRepairTests(unittest.TestCase):
    """Verify incomplete runs resume once and cannot report success prematurely."""

    @patch("sast_review.execute_review")
    def test_incomplete_assessment_resumes_existing_session(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"

            def run(*args: object, **kwargs: object) -> tuple[float, int, str, str, bool]:
                if kwargs.get("session_id") is None:
                    assessment.write_text(_INCOMPLETE_ASSESSMENT)
                    return 1.0, 0, '{"sessionID":"session-1"}\n', "", False
                assessment.write_text(_INCOMPLETE_ASSESSMENT + _VALIDATION)
                return 2.0, 0, '{"sessionID":"session-1"}\n', "", False

            execute.side_effect = run
            result = _execute_with_completion_repair(
                repository,
                "provider/model",
                "test",
                0,
                False,
                None,
            )

        self.assertEqual(result[0], 3.0)
        self.assertEqual(result[1], 0)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(execute.call_args.kwargs["session_id"], "session-1")

    @patch("sast_review.execute_review")
    def test_unchanged_stale_assessment_returns_failure(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"
            assessment.write_text(_INCOMPLETE_ASSESSMENT + _VALIDATION)
            execute.return_value = 1.0, 0, '{"sessionID":"session-1"}\n', "", False

            result = _execute_with_completion_repair(
                repository,
                "provider/model",
                "test",
                0,
                False,
                None,
            )

        self.assertEqual(result[1], 2)
        self.assertEqual(execute.call_count, 1)

    @patch("sast_review.execute_review")
    def test_incomplete_assessment_after_repair_returns_failure(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"

            def run(*args: object, **kwargs: object) -> tuple[float, int, str, str, bool]:
                assessment.write_text(_INCOMPLETE_ASSESSMENT)
                return 1.0, 0, '{"sessionID":"session-1"}\n', "", False

            execute.side_effect = run
            result = _execute_with_completion_repair(
                repository,
                "provider/model",
                "test",
                0,
                False,
                None,
            )

        self.assertEqual(result[1], 2)
        self.assertEqual(execute.call_count, 2)


if __name__ == "__main__":
    unittest.main()
