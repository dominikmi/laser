"""Tests for review orchestration completion behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sast_review import _execute_staged_review, execute_review
from sast_review.monitor import _subagent_protocol_violation

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


class ProtocolEnforcementTests(unittest.TestCase):
    """Verify premature and concurrent subagents are rejected."""

    def test_subagent_before_assessment_is_rejected(self) -> None:
        tasks = [{"status": "running"}]
        self.assertEqual(
            _subagent_protocol_violation(tasks, 0, 1),
            "subagent started before a non-empty assessment existed",
        )

    def test_subagent_during_primary_stage_is_rejected(self) -> None:
        tasks = [{"status": "running"}]
        self.assertEqual(
            _subagent_protocol_violation(tasks, 100, 0),
            "subagent started during the primary assessment stage",
        )

    def test_concurrent_subagents_are_rejected(self) -> None:
        tasks = [{"status": "running"}, {"status": "running"}]
        self.assertEqual(
            _subagent_protocol_violation(tasks, 100, 1),
            "multiple subagents started concurrently",
        )


class SessionRecoveryTests(unittest.TestCase):
    """Verify OpenCode DB discovery backs up missing JSON session events."""

    @patch("sast_review.subprocess.Popen")
    @patch("sast_review.SessionMonitor")
    def test_monitor_session_is_added_to_empty_events(
        self, monitor_type: object, popen: object
    ) -> None:
        monitor = monitor_type.return_value
        monitor.session_id = "session-from-db"
        monitor.protocol_violation = ""
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


class StagedReviewTests(unittest.TestCase):
    """Verify the runner serializes critic and verifier execution."""

    @patch("sast_review.execute_review")
    def test_critic_finishes_before_verifier_starts(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"

            def run(*args: object, **kwargs: object) -> tuple[float, int, str, str, bool]:
                prompt = kwargs.get("resume_prompt")
                if prompt is None:
                    assessment.write_text(_INCOMPLETE_ASSESSMENT)
                elif "Step 11" in prompt:
                    assessment.write_text(
                        _INCOMPLETE_ASSESSMENT
                        + "<!-- critic-checkpoint: 0 items, 0 accepted, 0 disputed -->\n"
                    )
                else:
                    assessment.write_text(_INCOMPLETE_ASSESSMENT + _VALIDATION)
                return 1.0, 0, '{"sessionID":"session-1"}\n', "", False

            execute.side_effect = run
            result = _execute_staged_review(
                repository,
                "provider/model",
                "test",
                0,
                False,
                None,
            )

        self.assertEqual(result[0], 3.0)
        self.assertEqual(result[1], 0)
        self.assertEqual(execute.call_count, 3)
        critic_call, verifier_call = execute.call_args_list[1:]
        self.assertIn("Step 11", critic_call.kwargs["resume_prompt"])
        self.assertNotIn("Step 12", critic_call.kwargs["resume_prompt"])
        self.assertIn("Step 12", verifier_call.kwargs["resume_prompt"])
        self.assertNotIn("Step 11", verifier_call.kwargs["resume_prompt"])

    @patch("sast_review.execute_review")
    def test_unchanged_stale_assessment_returns_failure(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"
            assessment.write_text(_INCOMPLETE_ASSESSMENT + _VALIDATION)
            execute.return_value = 1.0, 0, '{"sessionID":"session-1"}\n', "", False

            result = _execute_staged_review(
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
    def test_missing_critic_checkpoint_stops_before_verifier(self, execute: object) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            assessment = output / "SEC_ASSESSMENT_test.md"

            def run(*args: object, **kwargs: object) -> tuple[float, int, str, str, bool]:
                assessment.write_text(_INCOMPLETE_ASSESSMENT)
                return 1.0, 0, '{"sessionID":"session-1"}\n', "", False

            execute.side_effect = run
            result = _execute_staged_review(
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
