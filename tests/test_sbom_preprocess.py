"""Tests for bounded Syft/Grype preprocessing and repository exclusions."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sast_review.inject import (
    DEFAULT_SBOM_TIMEOUT,
    _load_syft_exclusions,
    run_sbom_preprocess,
)


class SyftConfigurationTests(unittest.TestCase):
    """Validate safe, deterministic scan scope across repository configs."""

    def test_defaults_merge_with_repository_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            config = repo / ".syft.yaml"
            config.write_text("exclude:\n  - ./data/**\n  - ./.venv/**\n  - ./output/**\n")
            patterns, selected_config = _load_syft_exclusions(repo)
            self.assertEqual(selected_config, config.resolve())
            self.assertEqual(patterns.count("./.venv/**"), 1)
            self.assertEqual(patterns.count("./output/**"), 1)
            self.assertEqual(patterns[-1], "./data/**")

    def test_unsafe_configs_fail_validation(self) -> None:
        for content in (
            "exclude: [../outside/**]\n",
            "exclude: [/private/**]\n",
            "exclude: [C:/outside/**]\n",
            "exclude: [data/**]\n",
            "exclude: [123]\n",
            "exclude: invalid\n",
            "exclude: [unterminated\n",
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary)
                (repo / ".syft.yaml").write_text(content)
                with self.assertRaises((TypeError, ValueError)):
                    _load_syft_exclusions(repo)

    def test_symlinked_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            config = root / "config.yaml"
            config.write_text("exclude: []\n")
            (repo / ".syft.yaml").symlink_to(config)
            with self.assertRaises(ValueError):
                _load_syft_exclusions(repo)


class SbomPreprocessTests(unittest.TestCase):
    """Ensure timeout and exclusions propagate without masking tool failure."""

    @patch("sast_review.inject.subprocess.run")
    def test_syft_and_grype_receive_timeout_scope_and_cwd(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".syft.yaml").write_text("exclude:\n  - ./data/**\n")
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                subprocess.CompletedProcess([], 0, stdout='{"matches": []}', stderr=""),
            ]
            sbom, grype = run_sbom_preprocess(
                repo,
                syft_binary=Path("/usr/bin/syft"),
                grype_binary=Path("/usr/bin/grype"),
                timeout_seconds=900,
            )
            self.assertIsNotNone(sbom)
            self.assertIsNotNone(grype)
            syft_call, grype_call = run.call_args_list
            self.assertEqual(syft_call.kwargs["timeout"], 900)
            self.assertEqual(grype_call.kwargs["timeout"], 900)
            self.assertEqual(syft_call.kwargs["cwd"], repo)
            self.assertEqual(grype_call.kwargs["cwd"], repo)
            command = syft_call.args[0]
            exclusions = [
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--exclude"
            ]
            self.assertIn("./data/**", exclusions)
            self.assertIn("**/node_modules/**", exclusions)
            self.assertEqual(len(exclusions), len(set(exclusions)))

    @patch("sast_review.inject.subprocess.run")
    def test_syft_timeout_skips_grype(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            run.side_effect = subprocess.TimeoutExpired(["syft"], DEFAULT_SBOM_TIMEOUT)
            self.assertEqual(
                run_sbom_preprocess(
                    repo,
                    syft_binary=Path("/usr/bin/syft"),
                    grype_binary=Path("/usr/bin/grype"),
                ),
                (None, None),
            )
            run.assert_called_once()
            self.assertEqual(run.call_args.kwargs["timeout"], DEFAULT_SBOM_TIMEOUT)

    @patch("sast_review.inject.subprocess.run")
    def test_grype_timeout_preserves_sbom(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                subprocess.TimeoutExpired(["grype"], DEFAULT_SBOM_TIMEOUT),
            ]
            sbom, grype = run_sbom_preprocess(
                repo,
                syft_binary=Path("/usr/bin/syft"),
                grype_binary=Path("/usr/bin/grype"),
            )
            self.assertIsNotNone(sbom)
            self.assertIsNone(grype)
            self.assertEqual(run.call_count, 2)

    @patch("sast_review.inject.subprocess.run")
    def test_invalid_config_never_invokes_syft(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".syft.yaml").write_text("exclude: [./../outside/**]\n")
            self.assertEqual(
                run_sbom_preprocess(repo, syft_binary=Path("/usr/bin/syft")),
                (None, None),
            )
            run.assert_not_called()

    def test_timeout_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            run_sbom_preprocess(Path(temporary), timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
