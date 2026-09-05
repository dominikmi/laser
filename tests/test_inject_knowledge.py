"""Tests for knowledge injection and Graphify freshness."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sast_review.inject import (
    InjectionManifest,
    cleanup,
    inject_commands,
    inject_omlx_unload_script,
    inject_prior_knowledge,
    run_graphify_preprocess,
)


class PriorKnowledgeInjectionTests(unittest.TestCase):
    """Verify prior context follows the existing backup/restore lifecycle."""

    def test_existing_prior_context_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            output = repository / ".security-output"
            output.mkdir()
            prior = output / "PRIOR_KNOWLEDGE.md"
            prior.write_text("original\n")
            manifest = InjectionManifest()
            inject_prior_knowledge(repository, "temporary\n", manifest)
            self.assertEqual(prior.read_text(), "temporary\n")
            cleanup(manifest)
            self.assertEqual(prior.read_text(), "original\n")

    def test_new_prior_context_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            manifest = InjectionManifest()
            inject_prior_knowledge(repository, "temporary\n", manifest)
            prior = repository / ".security-output" / "PRIOR_KNOWLEDGE.md"
            self.assertTrue(prior.exists())
            cleanup(manifest)
            self.assertFalse(prior.exists())

    def test_symlinked_output_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            outside = root / "outside"
            repository.mkdir()
            outside.mkdir()
            (repository / ".security-output").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                inject_prior_knowledge(repository, "unsafe\n", InjectionManifest())
            self.assertEqual(list(outside.iterdir()), [])

    def test_subagent_prompts_are_removed_by_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            runner = Path(__file__).resolve().parents[1]
            manifest = InjectionManifest()
            inject_commands(runner, repository, manifest)
            output = repository / ".security-output"
            self.assertTrue((output / "critic-prompt.txt").exists())
            self.assertTrue((output / "verifier-prompt.txt").exists())
            cleanup(manifest)
            self.assertFalse((output / "critic-prompt.txt").exists())
            self.assertFalse((output / "verifier-prompt.txt").exists())

    def test_omlx_script_uses_runtime_secret_and_is_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            manifest = InjectionManifest()
            inject_omlx_unload_script(
                repository,
                "omlx/private-model",
                "http://127.0.0.1:8000/v1",
                manifest,
            )
            script = repository / ".security-output" / "omlx-unload.sh"
            content = script.read_text()
            self.assertIn("SAST_REVIEW_OMLX_API_KEY", content)
            self.assertNotIn("runtime-secret", content)
            self.assertEqual(script.stat().st_mode & 0o777, 0o700)
            cleanup(manifest)
            self.assertFalse(script.exists())


class GraphifyFreshnessTests(unittest.TestCase):
    """Verify an existing graph is incrementally refreshed instead of trusted."""

    @patch("sast_review.inject.subprocess.run")
    def test_existing_graph_runs_update(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            graph = repository / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text("{}")
            completed = subprocess.CompletedProcess(
                ["graphify", "update", str(repository)],
                0,
                stdout="updated",
                stderr="",
            )
            run.return_value = completed
            self.assertTrue(run_graphify_preprocess(repository))
            run.assert_called_once()
            command = run.call_args.args[0]
            self.assertEqual(command, ["graphify", "update", str(repository)])

    @patch("sast_review.inject.subprocess.run")
    def test_full_mode_remains_full_with_existing_graph(self, run: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            graph = repository / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text("{}")
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            self.assertTrue(
                run_graphify_preprocess(
                    repository,
                    full_mode=True,
                    llm_base_url="http://127.0.0.1:8000/v1",
                    llm_model="review-model",
                    llm_api_key="runtime-secret",
                )
            )
            command = run.call_args.args[0]
            environment = run.call_args.kwargs["env"]
            self.assertEqual(command, ["graphify", str(repository)])
            self.assertEqual(environment["OPENAI_MODEL"], "review-model")


if __name__ == "__main__":
    unittest.main()
