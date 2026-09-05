"""Integration tests for the persistent knowledge pipeline."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from uuid import UUID

from sast_review.knowledge_models import VerdictState
from sast_review.knowledge_pipeline import (
    collect_knowledge_artifacts,
    open_knowledge_store,
    prepare_knowledge,
)

_REPOSITORY_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_ASSESSMENT = """# Security Assessment — 2026-09-05 — test

## Findings

### [src/app.py:1-3] — Command injection
**Finding ID:** F-001
**CWE:** CWE-78
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     src/app.py:1 — request input
Sink:       src/app.py:3 — process execution

```python
run(command)
```

**Exploit:** 1. submit command -> 2. input reaches run -> 3. execute process
**Mitigations:** None
**Fix:** Use an argument array.

<!-- verifier-record: {"finding_id":"F-001","result":"verified","checks_performed":["path","line","snippet","trace"],"evidence_locations":["src/app.py:1","src/app.py:3"],"detail":"Source and sink match current code."} -->
"""


class KnowledgePipelineTests(unittest.TestCase):
    """Verify collection, persistence, export, and subsequent retrieval."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        source = self.repository / "src" / "app.py"
        source.parent.mkdir()
        source.write_text("command = request.args['q']\nvalidate(command)\nrun(command)\n")
        self.output = self.root / "output"
        self.output.mkdir()
        self.assessment = self.output / "SEC_ASSESSMENT_test.md"
        self.assessment.write_text(_ASSESSMENT)
        self.database = self.root / "knowledge.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_completed_bundle_is_exported_ingested_and_reused(self) -> None:
        store = open_knowledge_store(self.database)
        artifacts = collect_knowledge_artifacts(
            self.assessment,
            self.repository,
            self.output,
            _REPOSITORY_ID,
            store,
            primary_model_id="provider/primary",
            critic_model_id="provider/critic",
            verifier_model_id="provider/verifier",
            prompt_text="review contract",
            detected_tool_versions={"semgrep": "1.0"},
            ingest=True,
        )
        self.assertTrue(artifacts.bundle_path.is_file())
        self.assertTrue((artifacts.okf_path / "index.md").is_file())
        self.assertIsNotNone(artifacts.ingest_result)
        claim = artifacts.bundle.findings[0]
        self.assertEqual(
            artifacts.ingest_result.finding_states[claim.finding_id],
            VerdictState.VERIFIED_ACTIVE,
        )
        persisted = json.loads(artifacts.bundle_path.read_text())
        self.assertEqual(persisted["metadata"]["repository_id"], str(_REPOSITORY_ID))

        prepared = prepare_knowledge(self.repository, _REPOSITORY_ID, self.database)
        self.assertEqual(prepared.active_count, 1)
        self.assertEqual(prepared.stale_count, 0)
        self.assertIn("src/app.py", prepared.prior_markdown)

    def test_non_ingested_bundle_remains_a_run_artifact(self) -> None:
        store = open_knowledge_store(self.database)
        artifacts = collect_knowledge_artifacts(
            self.assessment,
            self.repository,
            self.output,
            _REPOSITORY_ID,
            store,
            primary_model_id="provider/primary",
            critic_model_id=None,
            verifier_model_id="provider/verifier",
            prompt_text="review contract",
            detected_tool_versions={},
            ingest=False,
        )
        self.assertIsNone(artifacts.ingest_result)
        self.assertTrue(artifacts.bundle_path.exists())
        self.assertEqual(store.bundle_count(), 0)


if __name__ == "__main__":
    unittest.main()
