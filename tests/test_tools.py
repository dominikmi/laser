"""Tests for knowledge MCP configuration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from sast_review.tools import build_knowledge_mcp_config


class KnowledgeMcpConfigTests(unittest.TestCase):
    """Verify loopback restrictions and graceful daemon detection."""

    @patch("sast_review.tools.socket.create_connection")
    def test_reachable_loopback_service_is_configured(self, _create_connection: object) -> None:
        config = build_knowledge_mcp_config("http://127.0.0.1:8765/mcp")
        self.assertIn("laser-knowledge", config)
        self.assertEqual(config["laser-knowledge"]["type"], "remote")
        self.assertFalse(config["laser-knowledge"]["oauth"])

    @patch("sast_review.tools.socket.create_connection", side_effect=OSError)
    def test_unreachable_service_uses_local_stdio_fallback(self, _create_connection: object) -> None:
        database = Path("relative/knowledge.sqlite3")
        config = build_knowledge_mcp_config(
            "http://127.0.0.1:8765/mcp",
            database_path=database,
        )
        server = config["laser-knowledge"]
        self.assertEqual(server["type"], "local")
        self.assertEqual(
            server["command"],
            [
                sys.executable,
                "-m",
                "sast_review.knowledge_mcp",
                "--database",
                str(database.resolve()),
                "--transport",
                "stdio",
            ],
        )

    @patch("sast_review.tools.socket.create_connection", side_effect=OSError)
    def test_unreachable_service_without_database_is_omitted(
        self, _create_connection: object
    ) -> None:
        self.assertEqual(build_knowledge_mcp_config("http://127.0.0.1:8765/mcp"), {})

    def test_non_loopback_or_wrong_path_is_rejected(self) -> None:
        for url in (
            "https://example.com/mcp",
            "http://0.0.0.0:8765/mcp",
            "http://127.0.0.1:8765/other",
            "http://127.0.0.1:8765/mcp?token=secret",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                build_knowledge_mcp_config(url)


if __name__ == "__main__":
    unittest.main()
