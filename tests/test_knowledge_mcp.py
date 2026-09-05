"""Tests for the read-only review-knowledge MCP service."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from typing import cast

from sast_review.knowledge_mcp import create_server


class KnowledgeMcpTests(unittest.TestCase):
    """Verify service restrictions and exposed tool contracts."""

    def test_server_exposes_only_read_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = create_server(Path(temporary) / "knowledge.sqlite3")
            tools = asyncio.run(server.list_tools())
            names = {tool.name for tool in tools}
            self.assertEqual(
                names,
                {
                    "knowledge_status",
                    "search_security_patterns",
                },
            )
            self.assertTrue(all(tool.annotations and tool.annotations.readOnlyHint for tool in tools))
            _, status = asyncio.run(server.call_tool("knowledge_status", {}))
            self.assertIsNotNone(status)
            status_data = cast(dict[str, object], status)
            self.assertEqual(status_data["status"], "ready")
            self.assertEqual(status_data["bundle_count"], 0)

    def test_non_loopback_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "knowledge.sqlite3"
            with self.assertRaises(ValueError):
                create_server(database, host="0.0.0.0")
            with self.assertRaises(ValueError):
                create_server(database, port=0)


if __name__ == "__main__":
    unittest.main()
