"""Read-only MCP service for persistent security-review knowledge."""

import argparse
from pathlib import Path
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings
from mcp.types import ToolAnnotations

from sast_review.knowledge_store import KnowledgeStore

Settings.model_rebuild()

DEFAULT_DATABASE = Path.home() / ".local" / "share" / "sast-review" / "knowledge.sqlite3"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def create_server(
    database_path: Path,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> FastMCP:
    """Create a localhost-only, read-only knowledge MCP server.

    Args:
        database_path: SQLite knowledge database.
        host: Loopback interface to bind.
        port: TCP port to bind.

    Returns:
        Configured FastMCP server.

    Raises:
        ValueError: If a non-loopback host or invalid port is supplied.
    """
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("knowledge MCP must bind to a loopback interface")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    store = KnowledgeStore(database_path)
    server = FastMCP(
        "LASER Review Knowledge",
        instructions=(
            "This service exposes generalized cross-repository patterns only. Results "
            "are investigative leads, not verdicts. The service has no write tools."
        ),
        host=host,
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )

    @server.tool(annotations=_READ_ONLY)
    def knowledge_status() -> dict[str, int | str]:
        """Return read-only service status and the immutable bundle count."""
        return {
            "status": "ready",
            "bundle_count": store.bundle_count(),
        }

    @server.tool(annotations=_READ_ONLY)
    def search_security_patterns(
        query: str,
        current_repository_id: str,
        limit: int = 20,
    ) -> dict[str, object]:
        """Search generalized patterns from other repositories.

        Args:
            query: Security pattern terms or quoted phrase.
            current_repository_id: Repository UUID to exclude from results.
            limit: Maximum patterns to return.

        Returns:
            Generalized patterns explicitly labeled as non-verdict leads.
        """
        parsed_repository_id = UUID(current_repository_id)
        patterns = store.search_patterns(query, parsed_repository_id, limit=limit)
        return {
            "classification": "INVESTIGATIVE LEADS — NOT VERDICTS",
            "patterns": [pattern.model_dump(mode="json") for pattern in patterns],
        }

    return server


def main() -> None:
    """Run the local knowledge daemon using Streamable HTTP MCP."""
    parser = argparse.ArgumentParser(
        prog="sast-review-knowledge",
        description="Read-only local MCP daemon for LASER review knowledge",
    )
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--transport",
        choices=("streamable-http", "stdio"),
        default="streamable-http",
    )
    args = parser.parse_args()

    database_path = args.database.expanduser().resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if database_path.parent == DEFAULT_DATABASE.parent:
        database_path.parent.chmod(0o700)
    server = create_server(database_path, host=args.host, port=args.port)
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
