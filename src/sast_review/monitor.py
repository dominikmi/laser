"""Live monitoring of opencode sessions via SQLite polling.

Runs in a background thread during headless reviews, logging tool calls,
subagent delegations, assessment progress, and errors to the runner's
standard logging framework.

Also manages oMLX model lifecycle: when a subagent using an oMLX model
completes, the monitor unloads that model to free GPU memory before the
next subagent starts a different model.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Default opencode database location
_OPENCODE_DB = Path.home() / ".local" / "share" / "opencode" / "opencode.db"

# Polling interval in seconds
_POLL_INTERVAL = 10.0

# oMLX provider name (matches opencode.json provider key)
_OMLX_PROVIDER = "omlx"


def _resolve_omlx_endpoint() -> tuple[str, str]:
    """Read oMLX base URL and API key from opencode.json.

    Returns:
        Tuple of (base_url, api_key). Empty base_url if not configured.
    """
    config_path = Path.home() / ".config" / "opencode" / "opencode.json"
    if not config_path.exists():
        return ("", "")
    try:
        cfg = json.loads(config_path.read_text())
        provider = cfg.get("provider", {}).get(_OMLX_PROVIDER, {})
        options = provider.get("options", {})
        base_url = options.get("baseURL", "")
        api_key = options.get("apiKey", "")
        # Resolve {env:VAR} syntax
        if api_key.startswith("{env:") and api_key.endswith("}"):
            import os
            api_key = os.environ.get(api_key[5:-1], "")
        return (base_url, api_key)
    except (json.JSONDecodeError, OSError):
        return ("", "")


def _unload_omlx_model(
    base_url: str,
    api_key: str,
    model_id: str,
) -> bool:
    """Unload a model from oMLX to free GPU memory.

    Args:
        base_url: oMLX base URL (e.g. http://127.0.0.1:8000/v1).
        api_key: oMLX API key.
        model_id: model identifier to unload.

    Returns:
        True if unload succeeded or model was already unloaded.
    """
    # Strip trailing /v1 if present for the unload endpoint
    url = f"{base_url.rstrip('/')}/models/{model_id}/unload"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        req = urllib.request.Request(url, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(
                "Monitor: unloaded oMLX model '%s' (status=%d)",
                model_id, resp.status,
            )
            return True
    except urllib.error.HTTPError as exc:
        # 400/404 = model not loaded (already unloaded by memory guard)
        if exc.code in (400, 404):
            body = ""
            try:
                body = exc.read().decode()[:200]
            except OSError:
                pass
            logger.debug(
                "Monitor: oMLX model '%s' already unloaded (%d: %s)",
                model_id, exc.code, body,
            )
            return True
        logger.warning(
            "Monitor: failed to unload oMLX model '%s': HTTP %d",
            model_id, exc.code,
        )
    except (urllib.error.URLError, OSError) as exc:
        logger.warning(
            "Monitor: failed to unload oMLX model '%s': %s",
            model_id, exc,
        )
    return False


@dataclass
class _SessionState:
    """Tracks the latest known state for delta logging."""

    session_id: str = ""
    message_count: int = 0
    tool_counts: dict[str, int] = field(default_factory=dict)
    subagent_sessions: dict[str, str] = field(default_factory=dict)
    subagent_statuses: dict[str, str] = field(default_factory=dict)
    assessment_bytes: int = 0
    assessment_lines: int = 0
    last_error: str = ""
    omlx_base_url: str = ""
    omlx_api_key: str = ""
    # Primary session model info for pre-emptive unloading
    primary_provider: str = ""
    primary_model: str = ""


def _find_latest_session(
    conn: sqlite3.Connection,
    after_ts: int,
) -> str | None:
    """Find the most recent session created after the given timestamp."""
    row = conn.execute(
        "SELECT id FROM session WHERE time_created >= ? "
        "ORDER BY time_created DESC LIMIT 1",
        (after_ts,),
    ).fetchone()
    return row[0] if row else None


def _resolve_primary_model(
    conn: sqlite3.Connection,
    session_id: str,
) -> tuple[str, str]:
    """Read the primary session's provider and model from the DB.

    Returns:
        Tuple of (provider_id, model_id). Empty strings if unavailable.
    """
    row = conn.execute(
        "SELECT model FROM session WHERE id = ?",
        (session_id,),
    ).fetchone()
    if not row or not row[0]:
        return ("", "")
    try:
        model_info = json.loads(row[0])
        return (
            model_info.get("providerID", ""),
            model_info.get("id", ""),
        )
    except (json.JSONDecodeError, TypeError):
        return ("", "")


def _get_message_count(conn: sqlite3.Connection, session_id: str) -> int:
    """Get total message count for a session."""
    row = conn.execute(
        "SELECT COUNT(*) FROM message WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    return row[0] if row else 0


def _get_tool_counts(
    conn: sqlite3.Connection, session_id: str,
) -> dict[str, int]:
    """Get tool call counts grouped by tool name."""
    rows = conn.execute(
        "SELECT json_extract(data, '$.tool') AS tool_name, COUNT(*) AS cnt "
        "FROM part WHERE session_id = ? AND json_extract(data, '$.type') = 'tool' "
        "GROUP BY tool_name ORDER BY cnt DESC",
        (session_id,),
    ).fetchall()
    return {row[0]: row[1] for row in rows if row[0]}


def _get_subagent_tasks(
    conn: sqlite3.Connection, session_id: str,
) -> list[dict[str, str]]:
    """Get subagent task delegations and their statuses."""
    rows = conn.execute(
        "SELECT data FROM part "
        "WHERE session_id = ? AND json_extract(data, '$.tool') = 'task' "
        "ORDER BY time_created",
        (session_id,),
    ).fetchall()
    tasks: list[dict[str, str]] = []
    for row in rows:
        try:
            part = json.loads(row[0])
            meta = part.get("state", {}).get("metadata", {})
            status = part.get("state", {}).get("status", "unknown")
            model_info = meta.get("model", {})
            tasks.append({
                "title": part.get("state", {}).get("title", "unnamed"),
                "status": status,
                "session_id": meta.get("sessionId", ""),
                "provider": model_info.get("providerID", ""),
                "model": model_info.get("modelID", ""),
            })
        except (json.JSONDecodeError, TypeError):
            pass
    return tasks


def _get_latest_errors(
    conn: sqlite3.Connection, session_id: str, limit: int = 3,
) -> list[str]:
    """Get the most recent error messages from the session."""
    rows = conn.execute(
        "SELECT json_extract(data, '$.state.error') "
        "FROM part WHERE session_id = ? "
        "AND json_extract(data, '$.state.status') = 'error' "
        "ORDER BY time_created DESC LIMIT ?",
        (session_id, limit),
    ).fetchall()
    return [row[0] for row in rows if row[0]]


def _check_assessment(assessment_path: Path) -> tuple[int, int]:
    """Check assessment file size and line count.

    Returns:
        Tuple of (byte_count, line_count).
    """
    if not assessment_path.exists():
        return 0, 0
    try:
        content = assessment_path.read_text()
        return len(content.encode()), content.count("\n") + 1
    except OSError:
        return 0, 0


def _get_subagent_tool_counts(
    conn: sqlite3.Connection, session_id: str,
) -> dict[str, int]:
    """Get tool counts for a subagent session."""
    if not session_id:
        return {}
    return _get_tool_counts(conn, session_id)


def _poll_loop(
    state: _SessionState,
    assessment_path: Path,
    stop_event: threading.Event,
    start_ts: int,
    db_path: Path,
) -> None:
    """Main polling loop — runs in a background thread."""
    # Resolve oMLX endpoint once at startup for model unloading
    if not state.omlx_base_url:
        state.omlx_base_url, state.omlx_api_key = _resolve_omlx_endpoint()
        if state.omlx_base_url:
            logger.debug("Monitor: oMLX unload enabled (%s)", state.omlx_base_url)

    poll_count = 0
    while not stop_event.is_set():
        stop_event.wait(_POLL_INTERVAL)
        if stop_event.is_set():
            break
        poll_count += 1

        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error as exc:
            logger.debug("Monitor: DB connect failed: %s", exc)
            continue

        try:
            # Find the session on first poll
            if not state.session_id:
                sid = _find_latest_session(conn, start_ts)
                if not sid:
                    logger.debug("Monitor: no session found yet")
                    continue
                state.session_id = sid
                logger.info("Monitor: session found: %s", sid)

            sid = state.session_id

            # Message count
            msg_count = _get_message_count(conn, sid)
            if msg_count != state.message_count:
                state.message_count = msg_count

            # Tool counts
            tool_counts = _get_tool_counts(conn, sid)
            new_tools: dict[str, int] = {}
            for tool_name, count in tool_counts.items():
                prev = state.tool_counts.get(tool_name, 0)
                if count > prev:
                    new_tools[tool_name] = count - prev
            if new_tools:
                state.tool_counts = tool_counts
                delta_str = ", ".join(
                    f"{name}(+{cnt})" for name, cnt in new_tools.items()
                )
                total_str = ", ".join(
                    f"{name}={cnt}" for name, cnt in tool_counts.items()
                )
                logger.info(
                    "Monitor: msgs=%d  tools: %s  [delta: %s]",
                    msg_count, total_str, delta_str,
                )

            # Resolve primary model info once (for pre-emptive unloading)
            if not state.primary_provider and state.session_id:
                p, m = _resolve_primary_model(conn, state.session_id)
                if p and m:
                    state.primary_provider = p
                    state.primary_model = m
                    logger.debug(
                        "Monitor: primary model is %s/%s", p, m,
                    )

            # Subagent tasks
            tasks = _get_subagent_tasks(conn, sid)
            for task in tasks:
                task_id = task.get("session_id", "")
                prev_status = state.subagent_statuses.get(task_id, "")
                current_status = task["status"]
                if current_status != prev_status:
                    state.subagent_statuses[task_id] = current_status
                    provider_model = (
                        f"{task['provider']}/{task['model']}"
                        if task["provider"] else "unknown"
                    )
                    logger.info(
                        "Monitor: subagent '%s' [%s] status=%s (model=%s)",
                        task["title"], task_id[:20],
                        current_status, provider_model,
                    )

                    # Pre-emptive unload: when an oMLX subagent starts
                    # running, unload the primary model first to free
                    # GPU memory for the subagent's model.
                    if (
                        current_status == "running"
                        and task["provider"] == _OMLX_PROVIDER
                        and task["model"]
                        and state.omlx_base_url
                        and state.primary_provider == _OMLX_PROVIDER
                        and state.primary_model
                        and state.primary_model != task["model"]
                    ):
                        logger.info(
                            "Monitor: pre-emptive unload of primary "
                            "model '%s' for subagent '%s'",
                            state.primary_model, task["title"],
                        )
                        _unload_omlx_model(
                            state.omlx_base_url,
                            state.omlx_api_key,
                            state.primary_model,
                        )

                    # Log subagent tool usage when completed or errored
                    if current_status in ("completed", "error") and task_id:
                        sub_tools = _get_subagent_tool_counts(conn, task_id)
                        if sub_tools:
                            sub_str = ", ".join(
                                f"{n}={c}" for n, c in sub_tools.items()
                            )
                            logger.info(
                                "Monitor: subagent '%s' tools: %s",
                                task["title"], sub_str,
                            )
                        sub_msgs = _get_message_count(conn, task_id)
                        logger.info(
                            "Monitor: subagent '%s' messages=%d",
                            task["title"], sub_msgs,
                        )
                        # Unload the subagent's oMLX model to free
                        # GPU memory for the next model (primary
                        # resumption or another subagent).
                        if (
                            task["provider"] == _OMLX_PROVIDER
                            and task["model"]
                            and state.omlx_base_url
                        ):
                            _unload_omlx_model(
                                state.omlx_base_url,
                                state.omlx_api_key,
                                task["model"],
                            )

            # Assessment file progress
            assess_bytes, assess_lines = _check_assessment(assessment_path)
            if assess_bytes != state.assessment_bytes:
                state.assessment_bytes = assess_bytes
                state.assessment_lines = assess_lines
                logger.info(
                    "Monitor: assessment %d lines, %d bytes",
                    assess_lines, assess_bytes,
                )

            # Errors
            errors = _get_latest_errors(conn, sid, limit=1)
            if errors and errors[0] != state.last_error:
                state.last_error = errors[0]
                logger.warning(
                    "Monitor: session error: %s",
                    errors[0][:200],
                )

            # Periodic summary (every 6 polls = ~60s)
            if poll_count % 6 == 0 and not new_tools:
                total_str = ", ".join(
                    f"{name}={cnt}" for name, cnt in tool_counts.items()
                ) or "none"
                logger.info(
                    "Monitor: heartbeat msgs=%d tools=[%s] "
                    "assessment=%d lines",
                    msg_count, total_str, assess_lines,
                )

        except sqlite3.Error as exc:
            logger.debug("Monitor: DB query error: %s", exc)
        finally:
            conn.close()


class SessionMonitor:
    """Background monitor for opencode session activity.

    Usage:
        monitor = SessionMonitor(assessment_path)
        monitor.start()
        # ... run the review ...
        monitor.stop()
    """

    def __init__(
        self,
        assessment_path: Path,
        db_path: Path = _OPENCODE_DB,
        poll_interval: float = _POLL_INTERVAL,
    ) -> None:
        self._assessment_path = assessment_path
        self._db_path = db_path
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = _SessionState()
        self._start_ts = 0

    def start(self) -> None:
        """Start the monitoring thread."""
        if not self._db_path.exists():
            logger.warning(
                "Monitor: opencode DB not found at %s, monitoring disabled",
                self._db_path,
            )
            return

        # Record start time in milliseconds (opencode uses ms timestamps)
        self._start_ts = int(time.time() * 1000)
        self._stop_event.clear()
        self._state = _SessionState()

        self._thread = threading.Thread(
            target=_poll_loop,
            args=(
                self._state,
                self._assessment_path,
                self._stop_event,
                self._start_ts,
                self._db_path,
            ),
            daemon=True,
            name="session-monitor",
        )
        self._thread.start()
        logger.info("Monitor: started (poll every %.0fs)", self._poll_interval)

    def stop(self) -> None:
        """Stop the monitoring thread and log final summary."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        # Final summary
        if self._state.session_id:
            tool_str = ", ".join(
                f"{name}={cnt}"
                for name, cnt in self._state.tool_counts.items()
            ) or "none"
            logger.info(
                "Monitor: final — session=%s msgs=%d tools=[%s] "
                "assessment=%d lines/%d bytes",
                self._state.session_id[:20],
                self._state.message_count,
                tool_str,
                self._state.assessment_lines,
                self._state.assessment_bytes,
            )
            for task_id, status in self._state.subagent_statuses.items():
                logger.info(
                    "Monitor: subagent %s final_status=%s",
                    task_id[:20], status,
                )

    @property
    def session_id(self) -> str:
        """The discovered session ID, if any."""
        return self._state.session_id
