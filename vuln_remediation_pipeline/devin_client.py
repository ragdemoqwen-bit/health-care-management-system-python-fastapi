"""
Devin API Client Module

Thin wrapper around the Devin v3 REST API for creating sessions, polling
status, sending messages, and retrieving results.

Supports both:
  - Direct HTTP calls (standalone usage with DEVIN_API_KEY)
  - MCP tool calls (when running inside a Devin session)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://api.devin.ai/v3"

SETTLED_STATUSES = frozenset({"exit", "error", "suspended"})
SETTLED_DETAILS = frozenset({"finished", "waiting_for_user", "waiting_for_approval"})

DEFAULT_POLL_INTERVAL = 15  # seconds
DEFAULT_TIMEOUT = 1800  # 30 minutes


class SessionStatus(str, Enum):
    RUNNING = "running"
    EXIT = "exit"
    ERROR = "error"
    SUSPENDED = "suspended"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SessionResult:
    """Outcome of a completed Devin session."""

    session_id: str
    status: str
    status_detail: str = ""
    url: str = ""
    pr_url: Optional[str] = None
    structured_output: Optional[dict[str, Any]] = None
    error_message: Optional[str] = None


@dataclass
class DevinClientConfig:
    """Configuration for the Devin API client."""

    api_key: str = ""
    org_id: str = ""
    base_url: str = BASE_URL
    poll_interval: int = DEFAULT_POLL_INTERVAL
    timeout: int = DEFAULT_TIMEOUT
    repos: list[str] = field(default_factory=list)
    max_acu_limit: Optional[int] = None

    @classmethod
    def from_env(cls) -> DevinClientConfig:
        """Build config from environment variables."""
        return cls(
            api_key=os.environ.get("DEVIN_API_KEY", ""),
            org_id=os.environ.get("DEVIN_ORG_ID", ""),
            base_url=os.environ.get("DEVIN_API_BASE_URL", BASE_URL),
            poll_interval=int(os.environ.get("DEVIN_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL))),
            timeout=int(os.environ.get("DEVIN_TIMEOUT", str(DEFAULT_TIMEOUT))),
        )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class DevinClient:
    """Devin v3 API client for session lifecycle management."""

    def __init__(self, config: Optional[DevinClientConfig] = None) -> None:
        self.config = config or DevinClientConfig.from_env()
        self._headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

    # -- helpers -------------------------------------------------------------

    def _url(self, path: str) -> str:
        org = self.config.org_id
        return f"{self.config.base_url}/organizations/{org}{path}"

    def _request(
        self, method: str, path: str, json_body: Optional[dict] = None
    ) -> dict[str, Any]:
        url = self._url(path)
        resp = requests.request(method, url, headers=self._headers, json=json_body)
        resp.raise_for_status()
        return resp.json()

    # -- session lifecycle ---------------------------------------------------

    def create_session(
        self,
        prompt: str,
        title: Optional[str] = None,
        repos: Optional[list[str]] = None,
        playbook_id: Optional[str] = None,
        structured_output_schema: Optional[dict] = None,
        max_acu_limit: Optional[int] = None,
        tags: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Create a new Devin session.

        Returns the raw API response dict containing session_id, url, status.
        """
        body: dict[str, Any] = {"prompt": prompt}
        if title:
            body["title"] = title
        if repos or self.config.repos:
            body["repos"] = repos or self.config.repos
        if playbook_id:
            body["playbook_id"] = playbook_id
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema
        if max_acu_limit or self.config.max_acu_limit:
            body["max_acu_limit"] = max_acu_limit or self.config.max_acu_limit
        if tags:
            body["tags"] = tags

        logger.info("Creating Devin session: %s", title or prompt[:80])
        return self._request("POST", "/sessions", body)

    def get_session(self, session_id: str) -> dict[str, Any]:
        """Get current session state."""
        return self._request("GET", f"/sessions/{session_id}")

    def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        """Send a message to a running session."""
        return self._request(
            "POST", f"/sessions/{session_id}/messages", {"message": message}
        )

    def get_messages(self, session_id: str) -> list[dict[str, Any]]:
        """Retrieve all messages from a session."""
        resp = self._request("GET", f"/sessions/{session_id}/messages")
        return resp.get("items", [])

    def get_attachments(self, session_id: str) -> list[dict[str, Any]]:
        """Retrieve attachments from a session."""
        resp = self._request("GET", f"/sessions/{session_id}/attachments")
        return resp.get("items", [])

    def terminate_session(self, session_id: str) -> dict[str, Any]:
        """Terminate a running session."""
        return self._request("POST", f"/sessions/{session_id}/terminate")

    # -- polling -------------------------------------------------------------

    def is_settled(self, session_data: dict[str, Any]) -> bool:
        """Check whether a session has reached a terminal/settled state."""
        status = session_data.get("status", "")
        detail = session_data.get("status_detail", "")
        if status in SETTLED_STATUSES:
            return True
        if status == "running" and detail in SETTLED_DETAILS:
            return True
        return False

    def wait_for_completion(
        self,
        session_id: str,
        timeout: Optional[int] = None,
        poll_interval: Optional[int] = None,
        on_poll: Optional[callable] = None,
    ) -> SessionResult:
        """Poll a session until it reaches a settled state.

        Args:
            session_id: The session to monitor.
            timeout: Max seconds to wait (default from config).
            poll_interval: Seconds between polls (default from config).
            on_poll: Optional callback invoked with session data each poll.

        Returns:
            SessionResult with final status and any structured output.

        Raises:
            TimeoutError: If the session does not settle within the timeout.
        """
        timeout = timeout or self.config.timeout
        interval = poll_interval or self.config.poll_interval
        deadline = time.time() + timeout

        logger.info("Waiting for session %s (timeout=%ds)", session_id, timeout)

        while time.time() < deadline:
            data = self.get_session(session_id)
            if on_poll:
                on_poll(data)

            if self.is_settled(data):
                return self._build_result(data)

            time.sleep(interval)

        raise TimeoutError(
            f"Session {session_id} did not settle within {timeout}s"
        )

    def _build_result(self, data: dict[str, Any]) -> SessionResult:
        """Convert raw session data to a SessionResult."""
        return SessionResult(
            session_id=data.get("session_id", ""),
            status=data.get("status", ""),
            status_detail=data.get("status_detail", ""),
            url=data.get("url", ""),
            structured_output=data.get("structured_output"),
        )

    # -- batch operations ----------------------------------------------------

    def create_and_wait(
        self,
        prompt: str,
        title: Optional[str] = None,
        repos: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        structured_output_schema: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> SessionResult:
        """Create a session, wait for it to complete, and return the result."""
        resp = self.create_session(
            prompt=prompt,
            title=title,
            repos=repos,
            tags=tags,
            structured_output_schema=structured_output_schema,
        )
        session_id = resp["session_id"]
        logger.info("Session created: %s (%s)", session_id, resp.get("url", ""))
        return self.wait_for_completion(session_id, timeout=timeout)
