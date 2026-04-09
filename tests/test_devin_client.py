"""Tests for the Devin API client module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vuln_remediation_pipeline.devin_client import (
    DevinClient,
    DevinClientConfig,
    SessionResult,
    SessionStatus,
)


def _make_client(**overrides) -> DevinClient:
    defaults = {
        "api_key": "test-key",
        "org_id": "test-org",
        "poll_interval": 0,  # no delay in tests
        "timeout": 5,
    }
    defaults.update(overrides)
    return DevinClient(DevinClientConfig(**defaults))


class TestDevinClientConfig:
    def test_from_env(self):
        env = {
            "DEVIN_API_KEY": "key123",
            "DEVIN_ORG_ID": "org456",
            "DEVIN_POLL_INTERVAL": "30",
            "DEVIN_TIMEOUT": "600",
        }
        with patch.dict("os.environ", env, clear=False):
            config = DevinClientConfig.from_env()
            assert config.api_key == "key123"
            assert config.org_id == "org456"
            assert config.poll_interval == 30
            assert config.timeout == 600

    def test_from_env_defaults(self):
        with patch.dict("os.environ", {}, clear=True):
            config = DevinClientConfig.from_env()
            assert config.api_key == ""
            assert config.poll_interval == 15
            assert config.timeout == 1800


class TestDevinClient:
    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    def test_create_session(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "session_id": "devin-123",
            "url": "https://app.devin.ai/sessions/devin-123",
            "status": "running",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client()
        result = client.create_session(prompt="Fix SQL injection")

        assert result["session_id"] == "devin-123"
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert "sessions" in call_args[0][1]

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    def test_create_session_with_options(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "devin-456", "status": "running"}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client()
        client.create_session(
            prompt="Fix it",
            title="Fix SQL Injection",
            repos=["owner/repo"],
            tags=["vuln-fix"],
        )

        body = mock_request.call_args[1]["json"]
        assert body["prompt"] == "Fix it"
        assert body["title"] == "Fix SQL Injection"
        assert body["repos"] == ["owner/repo"]
        assert body["tags"] == ["vuln-fix"]

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    def test_get_session(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "devin-123", "status": "running"}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client()
        result = client.get_session("devin-123")
        assert result["status"] == "running"

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    def test_send_message(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client()
        client.send_message("devin-123", "Please also add tests")
        body = mock_request.call_args[1]["json"]
        assert body["message"] == "Please also add tests"

    def test_is_settled_exit(self):
        client = _make_client()
        assert client.is_settled({"status": "exit"}) is True

    def test_is_settled_error(self):
        client = _make_client()
        assert client.is_settled({"status": "error"}) is True

    def test_is_settled_suspended(self):
        client = _make_client()
        assert client.is_settled({"status": "suspended"}) is True

    def test_is_settled_running(self):
        client = _make_client()
        assert client.is_settled({"status": "running"}) is False

    def test_is_settled_running_finished(self):
        client = _make_client()
        assert client.is_settled({"status": "running", "status_detail": "finished"}) is True

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    def test_wait_for_completion_immediate(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "session_id": "devin-123",
            "status": "exit",
            "url": "https://app.devin.ai/sessions/devin-123",
            "structured_output": {"fixed": True, "pr_url": "https://github.com/pr/1", "summary": "done"},
        }
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client()
        result = client.wait_for_completion("devin-123")
        assert isinstance(result, SessionResult)
        assert result.status == "exit"

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    @patch("vuln_remediation_pipeline.devin_client.time.sleep")
    def test_wait_for_completion_polls(self, mock_sleep, mock_request):
        responses = [
            {"session_id": "devin-123", "status": "running"},
            {"session_id": "devin-123", "status": "running"},
            {"session_id": "devin-123", "status": "exit", "url": ""},
        ]
        mock_resp = MagicMock()
        mock_resp.json.side_effect = responses
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client(timeout=100)
        result = client.wait_for_completion("devin-123")
        assert result.status == "exit"
        assert mock_sleep.call_count == 2

    @patch("vuln_remediation_pipeline.devin_client.requests.request")
    @patch("vuln_remediation_pipeline.devin_client.time.time")
    def test_wait_for_completion_timeout(self, mock_time, mock_request):
        # Simulate time passing beyond timeout
        mock_time.side_effect = [0, 0, 100]  # start, first check, past deadline
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "devin-123", "status": "running"}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp

        client = _make_client(timeout=5)
        with pytest.raises(TimeoutError):
            client.wait_for_completion("devin-123")


class TestSessionResult:
    def test_status_stored(self):
        r = SessionResult(session_id="x", status="exit")
        assert r.status == "exit"

    def test_defaults(self):
        r = SessionResult(session_id="x", status="exit")
        assert r.pr_url is None
        assert r.structured_output is None
        assert r.error_message is None

    def test_fields(self):
        r = SessionResult(
            session_id="devin-123",
            status="exit",
            url="https://example.com",
            pr_url="https://github.com/pr/1",
        )
        assert r.session_id == "devin-123"
        assert r.pr_url == "https://github.com/pr/1"
