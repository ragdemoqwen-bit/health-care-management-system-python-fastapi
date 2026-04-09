"""Tests for the pipeline orchestrator module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from vuln_remediation_pipeline.devin_client import DevinClient, DevinClientConfig, SessionResult
from vuln_remediation_pipeline.pipeline import (
    PipelineConfig,
    PipelineReport,
    RemediationPipeline,
    RemediationResult,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_SARIF = FIXTURES_DIR / "minimal_sarif.json"


def _make_mock_client() -> DevinClient:
    """Create a mock DevinClient that returns successful results."""
    client = MagicMock(spec=DevinClient)
    client.create_session.return_value = {
        "session_id": "devin-test-123",
        "url": "https://app.devin.ai/sessions/devin-test-123",
        "status": "running",
    }
    client.wait_for_completion.return_value = SessionResult(
        session_id="devin-test-123",
        status="exit",
        url="https://app.devin.ai/sessions/devin-test-123",
        structured_output={
            "fixed": True,
            "pr_url": "https://github.com/owner/repo/pull/1",
            "summary": "Fixed the vulnerability",
            "files_changed": ["app/main.py"],
            "test_files": ["tests/test_fix.py"],
        },
    )
    return client


class TestPipelineConfig:
    def test_from_dict(self):
        data = {
            "sarif_path": "report.sarif.json",
            "repo": "owner/repo",
            "strategy": "severity_desc",
            "dry_run": True,
        }
        config = PipelineConfig.from_dict(data)
        assert config.sarif_path == "report.sarif.json"
        assert config.repo == "owner/repo"
        assert config.dry_run is True

    def test_from_dict_defaults(self):
        data = {"sarif_path": "report.sarif.json", "repo": "owner/repo"}
        config = PipelineConfig.from_dict(data)
        assert config.deduplicate_by_rule is True
        assert config.min_severity == 0.0
        assert config.session_timeout == 1800
        assert config.dry_run is False


class TestRemediationResult:
    def test_succeeded(self):
        r = RemediationResult(
            rank=1,
            rule_id="py/sql-injection",
            severity_label="Critical",
            severity_score=9.8,
            affected_count=1,
            status="success",
        )
        assert r.succeeded is True

    def test_not_succeeded(self):
        r = RemediationResult(
            rank=1,
            rule_id="py/sql-injection",
            severity_label="Critical",
            severity_score=9.8,
            affected_count=1,
            status="failed",
        )
        assert r.succeeded is False


class TestPipelineReport:
    def _make_report(self) -> PipelineReport:
        return PipelineReport(
            sarif_file="test.sarif.json",
            repo="owner/repo",
            total_vulnerabilities=4,
            unique_rules=3,
            strategy="severity_desc",
            results=[
                RemediationResult(
                    rank=1, rule_id="py/sql-injection",
                    severity_label="Critical", severity_score=9.8,
                    affected_count=1, status="success",
                    pr_url="https://github.com/pr/1",
                ),
                RemediationResult(
                    rank=2, rule_id="py/hardcoded-credentials",
                    severity_label="Critical", severity_score=9.1,
                    affected_count=2, status="failed",
                    error="Session timed out",
                ),
                RemediationResult(
                    rank=3, rule_id="py/log-injection",
                    severity_label="Medium", severity_score=4.3,
                    affected_count=1, status="skipped",
                ),
            ],
            started_at=1000.0,
            finished_at=2000.0,
        )

    def test_total_fixed(self):
        report = self._make_report()
        assert report.total_fixed == 1

    def test_total_failed(self):
        report = self._make_report()
        assert report.total_failed == 1

    def test_total_skipped(self):
        report = self._make_report()
        assert report.total_skipped == 1

    def test_duration(self):
        report = self._make_report()
        assert report.duration_seconds == 1000.0

    def test_to_dict(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["total_fixed"] == 1
        assert d["total_failed"] == 1
        assert len(d["results"]) == 3

    def test_to_markdown(self):
        report = self._make_report()
        md = report.to_markdown()
        assert "# Vulnerability Remediation Report" in md
        assert "py/sql-injection" in md
        assert "py/hardcoded-credentials" in md
        assert "Errors" in md  # should have error section
        assert "Session timed out" in md


class TestRemediationPipeline:
    def test_dry_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=True,
                output_dir=tmpdir,
            )
            pipeline = RemediationPipeline(config)
            report = pipeline.run()

            assert report.total_vulnerabilities == 4
            assert report.unique_rules == 3
            assert all(r.status == "skipped" for r in report.results)
            # Check output files created
            assert (Path(tmpdir) / "remediation-report.json").exists()
            assert (Path(tmpdir) / "remediation-report.md").exists()

    def test_dry_run_with_min_severity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=True,
                min_severity=5.0,
                output_dir=tmpdir,
            )
            pipeline = RemediationPipeline(config)
            report = pipeline.run()

            assert report.unique_rules == 2  # only sql-injection and hardcoded-credentials

    def test_dry_run_with_exclusions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=True,
                exclude_rules=["py/sql-injection"],
                output_dir=tmpdir,
            )
            pipeline = RemediationPipeline(config)
            report = pipeline.run()

            rule_ids = [r.rule_id for r in report.results]
            assert "py/sql-injection" not in rule_ids

    def test_live_run_with_mock_client(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=False,
                output_dir=tmpdir,
            )
            client = _make_mock_client()
            pipeline = RemediationPipeline(config, client=client)
            report = pipeline.run()

            assert report.total_vulnerabilities == 4
            assert report.unique_rules == 3
            assert client.create_session.call_count == 3
            assert client.wait_for_completion.call_count == 3
            assert all(r.status == "success" for r in report.results)
            assert all(r.pr_url for r in report.results)

    def test_live_run_handles_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=False,
                output_dir=tmpdir,
            )
            client = _make_mock_client()
            # Make the second call fail
            client.wait_for_completion.side_effect = [
                SessionResult(
                    session_id="s1", status="exit",
                    structured_output={"fixed": True, "pr_url": "https://pr/1", "summary": "ok"},
                ),
                Exception("API error"),
                SessionResult(
                    session_id="s3", status="exit",
                    structured_output={"fixed": True, "pr_url": "https://pr/3", "summary": "ok"},
                ),
            ]
            pipeline = RemediationPipeline(config, client=client)
            report = pipeline.run()

            statuses = [r.status for r in report.results]
            assert statuses.count("success") == 2
            assert statuses.count("failed") == 1

    def test_live_run_handles_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=False,
                output_dir=tmpdir,
            )
            client = _make_mock_client()
            client.wait_for_completion.side_effect = TimeoutError("timed out")

            pipeline = RemediationPipeline(config, client=client)
            report = pipeline.run()

            assert all(r.status == "timeout" for r in report.results)

    def test_output_json_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=True,
                output_dir=tmpdir,
            )
            pipeline = RemediationPipeline(config)
            pipeline.run()

            json_path = Path(tmpdir) / "remediation-report.json"
            data = json.loads(json_path.read_text())
            assert data["repo"] == "owner/repo"
            assert data["total_vulnerabilities"] == 4
            assert len(data["results"]) == 3

    def test_structured_output_not_fixed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = PipelineConfig(
                sarif_path=str(MINIMAL_SARIF),
                repo="owner/repo",
                dry_run=False,
                output_dir=tmpdir,
            )
            client = _make_mock_client()
            client.wait_for_completion.return_value = SessionResult(
                session_id="s1", status="exit",
                structured_output={"fixed": False, "pr_url": "", "summary": "Could not fix"},
            )
            pipeline = RemediationPipeline(config, client=client)
            report = pipeline.run()

            assert all(r.status == "failed" for r in report.results)
