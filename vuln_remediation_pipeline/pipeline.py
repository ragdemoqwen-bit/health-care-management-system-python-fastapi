"""
Pipeline Orchestrator Module

Main entry point that ties together SARIF parsing, prioritization, prompt
generation, and Devin session management into a sequential remediation
pipeline.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .devin_client import DevinClient, DevinClientConfig, SessionResult
from .prioritizer import (
    PrioritizedVulnerability,
    Strategy,
    format_priority_table,
    prioritize,
)
from .prompt_generator import generate_prompt, generate_structured_output_schema
from .sarif_parser import SARIFReport, parse_sarif

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline result types
# ---------------------------------------------------------------------------


@dataclass
class RemediationResult:
    """Outcome of remediating a single vulnerability class."""

    rank: int
    rule_id: str
    severity_label: str
    severity_score: float
    affected_count: int
    session_id: str = ""
    session_url: str = ""
    status: str = "pending"  # pending | running | success | failed | skipped | timeout
    pr_url: str = ""
    summary: str = ""
    error: str = ""
    duration_seconds: float = 0.0

    @property
    def succeeded(self) -> bool:
        return self.status == "success"


@dataclass
class PipelineReport:
    """Aggregated report of the entire pipeline run."""

    sarif_file: str
    repo: str
    total_vulnerabilities: int
    unique_rules: int
    strategy: str
    results: list[RemediationResult] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def total_fixed(self) -> int:
        return sum(1 for r in self.results if r.succeeded)

    @property
    def total_failed(self) -> int:
        return sum(1 for r in self.results if r.status == "failed")

    @property
    def total_skipped(self) -> int:
        return sum(1 for r in self.results if r.status == "skipped")

    @property
    def duration_seconds(self) -> float:
        if self.finished_at and self.started_at:
            return self.finished_at - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sarif_file": self.sarif_file,
            "repo": self.repo,
            "total_vulnerabilities": self.total_vulnerabilities,
            "unique_rules": self.unique_rules,
            "strategy": self.strategy,
            "total_fixed": self.total_fixed,
            "total_failed": self.total_failed,
            "total_skipped": self.total_skipped,
            "duration_seconds": round(self.duration_seconds, 1),
            "results": [
                {
                    "rank": r.rank,
                    "rule_id": r.rule_id,
                    "severity": r.severity_label,
                    "score": r.severity_score,
                    "affected_count": r.affected_count,
                    "status": r.status,
                    "pr_url": r.pr_url,
                    "session_url": r.session_url,
                    "summary": r.summary,
                    "error": r.error,
                    "duration_seconds": round(r.duration_seconds, 1),
                }
                for r in self.results
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Vulnerability Remediation Report",
            "",
            f"**Repository:** {self.repo}",
            f"**SARIF File:** {self.sarif_file}",
            f"**Strategy:** {self.strategy}",
            f"**Total Vulnerabilities:** {self.total_vulnerabilities}",
            f"**Unique Rules:** {self.unique_rules}",
            f"**Fixed:** {self.total_fixed} | **Failed:** {self.total_failed} | **Skipped:** {self.total_skipped}",
            f"**Duration:** {self.duration_seconds:.0f}s",
            "",
            "## Results",
            "",
            "| # | Rule | Severity | Score | Count | Status | PR |",
            "|---|------|----------|-------|-------|--------|----|",
        ]
        for r in self.results:
            pr_link = f"[PR]({r.pr_url})" if r.pr_url else "-"
            lines.append(
                f"| {r.rank} | `{r.rule_id}` | {r.severity_label} | {r.severity_score:.1f} "
                f"| {r.affected_count} | {r.status} | {pr_link} |"
            )

        # Details for failed items
        failed = [r for r in self.results if r.error]
        if failed:
            lines.extend(["", "## Errors", ""])
            for r in failed:
                lines.append(f"### {r.rule_id}")
                lines.append(f"```\n{r.error}\n```")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pipeline configuration
# ---------------------------------------------------------------------------


@dataclass
class PipelineConfig:
    """Configuration for a pipeline run."""

    sarif_path: str
    repo: str  # owner/repo
    strategy: Strategy = Strategy.SEVERITY_DESC
    deduplicate_by_rule: bool = True
    exclude_rules: Optional[list[str]] = None
    min_severity: float = 0.0
    session_timeout: int = 1800  # 30 min per session
    dry_run: bool = False
    output_dir: str = "."
    extra_context: Optional[str] = None
    tags: Optional[list[str]] = None
    max_acu_limit: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PipelineConfig:
        strategy = data.get("strategy", "severity_desc")
        return cls(
            sarif_path=data["sarif_path"],
            repo=data["repo"],
            strategy=Strategy(strategy),
            deduplicate_by_rule=data.get("deduplicate_by_rule", True),
            exclude_rules=data.get("exclude_rules"),
            min_severity=data.get("min_severity", 0.0),
            session_timeout=data.get("session_timeout", 1800),
            dry_run=data.get("dry_run", False),
            output_dir=data.get("output_dir", "."),
            extra_context=data.get("extra_context"),
            tags=data.get("tags"),
            max_acu_limit=data.get("max_acu_limit"),
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class RemediationPipeline:
    """Orchestrates end-to-end vulnerability remediation.

    Usage::

        config = PipelineConfig(sarif_path="report.sarif.json", repo="owner/repo")
        pipeline = RemediationPipeline(config)
        report = pipeline.run()
        print(report.to_markdown())
    """

    def __init__(
        self,
        config: PipelineConfig,
        client: Optional[DevinClient] = None,
    ) -> None:
        self.config = config
        self.client = client or DevinClient()

    # -- main entry ----------------------------------------------------------

    def run(self) -> PipelineReport:
        """Execute the full pipeline: parse -> prioritize -> remediate -> report."""
        report = self._init_report()
        report.started_at = time.time()

        # 1. Parse SARIF
        logger.info("Parsing SARIF file: %s", self.config.sarif_path)
        sarif = parse_sarif(self.config.sarif_path)
        report.total_vulnerabilities = sarif.total_count

        # 2. Prioritize
        items = prioritize(
            sarif,
            strategy=self.config.strategy,
            deduplicate_by_rule=self.config.deduplicate_by_rule,
            exclude_rules=self.config.exclude_rules,
            min_severity=self.config.min_severity,
        )
        report.unique_rules = len(items)

        logger.info(
            "Found %d vulnerabilities across %d unique rules",
            sarif.total_count,
            len(items),
        )
        logger.info("\n%s", format_priority_table(items))

        # 3. Remediate one-by-one
        for item in items:
            result = self._remediate(item)
            report.results.append(result)

            # Log progress
            done = len(report.results)
            total = len(items)
            logger.info(
                "[%d/%d] %s %s -> %s",
                done, total, item.rule_id,
                item.severity_label, result.status,
            )

        report.finished_at = time.time()

        # 4. Write outputs
        self._write_outputs(report)

        return report

    # -- remediation ---------------------------------------------------------

    def _remediate(self, item: PrioritizedVulnerability) -> RemediationResult:
        """Create a Devin session to fix one vulnerability class."""
        result = RemediationResult(
            rank=item.rank,
            rule_id=item.rule_id,
            severity_label=item.severity_label,
            severity_score=item.vulnerability.severity_score,
            affected_count=len(item.all_locations_for_rule),
        )

        if self.config.dry_run:
            result.status = "skipped"
            result.summary = "Dry run - session not created"
            return result

        prompt = generate_prompt(
            item,
            repo_name=self.config.repo,
            extra_context=self.config.extra_context,
        )

        start = time.time()
        try:
            result.status = "running"
            session_resp = self.client.create_session(
                prompt=prompt,
                title=f"Fix: {item.rule_id} ({item.severity_label})",
                repos=[self.config.repo],
                structured_output_schema=generate_structured_output_schema(),
                tags=self.config.tags or ["vuln-remediation"],
                max_acu_limit=self.config.max_acu_limit,
            )

            result.session_id = session_resp.get("session_id", "")
            result.session_url = session_resp.get("url", "")

            # Wait for completion
            session_result = self.client.wait_for_completion(
                session_id=result.session_id,
                timeout=self.config.session_timeout,
                on_poll=lambda data: logger.debug(
                    "  Session %s status: %s",
                    result.session_id, data.get("status"),
                ),
            )

            # Extract results
            if session_result.structured_output:
                so = session_result.structured_output
                result.pr_url = so.get("pr_url", "")
                result.summary = so.get("summary", "")
                if so.get("fixed"):
                    result.status = "success"
                else:
                    result.status = "failed"
                    result.error = so.get("summary", "Fix not applied")
            elif session_result.status == "exit":
                result.status = "success"
                result.summary = "Session completed"
            else:
                result.status = "failed"
                result.error = f"Session ended with status: {session_result.status}"

        except TimeoutError:
            result.status = "timeout"
            result.error = f"Session timed out after {self.config.session_timeout}s"
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception("Error remediating %s", item.rule_id)

        result.duration_seconds = time.time() - start
        return result

    # -- helpers -------------------------------------------------------------

    def _init_report(self) -> PipelineReport:
        return PipelineReport(
            sarif_file=self.config.sarif_path,
            repo=self.config.repo,
            total_vulnerabilities=0,
            unique_rules=0,
            strategy=self.config.strategy.value,
        )

    def _write_outputs(self, report: PipelineReport) -> None:
        """Write JSON and Markdown reports to disk."""
        out_dir = Path(self.config.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # JSON
        json_path = out_dir / "remediation-report.json"
        json_path.write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        logger.info("JSON report written to %s", json_path)

        # Markdown
        md_path = out_dir / "remediation-report.md"
        md_path.write_text(report.to_markdown(), encoding="utf-8")
        logger.info("Markdown report written to %s", md_path)
