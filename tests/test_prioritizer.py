"""Tests for the vulnerability prioritizer module."""

from __future__ import annotations

from pathlib import Path

from vuln_remediation_pipeline.prioritizer import (
    Strategy,
    format_priority_table,
    prioritize,
)
from vuln_remediation_pipeline.sarif_parser import parse_sarif

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_SARIF = FIXTURES_DIR / "minimal_sarif.json"


def _load_report():
    return parse_sarif(MINIMAL_SARIF)


class TestPrioritize:
    def test_severity_desc_order(self):
        report = _load_report()
        items = prioritize(report, strategy=Strategy.SEVERITY_DESC)
        scores = [it.vulnerability.severity_score for it in items]
        assert scores == sorted(scores, reverse=True)

    def test_severity_asc_order(self):
        report = _load_report()
        items = prioritize(report, strategy=Strategy.SEVERITY_ASC)
        scores = [it.vulnerability.severity_score for it in items]
        assert scores == sorted(scores)

    def test_deduplication_default(self):
        report = _load_report()
        items = prioritize(report)
        rule_ids = [it.rule_id for it in items]
        # py/hardcoded-credentials has 2 results but should appear once
        assert rule_ids.count("py/hardcoded-credentials") == 1
        assert len(items) == 3  # 3 unique rules

    def test_no_deduplication(self):
        report = _load_report()
        items = prioritize(report, deduplicate_by_rule=False)
        assert len(items) == 4  # all 4 results

    def test_exclude_rules(self):
        report = _load_report()
        items = prioritize(report, exclude_rules=["py/log-injection"])
        rule_ids = [it.rule_id for it in items]
        assert "py/log-injection" not in rule_ids

    def test_min_severity_filter(self):
        report = _load_report()
        items = prioritize(report, min_severity=5.0)
        for it in items:
            assert it.vulnerability.severity_score >= 5.0
        # py/log-injection has score 4.3 so should be excluded
        rule_ids = [it.rule_id for it in items]
        assert "py/log-injection" not in rule_ids

    def test_rank_assignment(self):
        report = _load_report()
        items = prioritize(report)
        ranks = [it.rank for it in items]
        assert ranks == list(range(1, len(items) + 1))

    def test_all_locations_for_rule(self):
        report = _load_report()
        items = prioritize(report)
        cred_item = next(it for it in items if it.rule_id == "py/hardcoded-credentials")
        assert len(cred_item.all_locations_for_rule) == 2

    def test_by_file_strategy(self):
        report = _load_report()
        items = prioritize(report, strategy=Strategy.BY_FILE, deduplicate_by_rule=False)
        uris = [it.vulnerability.primary_location.uri for it in items]
        # Should be grouped by file
        assert len(items) == 4

    def test_by_cwe_strategy(self):
        report = _load_report()
        items = prioritize(report, strategy=Strategy.BY_CWE)
        assert len(items) == 3


class TestFormatPriorityTable:
    def test_output_contains_header(self):
        report = _load_report()
        items = prioritize(report)
        table = format_priority_table(items)
        assert "#" in table
        assert "Severity" in table
        assert "Rule" in table

    def test_output_contains_rules(self):
        report = _load_report()
        items = prioritize(report)
        table = format_priority_table(items)
        assert "py/sql-injection" in table
        assert "py/hardcoded-credentials" in table
