"""Tests for the SARIF parser module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_remediation_pipeline.sarif_parser import (
    CodeFlowStep,
    Location,
    Rule,
    SARIFReport,
    Vulnerability,
    parse_sarif,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_SARIF = FIXTURES_DIR / "minimal_sarif.json"


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


class TestLocation:
    def test_from_sarif(self):
        phys = {
            "artifactLocation": {"uri": "app/main.py"},
            "region": {"startLine": 10, "startColumn": 5, "endLine": 12, "endColumn": 20},
        }
        loc = Location.from_sarif(phys)
        assert loc.uri == "app/main.py"
        assert loc.start_line == 10
        assert loc.start_column == 5
        assert loc.end_line == 12
        assert loc.end_column == 20

    def test_from_sarif_defaults(self):
        phys = {"artifactLocation": {"uri": "file.py"}, "region": {"startLine": 1}}
        loc = Location.from_sarif(phys)
        assert loc.start_column == 1
        assert loc.end_line is None

    def test_str_single_line(self):
        loc = Location(uri="a.py", start_line=5)
        assert str(loc) == "a.py:5"

    def test_str_multi_line(self):
        loc = Location(uri="a.py", start_line=5, end_line=10)
        assert str(loc) == "a.py:5-10"

    def test_str_same_line(self):
        loc = Location(uri="a.py", start_line=5, end_line=5)
        assert str(loc) == "a.py:5"


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class TestRule:
    def test_from_sarif(self):
        data = {
            "id": "py/sql-injection",
            "name": "SqlInjection",
            "shortDescription": {"text": "SQL injection"},
            "fullDescription": {"text": "Full description of SQL injection."},
            "defaultConfiguration": {"level": "error"},
            "properties": {
                "tags": ["security", "external/cwe/cwe-089"],
                "security-severity": "9.8",
            },
            "helpUri": "https://example.com",
        }
        rule = Rule.from_sarif(data)
        assert rule.rule_id == "py/sql-injection"
        assert rule.name == "SqlInjection"
        assert rule.level == "error"
        assert rule.security_severity == 9.8
        assert rule.cwe_tags == ["external/cwe/cwe-089"]
        assert rule.help_uri == "https://example.com"

    def test_from_sarif_no_severity(self):
        data = {
            "id": "test/rule",
            "name": "Test",
            "shortDescription": {"text": "test"},
            "fullDescription": {"text": "test full"},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": []},
        }
        rule = Rule.from_sarif(data)
        assert rule.security_severity == 0.0
        assert rule.cwe_tags == []


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------


class TestVulnerability:
    def _make_vuln(self, severity: float = 9.8, level: str = "error") -> Vulnerability:
        rule = Rule(
            rule_id="py/sql-injection",
            name="SqlInjection",
            short_description="SQL injection",
            full_description="Full desc",
            level=level,
            security_severity=severity,
            cwe_tags=["external/cwe/cwe-089"],
        )
        return Vulnerability(
            rule=rule,
            level=level,
            message="Test message",
            primary_location=Location(uri="app.py", start_line=10),
        )

    def test_severity_labels(self):
        assert self._make_vuln(9.8).severity_label == "Critical"
        assert self._make_vuln(7.5).severity_label == "High"
        assert self._make_vuln(5.0).severity_label == "Medium"
        assert self._make_vuln(2.0).severity_label == "Low"

    def test_cwe_ids(self):
        v = self._make_vuln()
        assert v.cwe_ids == ["CWE-089"]

    def test_summary(self):
        v = self._make_vuln()
        s = v.summary()
        assert "py/sql-injection" in s
        assert "CWE-089" in s
        assert "Critical" in s


# ---------------------------------------------------------------------------
# parse_sarif
# ---------------------------------------------------------------------------


class TestParseSarif:
    def test_parse_file(self):
        report = parse_sarif(MINIMAL_SARIF)
        assert isinstance(report, SARIFReport)
        assert report.tool_name == "CodeQL"
        assert report.schema_version == "2.1.0"

    def test_parse_string(self):
        raw = MINIMAL_SARIF.read_text()
        report = parse_sarif(raw)
        assert report.total_count == 4

    def test_rule_count(self):
        report = parse_sarif(MINIMAL_SARIF)
        assert len(report.rules) == 3

    def test_vulnerability_count(self):
        report = parse_sarif(MINIMAL_SARIF)
        assert report.total_count == 4
        assert report.error_count == 3
        assert report.warning_count == 1

    def test_by_severity(self):
        report = parse_sarif(MINIMAL_SARIF)
        ordered = report.by_severity()
        scores = [v.severity_score for v in ordered]
        assert scores == sorted(scores, reverse=True)

    def test_by_rule(self):
        report = parse_sarif(MINIMAL_SARIF)
        grouped = report.by_rule()
        assert len(grouped["py/hardcoded-credentials"]) == 2
        assert len(grouped["py/sql-injection"]) == 1

    def test_deduplicate(self):
        report = parse_sarif(MINIMAL_SARIF)
        unique = report.deduplicate()
        rule_ids = [v.rule.rule_id for v in unique]
        assert len(set(rule_ids)) == len(rule_ids)
        assert len(unique) == 3  # 3 unique rules

    def test_code_flows_parsed(self):
        report = parse_sarif(MINIMAL_SARIF)
        sql_vulns = [v for v in report.vulnerabilities if v.rule.rule_id == "py/sql-injection"]
        assert len(sql_vulns) == 1
        assert len(sql_vulns[0].code_flow_steps) == 2

    def test_related_locations_parsed(self):
        report = parse_sarif(MINIMAL_SARIF)
        sql_vulns = [v for v in report.vulnerabilities if v.rule.rule_id == "py/sql-injection"]
        assert len(sql_vulns[0].related_locations) == 1

    def test_fingerprints_parsed(self):
        report = parse_sarif(MINIMAL_SARIF)
        fps = [v.fingerprint for v in report.vulnerabilities]
        assert "fp-sql-001" in fps

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_sarif("/nonexistent/file.sarif.json")

    def test_invalid_version(self):
        data = {"version": "1.0", "runs": []}
        with pytest.raises(ValueError, match="Unsupported SARIF version"):
            parse_sarif(json.dumps(data))

    def test_no_runs(self):
        data = {"version": "2.1.0", "runs": []}
        with pytest.raises(ValueError, match="no runs"):
            parse_sarif(json.dumps(data))

    def test_result_without_rule_definition(self):
        """Results referencing rules not in the driver should still parse."""
        data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Test", "rules": []}},
                "results": [{
                    "ruleId": "unknown/rule",
                    "level": "note",
                    "message": {"text": "something"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "x.py"},
                            "region": {"startLine": 1},
                        }
                    }],
                }],
            }],
        }
        report = parse_sarif(json.dumps(data))
        assert report.total_count == 1
        assert report.vulnerabilities[0].rule.rule_id == "unknown/rule"
