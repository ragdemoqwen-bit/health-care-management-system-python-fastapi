"""Tests for the prompt generator module."""

from __future__ import annotations

from pathlib import Path

from vuln_remediation_pipeline.prioritizer import prioritize
from vuln_remediation_pipeline.prompt_generator import (
    generate_prompt,
    generate_structured_output_schema,
)
from vuln_remediation_pipeline.sarif_parser import parse_sarif

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_SARIF = FIXTURES_DIR / "minimal_sarif.json"


def _get_items():
    report = parse_sarif(MINIMAL_SARIF)
    return prioritize(report)


class TestGeneratePrompt:
    def test_contains_rule_id(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert items[0].rule_id in prompt

    def test_contains_repository(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert "owner/repo" in prompt

    def test_contains_severity(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert items[0].severity_label in prompt

    def test_contains_cwe(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        # SQL injection should have CWE-089
        assert "CWE" in prompt

    def test_contains_remediation_guidance(self):
        items = _get_items()
        # SQL injection item
        sql_item = next(it for it in items if it.rule_id == "py/sql-injection")
        prompt = generate_prompt(sql_item, repo_name="owner/repo")
        assert "parameterised" in prompt or "parameterized" in prompt

    def test_contains_affected_locations(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert "Affected Locations" in prompt

    def test_contains_requirements(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert "Fix the vulnerability" in prompt
        assert "Write test cases" in prompt
        assert "Create a pull request" in prompt

    def test_extra_context_included(self):
        items = _get_items()
        prompt = generate_prompt(
            items[0],
            repo_name="owner/repo",
            extra_context="Use pytest for all tests.",
        )
        assert "Use pytest for all tests." in prompt

    def test_extra_context_omitted_when_none(self):
        items = _get_items()
        prompt = generate_prompt(items[0], repo_name="owner/repo")
        assert "Additional Context" not in prompt

    def test_help_uri_included(self):
        items = _get_items()
        sql_item = next(it for it in items if it.rule_id == "py/sql-injection")
        prompt = generate_prompt(sql_item, repo_name="owner/repo")
        assert "Reference" in prompt
        assert "codeql.github.com" in prompt


class TestStructuredOutputSchema:
    def test_schema_has_required_fields(self):
        schema = generate_structured_output_schema()
        assert schema["type"] == "object"
        props = schema["properties"]
        assert "fixed" in props
        assert "pr_url" in props
        assert "summary" in props
        assert set(schema["required"]) == {"fixed", "pr_url", "summary"}

    def test_schema_optional_fields(self):
        schema = generate_structured_output_schema()
        props = schema["properties"]
        assert "files_changed" in props
        assert "test_files" in props
