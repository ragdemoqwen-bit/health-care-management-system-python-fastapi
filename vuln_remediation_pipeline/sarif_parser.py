"""
SARIF Parser Module

Parses CodeQL SARIF v2.1.0 reports and extracts structured vulnerability data.
Handles rule definitions, result locations, code flows, and related locations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Location:
    """A physical location in source code."""

    uri: str
    start_line: int
    start_column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    @classmethod
    def from_sarif(cls, physical_location: dict) -> Location:
        artifact = physical_location.get("artifactLocation", {})
        region = physical_location.get("region", {})
        return cls(
            uri=artifact.get("uri", ""),
            start_line=region.get("startLine", 0),
            start_column=region.get("startColumn", 1),
            end_line=region.get("endLine"),
            end_column=region.get("endColumn"),
        )

    def __str__(self) -> str:
        loc = f"{self.uri}:{self.start_line}"
        if self.end_line and self.end_line != self.start_line:
            loc += f"-{self.end_line}"
        return loc


@dataclass
class CodeFlowStep:
    """A single step in a taint-tracking code flow."""

    location: Location
    message: str

    @classmethod
    def from_sarif(cls, thread_flow_location: dict) -> CodeFlowStep:
        loc_data = thread_flow_location.get("location", {})
        phys = loc_data.get("physicalLocation", {})
        msg = loc_data.get("message", {}).get("text", "")
        return cls(location=Location.from_sarif(phys), message=msg)


@dataclass
class Rule:
    """A CodeQL rule definition."""

    rule_id: str
    name: str
    short_description: str
    full_description: str
    level: str  # "error", "warning", "note"
    security_severity: float
    cwe_tags: list[str] = field(default_factory=list)
    help_uri: str = ""

    @classmethod
    def from_sarif(cls, rule_data: dict) -> Rule:
        props = rule_data.get("properties", {})
        tags = props.get("tags", [])
        cwe_tags = [t for t in tags if t.startswith("external/cwe/")]
        severity_str = props.get("security-severity", "0.0")
        return cls(
            rule_id=rule_data.get("id", ""),
            name=rule_data.get("name", ""),
            short_description=rule_data.get("shortDescription", {}).get("text", ""),
            full_description=rule_data.get("fullDescription", {}).get("text", ""),
            level=rule_data.get("defaultConfiguration", {}).get("level", "warning"),
            security_severity=float(severity_str),
            cwe_tags=cwe_tags,
            help_uri=rule_data.get("helpUri", ""),
        )


@dataclass
class Vulnerability:
    """A single vulnerability finding from a SARIF report."""

    rule: Rule
    level: str
    message: str
    primary_location: Location
    related_locations: list[Location] = field(default_factory=list)
    code_flow_steps: list[CodeFlowStep] = field(default_factory=list)
    fingerprint: str = ""

    @property
    def severity_score(self) -> float:
        """Numeric score for sorting. Higher = more severe."""
        return self.rule.security_severity

    @property
    def severity_label(self) -> str:
        score = self.severity_score
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"

    @property
    def cwe_ids(self) -> list[str]:
        """Extract CWE IDs like 'CWE-089' from tags."""
        ids = []
        for tag in self.rule.cwe_tags:
            # "external/cwe/cwe-089" -> "CWE-089"
            parts = tag.split("/")
            if len(parts) >= 3:
                ids.append(parts[-1].upper())
        return ids

    def summary(self) -> str:
        cwe = ", ".join(self.cwe_ids) if self.cwe_ids else "N/A"
        return (
            f"[{self.severity_label}] {self.rule.rule_id} "
            f"({cwe}) at {self.primary_location}"
        )


@dataclass
class SARIFReport:
    """Parsed SARIF report containing tool info and vulnerability results."""

    schema_version: str
    tool_name: str
    tool_version: str
    rules: dict[str, Rule]
    vulnerabilities: list[Vulnerability]

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.level == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.level == "warning")

    def by_severity(self, descending: bool = True) -> list[Vulnerability]:
        """Return vulnerabilities sorted by security-severity score."""
        return sorted(
            self.vulnerabilities,
            key=lambda v: v.severity_score,
            reverse=descending,
        )

    def by_rule(self) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by rule ID."""
        grouped: dict[str, list[Vulnerability]] = {}
        for v in self.vulnerabilities:
            grouped.setdefault(v.rule.rule_id, []).append(v)
        return grouped

    def deduplicate(self) -> list[Vulnerability]:
        """Return unique vulnerabilities grouped by rule for batch fixing.

        When multiple results share the same rule_id, they are consolidated
        into a single entry (the first occurrence) so Devin can fix the entire
        class of issues in one session.  The returned list is sorted by
        descending severity.
        """
        seen_rules: set[str] = set()
        unique: list[Vulnerability] = []
        for v in self.by_severity():
            if v.rule.rule_id not in seen_rules:
                seen_rules.add(v.rule.rule_id)
                unique.append(v)
        return unique


def parse_sarif(source: str | Path) -> SARIFReport:
    """Parse a SARIF JSON file or string into a SARIFReport.

    Args:
        source: File path or raw JSON string.

    Returns:
        Parsed SARIFReport object.

    Raises:
        ValueError: If the SARIF data is malformed or unsupported.
        FileNotFoundError: If the source path does not exist.
    """
    if isinstance(source, Path) or (
        isinstance(source, str) and not source.lstrip().startswith("{")
    ):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"SARIF file not found: {path}")
        raw = path.read_text(encoding="utf-8")
    else:
        raw = source

    data = json.loads(raw)

    version = data.get("version", "")
    if not version.startswith("2.1"):
        raise ValueError(f"Unsupported SARIF version: {version}")

    runs = data.get("runs", [])
    if not runs:
        raise ValueError("SARIF report contains no runs")

    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})

    # Parse rules
    rules: dict[str, Rule] = {}
    for rule_data in driver.get("rules", []):
        rule = Rule.from_sarif(rule_data)
        rules[rule.rule_id] = rule

    # Parse results
    vulnerabilities: list[Vulnerability] = []
    for result in run.get("results", []):
        rule_id = result.get("ruleId", "")
        rule = rules.get(rule_id)
        if rule is None:
            # Build a minimal rule from the result itself
            rule = Rule(
                rule_id=rule_id,
                name=rule_id,
                short_description=rule_id,
                full_description="",
                level=result.get("level", "warning"),
                security_severity=0.0,
            )
            rules[rule_id] = rule

        # Primary location
        locations = result.get("locations", [])
        if locations:
            phys = locations[0].get("physicalLocation", {})
            primary = Location.from_sarif(phys)
        else:
            primary = Location(uri="unknown", start_line=0)

        # Related locations
        related = []
        for rl in result.get("relatedLocations", []):
            phys = rl.get("physicalLocation", {})
            related.append(Location.from_sarif(phys))

        # Code flows
        steps: list[CodeFlowStep] = []
        for cf in result.get("codeFlows", []):
            for tf in cf.get("threadFlows", []):
                for tfl in tf.get("locations", []):
                    steps.append(CodeFlowStep.from_sarif(tfl))

        # Fingerprint
        fps = result.get("fingerprints", {})
        fingerprint = fps.get("0", "")

        vulnerabilities.append(
            Vulnerability(
                rule=rule,
                level=result.get("level", rule.level),
                message=result.get("message", {}).get("text", ""),
                primary_location=primary,
                related_locations=related,
                code_flow_steps=steps,
                fingerprint=fingerprint,
            )
        )

    return SARIFReport(
        schema_version=version,
        tool_name=driver.get("name", "unknown"),
        tool_version=driver.get("semanticVersion", "unknown"),
        rules=rules,
        vulnerabilities=vulnerabilities,
    )
