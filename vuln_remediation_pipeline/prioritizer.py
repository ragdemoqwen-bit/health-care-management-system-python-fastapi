"""
Vulnerability Prioritizer Module

Determines the order in which vulnerabilities should be remediated based on
security-severity score, level, and optional custom weighting rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .sarif_parser import SARIFReport, Vulnerability


class Strategy(str, Enum):
    """Prioritization strategies."""

    SEVERITY_DESC = "severity_desc"  # Highest severity first (default)
    SEVERITY_ASC = "severity_asc"  # Lowest severity first (quick wins)
    BY_FILE = "by_file"  # Group by file to minimise context switches
    BY_CWE = "by_cwe"  # Group by CWE category


@dataclass
class PrioritizedVulnerability:
    """A vulnerability annotated with its priority rank and batch key."""

    rank: int
    batch_key: str  # rule_id used to group same-class issues
    vulnerability: Vulnerability
    all_locations_for_rule: list[Vulnerability] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return self.vulnerability.rule.rule_id

    @property
    def severity_label(self) -> str:
        return self.vulnerability.severity_label


def prioritize(
    report: SARIFReport,
    strategy: Strategy = Strategy.SEVERITY_DESC,
    deduplicate_by_rule: bool = True,
    exclude_rules: Optional[list[str]] = None,
    min_severity: float = 0.0,
) -> list[PrioritizedVulnerability]:
    """Prioritize and optionally deduplicate vulnerabilities for remediation.

    Args:
        report: Parsed SARIF report.
        strategy: Ordering strategy.
        deduplicate_by_rule: If True, group same-rule findings into one item.
        exclude_rules: Rule IDs to skip (e.g. rules already addressed).
        min_severity: Minimum security-severity score to include.

    Returns:
        Ordered list of PrioritizedVulnerability items.
    """
    excluded = set(exclude_rules or [])

    # Filter
    candidates = [
        v
        for v in report.vulnerabilities
        if v.rule.rule_id not in excluded and v.severity_score >= min_severity
    ]

    # Sort according to strategy
    if strategy == Strategy.SEVERITY_DESC:
        candidates.sort(key=lambda v: v.severity_score, reverse=True)
    elif strategy == Strategy.SEVERITY_ASC:
        candidates.sort(key=lambda v: v.severity_score)
    elif strategy == Strategy.BY_FILE:
        candidates.sort(
            key=lambda v: (v.primary_location.uri, -v.severity_score)
        )
    elif strategy == Strategy.BY_CWE:
        candidates.sort(
            key=lambda v: (
                v.cwe_ids[0] if v.cwe_ids else "zzz",
                -v.severity_score,
            )
        )

    # Group by rule
    rule_groups: dict[str, list[Vulnerability]] = {}
    for v in candidates:
        rule_groups.setdefault(v.rule.rule_id, []).append(v)

    # Build output
    result: list[PrioritizedVulnerability] = []
    seen_rules: set[str] = set()
    rank = 1

    for v in candidates:
        if deduplicate_by_rule and v.rule.rule_id in seen_rules:
            continue
        seen_rules.add(v.rule.rule_id)

        result.append(
            PrioritizedVulnerability(
                rank=rank,
                batch_key=v.rule.rule_id,
                vulnerability=v,
                all_locations_for_rule=rule_groups.get(v.rule.rule_id, [v]),
            )
        )
        rank += 1

    return result


def format_priority_table(items: list[PrioritizedVulnerability]) -> str:
    """Render a human-readable priority table."""
    lines = [
        f"{'#':<4} {'Severity':<10} {'Score':<6} {'Rule':<30} {'Location':<45} {'Count':<5}",
        "-" * 100,
    ]
    for item in items:
        lines.append(
            f"{item.rank:<4} "
            f"{item.severity_label:<10} "
            f"{item.vulnerability.severity_score:<6.1f} "
            f"{item.rule_id:<30} "
            f"{str(item.vulnerability.primary_location):<45} "
            f"{len(item.all_locations_for_rule):<5}"
        )
    return "\n".join(lines)
