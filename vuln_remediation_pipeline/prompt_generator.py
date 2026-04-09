"""
Prompt Generator Module

Builds detailed, context-rich prompts for Devin sessions to fix each
vulnerability class.  Prompts include:
  - Vulnerability description and CWE reference
  - Affected file(s) and line numbers
  - Concrete remediation guidance per rule type
  - Test-case generation instructions
  - PR creation instructions
"""

from __future__ import annotations

from typing import Optional

from .prioritizer import PrioritizedVulnerability
from .sarif_parser import Vulnerability


# ---------------------------------------------------------------------------
# Rule-specific remediation guidance
# ---------------------------------------------------------------------------

_REMEDIATION_HINTS: dict[str, str] = {
    "py/sql-injection": (
        "Replace raw string concatenation / f-string SQL queries with "
        "parameterised queries using SQLAlchemy's `text()` with bound "
        "parameters, or use the ORM query builder.  Never interpolate "
        "user input directly into SQL strings."
    ),
    "py/hardcoded-credentials": (
        "Move all secrets (passwords, API keys, JWT secrets) to environment "
        "variables.  Use `os.environ` or a settings library like Pydantic "
        "Settings / python-dotenv.  Remove the hard-coded values from the "
        "source and add them to a `.env.example` with placeholder values."
    ),
    "py/sensitive-data-exposure": (
        "Exclude sensitive fields (SSN, internal notes, passwords) from API "
        "response schemas.  Use a separate response model that only includes "
        "safe fields.  If the data is needed internally, keep it in a "
        "private/internal schema that is never returned to the client."
    ),
    "py/missing-authorization": (
        "Add proper authorization checks to the endpoint.  Ensure that the "
        "`current_user` dependency is declared as a *function parameter* "
        "(not a local variable) so FastAPI actually invokes it.  Also "
        "verify role-based access (e.g. only admins can delete)."
    ),
    "py/broken-access-control": (
        "Ensure that `Depends(get_current_user)` is passed as a function "
        "parameter, not assigned as a local variable inside the route body. "
        "When it is a local variable the dependency is never executed and "
        "the endpoint is unprotected.  Add role checks where appropriate."
    ),
    "py/insecure-deserialization": (
        "Never use `pickle.loads()` or `yaml.load()` with untrusted input. "
        "Use `json.loads()` or `yaml.safe_load()` instead."
    ),
    "py/path-traversal": (
        "Validate and sanitise file paths.  Use `pathlib.Path.resolve()` "
        "and ensure the resolved path is still under the expected base "
        "directory.  Reject paths containing `..` or absolute paths from "
        "user input."
    ),
    "py/command-injection": (
        "Avoid `os.system()` and `subprocess.run(shell=True)`.  Use "
        "`subprocess.run()` with a list of arguments and `shell=False`.  "
        "Validate and sanitise all user-supplied values before passing "
        "them to subprocesses."
    ),
    "py/weak-crypto": (
        "Replace weak algorithms (MD5, SHA-1 for security purposes, DES) "
        "with strong alternatives (SHA-256+, bcrypt/argon2 for passwords, "
        "AES-256 for encryption)."
    ),
    "py/insecure-jwt": (
        "Use a strong, randomly generated secret for JWT signing.  Set "
        "appropriate expiration times.  Use RS256 instead of HS256 when "
        "possible.  Validate all claims on verification."
    ),
    "py/missing-rate-limiting": (
        "Add rate limiting to authentication and sensitive endpoints using "
        "a middleware like `slowapi` or a custom solution with Redis.  "
        "Return HTTP 429 when limits are exceeded."
    ),
    "py/log-injection": (
        "Sanitise user input before including it in log messages.  Strip "
        "or escape newlines and control characters to prevent log forging."
    ),
}


def _get_remediation_hint(rule_id: str) -> str:
    """Return rule-specific remediation guidance, or a generic hint."""
    hint = _REMEDIATION_HINTS.get(rule_id)
    if hint:
        return hint
    # Generic fallback
    return (
        "Analyse the vulnerability described above and apply the "
        "industry-standard fix for this class of issue.  Follow OWASP "
        "guidelines and the language/framework best practices."
    )


# ---------------------------------------------------------------------------
# Location formatting
# ---------------------------------------------------------------------------


def _format_locations(vulns: list[Vulnerability]) -> str:
    """Format a list of vulnerability locations for the prompt."""
    lines = []
    for i, v in enumerate(vulns, 1):
        loc = v.primary_location
        lines.append(f"  {i}. {loc.uri}:{loc.start_line} - {v.message}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_prompt(
    item: PrioritizedVulnerability,
    repo_name: str,
    extra_context: Optional[str] = None,
) -> str:
    """Generate a comprehensive Devin session prompt for a vulnerability.

    Args:
        item: Prioritized vulnerability with all related locations.
        repo_name: Repository in owner/repo format.
        extra_context: Additional instructions to append.

    Returns:
        A multi-section prompt string.
    """
    v = item.vulnerability
    rule = v.rule
    all_locs = item.all_locations_for_rule
    cwe = ", ".join(v.cwe_ids) if v.cwe_ids else "N/A"

    sections = [
        f"# Security Vulnerability Fix: {rule.rule_id}",
        "",
        f"**Repository:** {repo_name}",
        f"**Rule:** {rule.rule_id} - {rule.short_description}",
        f"**Severity:** {v.severity_label} (score {v.severity_score:.1f})",
        f"**CWE:** {cwe}",
        f"**Level:** {v.level}",
        "",
        "## Description",
        "",
        rule.full_description or rule.short_description,
        "",
        "## Affected Locations",
        "",
        _format_locations(all_locs),
        "",
        "## Remediation Guidance",
        "",
        _get_remediation_hint(rule.rule_id),
        "",
        "## Requirements",
        "",
        "1. **Fix the vulnerability** in ALL affected locations listed above.",
        "2. **Write test cases** that validate the fix:",
        "   - A test proving the vulnerability is fixed (e.g. malicious input is rejected/sanitised).",
        "   - A test proving normal functionality still works after the fix.",
        "3. **Create a pull request** with:",
        f"   - Branch name: `fix/{rule.rule_id.replace('/', '-')}`",
        f"   - Title: `fix: {rule.short_description}`",
        f"   - Description referencing {cwe} and explaining the fix.",
        "4. **Do not break existing tests.**  Run any existing test suite and confirm it passes.",
        "",
    ]

    if rule.help_uri:
        sections.extend(["## Reference", "", rule.help_uri, ""])

    if extra_context:
        sections.extend(["## Additional Context", "", extra_context, ""])

    return "\n".join(sections)


def generate_structured_output_schema() -> dict:
    """Return a JSON schema for Devin's structured output.

    This lets us extract machine-readable results from each session.
    """
    return {
        "type": "object",
        "properties": {
            "fixed": {
                "type": "boolean",
                "description": "Whether the vulnerability was successfully fixed.",
            },
            "pr_url": {
                "type": "string",
                "description": "URL of the pull request created for the fix.",
            },
            "files_changed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of files modified.",
            },
            "test_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of test files created or modified.",
            },
            "summary": {
                "type": "string",
                "description": "Brief summary of what was done.",
            },
        },
        "required": ["fixed", "pr_url", "summary"],
    }
