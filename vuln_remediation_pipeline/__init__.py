"""
Vulnerability Remediation Pipeline

A generic pipeline that reads CodeQL SARIF reports, prioritizes vulnerabilities
by severity, and resolves them one-by-one using the Devin API -- creating a
child session per vulnerability, generating test cases, and opening a PR for
each fix.
"""

__version__ = "1.0.0"
