"""Tests for the human-readable output (src/xacct/render.py).

Run them:            pytest tests/test_render.py -v
See the real output: xacct lint --policy examples/policies/bad-permissions.json
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from xacct import render
from xacct.lint import Finding, Severity
from xacct.render import FIXES, fix_for, render_lint, render_verify, use_color
from xacct.verify import CheckResult

HIGH_A = Finding("XA002", Severity.HIGH, "trust.json", "#0", "trusts a whole account")
HIGH_B = Finding("XA003", Severity.HIGH, "trust.json", "#0", "no ExternalId")
MED = Finding("XA015", Severity.MEDIUM, "perms.json", "Push", "write on *")
LOW = Finding("XA005", Severity.LOW, "trust.json", "-", "long session")


# --- lint ------------------------------------------------------------------------------


def test_every_lint_rule_has_a_fix() -> None:
    source = (Path(render.__file__).parent / "lint.py").read_text()
    rules = set(re.findall(r'"(XA\d{3})"', source))
    assert rules, "no rule ids found in lint.py"
    assert rules <= FIXES.keys(), f"missing fixes: {sorted(rules - FIXES.keys())}"


def test_access_analyzer_rules_get_generic_fix() -> None:
    assert "Access Analyzer" in fix_for("AA:PASS_ROLE_WITH_STAR_IN_RESOURCE")
    assert fix_for("XA999") == ""


def test_clean_lint_says_pass_first() -> None:
    assert render_lint([], 2, Severity.HIGH) == "✓ PASS — no problems in 2 policies\n"
    assert "in 1 policy\n" in render_lint([], 1, Severity.HIGH)


def test_failing_lint_verdict_first_then_grouped_by_document() -> None:
    out = render_lint([MED, HIGH_A, HIGH_B, LOW], 2, Severity.HIGH)
    lines = out.splitlines()
    assert lines[0] == "✗ FAIL — 2 high, 1 medium, 1 low in 2 policies"
    # each document title appears once, not once per finding
    assert out.count("trust.json") == 1 and out.count("perms.json") == 1
    # worst document first, worst finding first inside it
    assert out.index("trust.json") < out.index("perms.json")
    trust_block = out[out.index("trust.json") : out.index("perms.json")]
    assert trust_block.index("HIGH") < trust_block.index("LOW")


def test_same_rule_same_statement_shares_one_fix() -> None:
    a = Finding("XA010", Severity.HIGH, "p.json", "TooWide", "action 's3:*' is too wide")
    b = Finding("XA010", Severity.HIGH, "p.json", "TooWide", "action 'ecr:*' is too wide")
    out = render_lint([a, b], 1, Severity.HIGH)
    assert out.count("Fix: ") == 1
    assert "action 's3:*' is too wide\n           action 'ecr:*' is too wide" in out


def test_each_finding_has_fix_and_rule_last() -> None:
    out = render_lint([HIGH_A], 1, Severity.HIGH)
    assert "Fix: " + FIXES["XA002"] in out
    assert out.rstrip().endswith("(XA002 · statement #0)")


def test_document_level_finding_has_no_statement() -> None:
    assert "(XA005)" in render_lint([LOW], 1, Severity.HIGH)


def test_findings_below_threshold_pass_with_warnings() -> None:
    assert render_lint([MED], 1, Severity.HIGH).startswith("! PASS with warnings — 1 medium")
    assert render_lint([HIGH_A], 1, None).startswith("! PASS with warnings")  # --fail-on never


def test_no_color_codes_unless_asked() -> None:
    assert "\033[" not in render_lint([HIGH_A], 1, Severity.HIGH)
    colored = render_lint([HIGH_A], 1, Severity.HIGH, color=True)
    assert "\033[31" in colored and "\033[0m" in colored


# --- verify ----------------------------------------------------------------------------


def trust(name: str, ok: bool = True, detail: str = "arn:aws:sts::1:assumed-role/x/y") -> Any:
    return CheckResult("trust", name, ok, detail)


def perm(name: str, ok: bool = True, detail: str = "allowed") -> Any:
    return CheckResult("permissions", name, ok, detail)


def test_verify_all_pass_hides_permission_lines() -> None:
    results = [
        trust("no ExternalId is refused"),
        trust("correct ExternalId is accepted"),
        perm("allowed: s3:PutObject on arn:aws:s3:::b/x"),
        perm("denied: iam:CreateUser on *", detail="explicitDeny"),
    ]
    out = render_verify(results)
    assert out.splitlines()[0] == "✓ PASS — 4 of 4 checks"
    assert "Who can get in  2/2 ✓" in out
    assert "Without ExternalId → refused" in out  # plain label
    assert "s3:PutObject" not in out  # passing permissions are summarized
    assert "(2 passed; --details lists them)" in out
    assert "assumed-role" not in out  # ARNs only with --details


def test_verify_details_lists_everything() -> None:
    out = render_verify(
        [trust("correct ExternalId is accepted"), perm("allowed: s3:X")], details=True
    )
    assert "Should be allowed: s3:X" in out and "assumed-role" in out
    assert "--details lists them" not in out


def test_verify_failure_shows_what_aws_answered() -> None:
    results = [
        trust("correct ExternalId is accepted", ok=False, detail="AccessDenied"),
        perm("denied: cloudtrail:StopLogging on *", ok=False, detail="allowed"),
        perm("allowed: s3:GetObject on x"),
    ]
    out = render_verify(results)
    assert out.splitlines()[0] == "✗ FAIL — 2 of 3 checks failed"
    assert "Who can get in  0/1 ✗" in out
    assert "What the role can do  1/2 ✗" in out
    assert "✗ Should be denied: cloudtrail:StopLogging on *\n      AWS answered: allowed" in out
    assert "(1 passed; --details lists them)" in out


def test_unknown_check_name_shown_as_is() -> None:
    assert "something new" in render_verify([trust("something new")])


# --- color detection -----------------------------------------------------------------


class Tty:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


def test_use_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(Tty(True)) is True  # type: ignore[arg-type]
    assert use_color(Tty(False)) is False  # type: ignore[arg-type]
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color(Tty(True)) is False  # type: ignore[arg-type]
