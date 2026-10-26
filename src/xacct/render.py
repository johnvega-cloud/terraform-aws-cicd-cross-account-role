"""Human-readable output for ``xacct lint`` and ``xacct verify``.

Layout rules: the verdict comes first, problems are grouped by document,
each problem says how to fix it, the rule code goes last, and what passed is
summarized (``--details`` lists it). Colors only on a terminal, never when
NO_COLOR is set. Machines keep ``--output json`` (lint) and ``--report`` (verify).

Try it (from the repository root, with the venv active):

    # lint: a failing policy (FAIL, exit 3), then a clean trust policy (PASS, exit 0)
    xacct lint --policy examples/policies/bad-permissions.json; echo "exit=$?"
    xacct lint --trust examples/policies/deploy-trust.json --account-id 222222222222

    # lint: same findings but --fail-on never -> "PASS with warnings", exit 0
    xacct lint --policy examples/policies/bad-permissions.json --fail-on never

    # the same findings for a machine
    xacct lint --policy examples/policies/bad-permissions.json --output json

    # verify needs a deployed e2e/aws (see e2e/aws/README.md):
    xacct verify --tf-output e2e/aws/out.json --region us-east-1
    xacct verify --tf-output e2e/aws/out.json --region us-east-1 --details

    # unit tests for this module (--no-cov: the 90% coverage gate is for the full suite)
    pytest tests/test_render.py -v --no-cov
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TextIO

from xacct.lint import Finding, Severity
from xacct.verify import CheckResult

# How to fix each lint rule, in one line. tests/test_render.py fails if a rule
# in lint.py has no entry here.
FIXES: dict[str, str] = {
    "XA000": "Make it a valid IAM policy: a JSON object with a Statement list.",
    "XA001": "Name the exact principal, or add an aws:PrincipalArn / aws:PrincipalOrgID condition.",
    "XA002": 'Add the condition  "ArnEquals": {"aws:PrincipalArn": "<exact pipeline role ARN>"}',
    "XA003": 'Add the condition  "StringEquals": {"sts:ExternalId": "<value from SSM>"}',
    "XA004": 'Pin one repository:  "...githubusercontent.com:sub": '
    '"repo:<owner>/<repo>:environment:<env>"',
    "XA005": "Set max_session_duration to 3600; a deploy rarely needs more.",
    "XA006": "Replace the wildcard with one environment or branch, "
    "e.g. repo:<owner>/<repo>:environment:prod",
    "XA007": 'Add the condition  "StringEquals": '
    '{"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}',
    "XA010": "List the exact actions the deploy needs (e.g. ecr:PutImage), not a whole service.",
    "XA011": "Rewrite it as an Allow with an explicit Action and Resource list.",
    "XA012": "Remove these IAM actions, or scope them to exact role ARNs behind a "
    "permissions boundary.",
    "XA013": 'Scope Resource to the exact role ARNs and add  "StringEquals": '
    '{"iam:PassedToService": "<service>"}',
    "XA014": "Scope Resource to the exact role ARNs the pipeline may assume.",
    "XA015": 'Replace Resource "*" with the ARNs this action should touch.',
    "XA016": "List the exact actions instead of a wildcard pattern.",
}
AA_FIX = "See the IAM Access Analyzer policy check reference for this issue code."

_COLORS = {"red": "31", "yellow": "33", "green": "32", "dim": "2", "bold": "1"}
_SEV_STYLE = {
    Severity.HIGH: ("HIGH", "red", "✗"),
    Severity.MEDIUM: ("MEDIUM", "yellow", "!"),
    Severity.LOW: ("LOW", "dim", "·"),
}

# verify check name -> plain sentence. Unknown names are shown as they are.
_TRUST_LABELS = {
    "reach pipeline role": "You can reach the pipeline role",
    "no ExternalId is refused": "Without ExternalId → refused",
    "wrong ExternalId is refused": "Wrong ExternalId → refused",
    "correct ExternalId is accepted": "Correct ExternalId → accepted",
    "non-pipeline principal is refused": "Someone else with the right ExternalId → refused",
}
_GROUP_TITLES = {"trust": "Who can get in", "permissions": "What the role can do"}


def _label(name: str) -> str:
    """Plain sentence for a check: trust names from the table, permission names
    ("allowed: X" / "denied: X") as what was expected."""
    if name in _TRUST_LABELS:
        return _TRUST_LABELS[name]
    for prefix, says in (("allowed: ", "Should be allowed: "), ("denied: ", "Should be denied: ")):
        if name.startswith(prefix):
            return says + name[len(prefix) :]
    return name


def use_color(stream: TextIO) -> bool:
    """Color only on a real terminal, and never when NO_COLOR is set (no-color.org)."""
    return stream.isatty() and not os.environ.get("NO_COLOR")


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(_COLORS[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"


def fix_for(rule: str) -> str:
    return AA_FIX if rule.startswith("AA:") else FIXES.get(rule, "")


# --- lint ------------------------------------------------------------------------------


def render_lint(
    findings: Sequence[Finding],
    doc_count: int,
    threshold: Severity | None,
    *,
    color: bool = False,
) -> str:
    """Verdict, then findings grouped by document, worst first.

    ``threshold`` is the --fail-on severity (None for "never"): it decides
    whether the verdict says FAIL or PASS with warnings.
    """
    paint = _Painter(color)
    counts = {sev: sum(f.severity is sev for f in findings) for sev in Severity}
    breakdown = ", ".join(
        f"{n} {sev.name.lower()}" for sev, n in sorted(counts.items(), reverse=True) if n
    )
    docs = f"{doc_count} {'policy' if doc_count == 1 else 'policies'}"
    failing = threshold is not None and any(f.severity >= threshold for f in findings)

    if not findings:
        head = paint(f"✓ PASS — no problems in {docs}", "green", "bold")
    elif failing:
        head = paint(f"✗ FAIL — {breakdown} in {docs}", "red", "bold")
    else:
        head = paint(f"! PASS with warnings — {breakdown} in {docs}", "yellow", "bold")
    lines = [head]

    by_doc: dict[str, list[Finding]] = {}
    for f in findings:
        by_doc.setdefault(f.document, []).append(f)
    # Worst document first, so the first problem you read is the one to fix first.
    ordered = sorted(by_doc.items(), key=lambda kv: (-max(f.severity for f in kv[1]), kv[0]))
    for doc, items in ordered:
        lines += ["", paint(doc, "bold")]
        # One entry per (rule, statement): s3:* and ecr:* in the same statement
        # share one fix instead of repeating it.
        entries: dict[tuple[str, str, Severity], list[str]] = {}
        for f in sorted(items, key=lambda x: -x.severity):
            entries.setdefault((f.rule, f.sid, f.severity), []).append(f.message)
        for (rule, sid, severity), messages in entries.items():
            label, style, mark = _SEV_STYLE[severity]
            lines.append(f"  {paint(f'{mark} {label:<6}', style)} {messages[0]}")
            lines += [f"           {m}" for m in messages[1:]]
            fix = fix_for(rule)
            if fix:
                lines.append(f"           Fix: {fix}")
            where = rule + ("" if sid in ("-", "") else f" · statement {sid}")
            lines.append(paint(f"           ({where})", "dim"))
    return "\n".join(lines) + "\n"


# --- verify ----------------------------------------------------------------------------


def render_verify(
    results: Sequence[CheckResult], *, details: bool = False, color: bool = False
) -> str:
    """Verdict, then one block per group. Trust checks are always listed (they are
    few and are the point of the tool); passing permission checks only with
    ``details``. Failures always show what AWS answered."""
    paint = _Painter(color)
    total = len(results)
    passed = sum(r.passed for r in results)
    if passed == total:
        head = paint(f"✓ PASS — {passed} of {total} checks", "green", "bold")
    else:
        head = paint(f"✗ FAIL — {total - passed} of {total} checks failed", "red", "bold")
    lines = [head]

    groups: dict[str, list[CheckResult]] = {}
    for r in results:
        groups.setdefault(r.group, []).append(r)
    for group, items in groups.items():
        ok = sum(r.passed for r in items)
        mark = paint("✓", "green") if ok == len(items) else paint("✗", "red")
        title = _GROUP_TITLES.get(group, group)
        lines += ["", f"{paint(title, 'bold')}  {ok}/{len(items)} {mark}"]
        show_all = details or group == "trust"
        hidden = 0
        for r in items:
            if r.passed and not show_all:
                hidden += 1
                continue
            label = _label(r.name)
            if r.passed:
                lines.append(f"  {paint('✓', 'green')} {label}")
                if details:
                    lines.append(paint(f"      {r.detail}", "dim"))
            else:
                lines.append(f"  {paint('✗', 'red')} {label}")
                lines.append(f"      AWS answered: {r.detail}")
        if hidden:
            lines.append(paint(f"  ({hidden} passed; --details lists them)", "dim"))
    return "\n".join(lines) + "\n"
