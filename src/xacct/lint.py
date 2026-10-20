"""Static checks for CI/CD role policies: trust policies and permission policies.

Documents come from JSON files, a Terraform plan (``terraform show -json``) or
a live role. The rules are aimed at one question: can this role be assumed by
someone it should not, or do more than deploy what it was built to deploy?
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any

from xacct.policy import PolicyError, Statement, action_matches, parse_statements

log = logging.getLogger(__name__)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.upper()]
        except KeyError:
            raise ValueError(f"unknown severity {text!r} (low, medium, high)") from None


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    document: str
    sid: str
    message: str

    def to_dict(self) -> dict[str, str]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass(frozen=True)
class Document:
    """One policy to lint. ``kind`` is "trust" or "permissions"."""

    name: str
    kind: str
    body: str | Mapping[str, Any]
    role_account: str | None = None
    max_session_duration: int | None = None


GITHUB_OIDC = "token.actions.githubusercontent.com"
ACCOUNT_IN_ARN = re.compile(r"^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):")
MAX_SESSION_SECONDS = 3600

# Known IAM privilege-escalation actions: each lets the caller grant itself (or
# a principal it controls) more permissions than it was given.
ESCALATION_ACTIONS = (
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary",
    "iam:PutGroupPolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateLoginProfile",
)

READ_PREFIXES = ("describe", "list", "get", "batchget", "head", "lookup", "search", "view")

# Actions that only work with Resource "*" (no resource-level permissions).
RESOURCELESS_ACTIONS = (
    "ecr:GetAuthorizationToken",
    "cloudformation:ValidateTemplate",
    "cloudfront:CreateInvalidation",
    "sts:GetCallerIdentity",
    "ecs:RegisterTaskDefinition",
    "ecs:DeregisterTaskDefinition",
)


# --- Trust policies -----------------------------------------------------------------


def lint_trust(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, sev: Severity, st: Statement, msg: str) -> None:
        findings.append(Finding(rule, sev, doc.name, st.sid, msg))

    for st in parse_statements(doc.body):
        if not st.allows:
            continue
        if st.not_principal:
            add("XA001", Severity.HIGH, st, "Allow with NotPrincipal trusts everyone not listed")
            continue
        anyone = "*" in st.principals or "*" in st.principals.get("AWS", ())
        if anyone and not _has_any(
            st, "aws:PrincipalArn", "aws:PrincipalOrgID", "aws:PrincipalAccount"
        ):
            add("XA001", Severity.HIGH, st, 'Principal "*" lets any AWS account assume the role')
            continue

        if any(action_matches(a, "sts:AssumeRole") for a in st.actions):
            findings.extend(_lint_aws_trust(doc, st))
        if any(action_matches(a, "sts:AssumeRoleWithWebIdentity") for a in st.actions):
            findings.extend(_lint_oidc_trust(doc, st))

    if doc.max_session_duration and doc.max_session_duration > MAX_SESSION_SECONDS:
        findings.append(
            Finding(
                "XA005",
                Severity.LOW,
                doc.name,
                "-",
                f"max_session_duration is {doc.max_session_duration}s; a deploy needs "
                f"<= {MAX_SESSION_SECONDS}s (and role chaining caps it at 1 hour anyway)",
            )
        )
    return findings


def _lint_aws_trust(doc: Document, st: Statement) -> Iterator[Finding]:
    aws = st.principals.get("AWS", ())
    if not aws:
        return
    roots = [p for p in aws if p.endswith(":root") or re.fullmatch(r"\d{12}", p)]
    if roots and not _has_any(st, "aws:PrincipalArn"):
        yield Finding(
            "XA002",
            Severity.HIGH,
            doc.name,
            st.sid,
            "trusts a whole account without an aws:PrincipalArn condition: any principal "
            "there with sts:AssumeRole permission can assume this role",
        )

    principal_accounts = {_account_of(p) for p in aws} - {None}
    cross = doc.role_account is None or any(a != doc.role_account for a in principal_accounts)
    if cross and not st.has_condition("sts:ExternalId"):
        where = "role account unknown, assuming cross-account" if doc.role_account is None else ""
        yield Finding(
            "XA003",
            Severity.HIGH,
            doc.name,
            st.sid,
            "cross-account sts:AssumeRole without an sts:ExternalId condition"
            + (f" ({where})" if where else ""),
        )


def _lint_oidc_trust(doc: Document, st: Statement) -> Iterator[Finding]:
    federated = st.principals.get("Federated", ())
    if not any(p.endswith(GITHUB_OIDC) for p in federated):
        return
    subs = [v for _, values in st.condition(f"{GITHUB_OIDC}:sub") for v in values]
    if not subs:
        yield Finding(
            "XA004",
            Severity.HIGH,
            doc.name,
            st.sid,
            "GitHub OIDC trust without a `sub` condition: any repository on GitHub can assume it",
        )
    for sub in subs:
        if sub == "*" or not re.match(r"^repo:[^/*?]+/[^/*?:]+:", sub):
            yield Finding(
                "XA004",
                Severity.HIGH,
                doc.name,
                st.sid,
                f"`sub` {sub!r} is not limited to one repository",
            )
        elif "*" in sub or "?" in sub:
            yield Finding(
                "XA006",
                Severity.MEDIUM,
                doc.name,
                st.sid,
                f"`sub` {sub!r} has a wildcard: every matching branch, tag or PR can deploy",
            )
    if not st.has_condition(f"{GITHUB_OIDC}:aud"):
        yield Finding(
            "XA007", Severity.MEDIUM, doc.name, st.sid, "GitHub OIDC trust without an `aud` check"
        )


# --- Permission policies -----------------------------------------------------------


def lint_permissions(doc: Document) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule: str, sev: Severity, st: Statement, msg: str) -> None:
        findings.append(Finding(rule, sev, doc.name, st.sid, msg))

    for st in parse_statements(doc.body):
        if not st.allows:
            continue  # explicit denies only ever remove permissions
        if st.not_actions or st.not_resources:
            add("XA011", Severity.HIGH, st, "Allow with NotAction/NotResource grants by exclusion")
        star_resource = "*" in st.resources

        for action in st.actions:
            if action == "*" or action.endswith(":*"):
                add("XA010", Severity.HIGH, st, f"action {action!r} grants a whole service or more")
                continue
            if "*" in action or "?" in action:
                add("XA016", Severity.LOW, st, f"action {action!r} uses a wildcard")
            if star_resource and not _is_read(action) and not _resourceless(action):
                add(
                    "XA015",
                    Severity.MEDIUM,
                    st,
                    f'write action {action!r} on Resource "*": scope it to ARNs',
                )

        escalation = sorted({e for e in ESCALATION_ACTIONS if st.grants(e)})
        if escalation and not any(a == "*" or a.endswith(":*") for a in st.actions):
            sev = Severity.HIGH if star_resource else Severity.MEDIUM
            add("XA012", sev, st, "privilege escalation actions: " + ", ".join(escalation))

        if st.grants("iam:PassRole"):
            if star_resource:
                add("XA013", Severity.HIGH, st, 'iam:PassRole on Resource "*" can pass any role')
            elif not st.has_condition("iam:PassedToService"):
                add(
                    "XA013",
                    Severity.MEDIUM,
                    st,
                    "iam:PassRole without an iam:PassedToService condition",
                )

        if st.grants("sts:AssumeRole") and star_resource:
            add("XA014", Severity.HIGH, st, 'sts:AssumeRole on Resource "*" can hop to any role')
    return findings


def lint(docs: Iterable[Document]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in docs:
        try:
            if doc.kind == "trust":
                findings.extend(lint_trust(doc))
            else:
                findings.extend(lint_permissions(doc))
        except PolicyError as exc:
            findings.append(Finding("XA000", Severity.HIGH, doc.name, "-", f"unreadable: {exc}"))
    return sorted(findings, key=lambda f: (-f.severity, f.document, f.rule))


# --- Sources ------------------------------------------------------------------------


def documents_from_plan(plan: Mapping[str, Any], account_id: str | None = None) -> list[Document]:
    """IAM documents in ``terraform show -json <plan>`` output.

    Reads planned values of aws_iam_role (trust), aws_iam_role_policy and
    aws_iam_policy (permissions). Values not known until apply are skipped.
    """
    if account_id is None:
        accounts = set(_caller_accounts(plan.get("prior_state", {}).get("values", {})))
        account_id = accounts.pop() if len(accounts) == 1 else None

    docs: list[Document] = []
    root = plan.get("planned_values", {}).get("root_module", {})
    for res in _walk_resources(root):
        values = res.get("values") or {}
        address = str(res.get("address", res.get("type", "?")))
        rtype = res.get("type")
        if rtype == "aws_iam_role":
            body = values.get("assume_role_policy")
            if body:
                docs.append(
                    Document(
                        address,
                        "trust",
                        body,
                        account_id,
                        values.get("max_session_duration"),
                    )
                )
            else:
                log.warning("%s: trust policy not known until apply, skipped", address)
        elif rtype in ("aws_iam_role_policy", "aws_iam_policy"):
            body = values.get("policy")
            if body:
                docs.append(Document(address, "permissions", body))
            else:
                log.warning("%s: policy not known until apply, skipped", address)
    return docs


def documents_from_role(iam: Any, role_name: str) -> list[Document]:
    """Trust + every inline and attached policy of a live role."""
    role = iam.get_role(RoleName=role_name)["Role"]
    account = _account_of(role["Arn"])
    docs = [
        Document(
            f"{role_name} (trust)",
            "trust",
            role["AssumeRolePolicyDocument"],
            account,
            role.get("MaxSessionDuration"),
        )
    ]
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        for name in page["PolicyNames"]:
            body = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            docs.append(Document(f"{role_name}/{name}", "permissions", body))
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
        for att in page["AttachedPolicies"]:
            arn = att["PolicyArn"]
            version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            body = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]
            docs.append(Document(arn, "permissions", body["Document"]))
    return docs


def access_analyzer_findings(client: Any, docs: Iterable[Document]) -> list[Finding]:
    """Run IAM Access Analyzer ValidatePolicy on each document (AWS-side grammar + checks)."""
    severity = {
        "ERROR": Severity.HIGH,
        "SECURITY_WARNING": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "SUGGESTION": Severity.LOW,
    }
    out: list[Finding] = []
    for doc in docs:
        body = doc.body if isinstance(doc.body, str) else json.dumps(doc.body)
        kwargs: dict[str, str] = {"policyDocument": body, "policyType": "IDENTITY_POLICY"}
        if doc.kind == "trust":
            kwargs["policyType"] = "RESOURCE_POLICY"
            kwargs["validatePolicyResourceType"] = "AWS::IAM::AssumeRolePolicyDocument"
        for page in client.get_paginator("validate_policy").paginate(**kwargs):
            for f in page["findings"]:
                out.append(
                    Finding(
                        f"AA:{f['issueCode']}",
                        severity.get(f["findingType"], Severity.LOW),
                        doc.name,
                        "-",
                        f["findingDetails"],
                    )
                )
    return out


# --- helpers -------------------------------------------------------------------------


def _has_any(st: Statement, *keys: str) -> bool:
    return any(st.has_condition(k) for k in keys)


def _account_of(principal: str) -> str | None:
    if re.fullmatch(r"\d{12}", principal):
        return principal
    m = ACCOUNT_IN_ARN.match(principal)
    return m.group(1) if m else None


def _is_read(action: str) -> bool:
    name = action.split(":", 1)[-1].lower()
    return name.startswith(READ_PREFIXES)


def _resourceless(action: str) -> bool:
    return any(action_matches(action, r) for r in RESOURCELESS_ACTIONS)


def _walk_resources(module: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk_resources(child)


def _caller_accounts(values: Mapping[str, Any]) -> Iterator[str]:
    for res in _walk_resources(values.get("root_module", {})):
        if res.get("type") == "aws_caller_identity":
            acc = (res.get("values") or {}).get("account_id")
            if acc:
                yield str(acc)
