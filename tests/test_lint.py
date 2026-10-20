from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import boto3
import pytest

from tests.conftest import PIPELINE_ARN, TARGET, TOOLING
from xacct.lint import (
    Document,
    Finding,
    Severity,
    access_analyzer_findings,
    documents_from_plan,
    documents_from_role,
    lint,
)

GH = "token.actions.githubusercontent.com"
OIDC_ARN = f"arn:aws:iam::{TOOLING}:oidc-provider/{GH}"


def doc(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def rules(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.rule, f.severity.name) for f in findings}


def good_deploy_trust() -> dict[str, Any]:
    """What modules/deploy-role renders."""
    return doc(
        [
            {
                "Sid": "PipelineRoleWithExternalId",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{TOOLING}:root"},
                "Condition": {
                    "ArnEquals": {"aws:PrincipalArn": PIPELINE_ARN},
                    "StringEquals": {"sts:ExternalId": "x" * 32},
                },
            }
        ]
    )


def trust(body: dict[str, Any], account: str | None = TARGET, max_s: int | None = None) -> Any:
    return lint([Document("t", "trust", body, account, max_s)])


def perms(*statements: dict[str, Any]) -> Any:
    return lint([Document("p", "permissions", doc(list(statements)))])


# --- trust ---------------------------------------------------------------------------


def test_module_trust_policy_is_clean() -> None:
    assert trust(good_deploy_trust()) == []


def test_principal_star() -> None:
    body = doc([{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}])
    assert ("XA001", "HIGH") in rules(trust(body))


def test_principal_star_with_org_condition_is_not_xa001() -> None:
    body = doc(
        [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": "o-abc123def4", "sts:ExternalId": "x"}
                },
            }
        ]
    )
    assert "XA001" not in {r for r, _ in rules(trust(body))}


def test_not_principal() -> None:
    body = doc([{"Effect": "Allow", "NotPrincipal": {"AWS": "x"}, "Action": "sts:AssumeRole"}])
    assert rules(trust(body)) == {("XA001", "HIGH")}


def test_account_root_without_principal_arn() -> None:
    body = good_deploy_trust()
    del body["Statement"][0]["Condition"]["ArnEquals"]
    assert rules(trust(body)) == {("XA002", "HIGH")}


def test_bare_account_id_principal_counts_as_root() -> None:
    body = good_deploy_trust()
    body["Statement"][0]["Principal"] = {"AWS": TOOLING}
    del body["Statement"][0]["Condition"]["ArnEquals"]
    assert ("XA002", "HIGH") in rules(trust(body))


def test_cross_account_without_external_id() -> None:
    body = good_deploy_trust()
    del body["Statement"][0]["Condition"]["StringEquals"]
    assert rules(trust(body)) == {("XA003", "HIGH")}


def test_same_account_without_external_id_is_ok() -> None:
    body = good_deploy_trust()
    del body["Statement"][0]["Condition"]["StringEquals"]
    assert trust(body, account=TOOLING) == []


def test_unknown_account_is_treated_as_cross_account() -> None:
    body = good_deploy_trust()
    del body["Statement"][0]["Condition"]["StringEquals"]
    [f] = trust(body, account=None)
    assert f.rule == "XA003" and "unknown" in f.message


def test_deny_statements_are_ignored() -> None:
    body = doc([{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}])
    assert trust(body) == []


def test_long_session() -> None:
    assert rules(trust(good_deploy_trust(), max_s=43200)) == {("XA005", "LOW")}


def gh_trust(sub: Any = "repo:acme/app1:ref:refs/heads/main", aud: bool = True) -> dict[str, Any]:
    cond: dict[str, Any] = {}
    if aud:
        cond["StringEquals"] = {f"{GH}:aud": "sts.amazonaws.com"}
    if sub is not None:
        cond["StringLike"] = {f"{GH}:sub": sub}
    return doc(
        [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Principal": {"Federated": OIDC_ARN},
                "Condition": cond,
            }
        ]
    )


def test_github_oidc_pinned_is_clean() -> None:
    assert trust(gh_trust()) == []


@pytest.mark.parametrize("sub", ["*", "repo:acme/*", "repo:*", "repo:acme/*:ref:refs/heads/main"])
def test_github_sub_spanning_repos(sub: str) -> None:
    assert ("XA004", "HIGH") in rules(trust(gh_trust(sub)))


def test_github_without_sub() -> None:
    assert rules(trust(gh_trust(None))) == {("XA004", "HIGH")}


def test_github_wildcard_within_repo() -> None:
    assert rules(trust(gh_trust("repo:acme/app1:*"))) == {("XA006", "MEDIUM")}


def test_github_without_aud() -> None:
    assert rules(trust(gh_trust(aud=False))) == {("XA007", "MEDIUM")}


def test_other_federated_provider_not_checked_as_github() -> None:
    body = gh_trust(None)
    body["Statement"][0]["Principal"]["Federated"] = "cognito-identity.amazonaws.com"
    assert trust(body) == []


# --- permissions -------------------------------------------------------------------


def test_least_privilege_policy_is_clean() -> None:
    assert (
        perms(
            {
                "Sid": "Push",
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": "arn:aws:s3:::b/artifacts/*",
            },
            {
                "Sid": "Login",
                "Effect": "Allow",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {"Sid": "Read", "Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
            {
                "Sid": "Pass",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::1:role/app-task",
                "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}},
            },
        )
        == []
    )


@pytest.mark.parametrize("action", ["*", "s3:*", "iam:*"])
def test_service_wildcards(action: str) -> None:
    assert ("XA010", "HIGH") in rules(perms({"Effect": "Allow", "Action": action, "Resource": "*"}))


def test_not_action() -> None:
    found = rules(perms({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    assert ("XA011", "HIGH") in found


def test_escalation_on_star_is_high_and_on_arn_medium() -> None:
    star = perms({"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"})
    scoped = perms(
        {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "arn:aws:iam::1:role/app-*"}
    )
    assert ("XA012", "HIGH") in rules(star)
    assert ("XA012", "MEDIUM") in rules(scoped)


def test_partial_wildcard_reaches_escalation() -> None:
    found = perms({"Effect": "Allow", "Action": "iam:Attach*", "Resource": "arn:aws:iam::1:role/x"})
    assert {("XA012", "MEDIUM"), ("XA016", "LOW")} <= rules(found)
    assert "iam:AttachRolePolicy" in next(f.message for f in found if f.rule == "XA012")


def test_passrole() -> None:
    star = perms({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    no_cond = perms(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/x"}
    )
    assert ("XA013", "HIGH") in rules(star)
    assert rules(no_cond) == {("XA013", "MEDIUM")}


def test_assume_any_role() -> None:
    assert ("XA014", "HIGH") in rules(
        perms({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"})
    )


def test_write_on_star() -> None:
    assert rules(perms({"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"})) == {
        ("XA015", "MEDIUM")
    }


def test_explicit_deny_is_never_a_finding() -> None:
    assert perms({"Effect": "Deny", "Action": "*", "Resource": "*"}) == []


def test_unreadable_document_is_a_finding_not_a_crash() -> None:
    [f] = lint([Document("bad", "permissions", "{nope")])
    assert f.rule == "XA000" and f.severity is Severity.HIGH


def test_findings_sorted_by_severity() -> None:
    found = perms(
        {"Effect": "Allow", "Action": ["s3:Put*", "s3:DeleteObject"], "Resource": "*"},
    )
    assert [f.severity for f in found] == sorted((f.severity for f in found), reverse=True)


def test_severity_parse() -> None:
    assert Severity.parse("Medium") is Severity.MEDIUM
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("critical")


def test_finding_to_dict() -> None:
    f = Finding("XA010", Severity.HIGH, "d", "s", "m")
    assert f.to_dict()["severity"] == "HIGH"


# --- sources ---------------------------------------------------------------------------


def plan_json() -> dict[str, Any]:
    return {
        "prior_state": {
            "values": {
                "root_module": {
                    "child_modules": [
                        {
                            "resources": [
                                {
                                    "type": "aws_caller_identity",
                                    "values": {"account_id": TARGET},
                                }
                            ]
                        }
                    ]
                }
            }
        },
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "values": {}}
                ],
                "child_modules": [
                    {
                        "address": "module.deploy",
                        "resources": [
                            {
                                "address": "module.deploy.aws_iam_role.this",
                                "type": "aws_iam_role",
                                "values": {
                                    "assume_role_policy": json.dumps(good_deploy_trust()),
                                    "max_session_duration": 3600,
                                },
                            },
                            {
                                "address": "module.deploy.aws_iam_role_policy.deploy",
                                "type": "aws_iam_role_policy",
                                "values": {
                                    "policy": json.dumps(
                                        doc(
                                            [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
                                        )
                                    )
                                },
                            },
                            {
                                "address": "module.deploy.aws_iam_role_policy.later",
                                "type": "aws_iam_role_policy",
                                "values": {},
                            },
                            {
                                "address": "aws_iam_role.unknown",
                                "type": "aws_iam_role",
                                "values": {},
                            },
                        ],
                    }
                ],
            }
        },
    }


def test_documents_from_plan(caplog: pytest.LogCaptureFixture) -> None:
    docs = documents_from_plan(plan_json())
    assert [(d.name, d.kind) for d in docs] == [
        ("module.deploy.aws_iam_role.this", "trust"),
        ("module.deploy.aws_iam_role_policy.deploy", "permissions"),
    ]
    assert docs[0].role_account == TARGET
    assert docs[0].max_session_duration == 3600
    assert "not known until apply" in caplog.text
    assert rules(lint(docs)) == {("XA010", "HIGH")}


def test_documents_from_plan_account_override() -> None:
    docs = documents_from_plan(plan_json(), account_id=TOOLING)
    assert docs[0].role_account == TOOLING


def test_documents_from_live_role(aws: None) -> None:
    iam = boto3.client("iam")
    iam.create_role(
        RoleName="cicd-deploy-app1", AssumeRolePolicyDocument=json.dumps(good_deploy_trust())
    )
    iam.put_role_policy(
        RoleName="cicd-deploy-app1",
        PolicyName="deploy",
        PolicyDocument=json.dumps(
            doc([{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}])
        ),
    )
    arn = iam.create_policy(
        PolicyName="wide",
        PolicyDocument=json.dumps(doc([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}])),
    )["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="cicd-deploy-app1", PolicyArn=arn)

    docs = documents_from_role(iam, "cicd-deploy-app1")
    assert [d.kind for d in docs] == ["trust", "permissions", "permissions"]
    assert docs[0].role_account == "123456789012"  # moto's default account
    # moto's account is not TOOLING, so the trust is cross-account and has its ExternalId.
    # iam:* also covers iam:PassRole on "*".
    assert rules(lint(docs)) == {("XA010", "HIGH"), ("XA013", "HIGH")}


class FakeAnalyzer:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def get_paginator(self, name: str) -> Any:
        assert name == "validate_policy"
        outer = self

        class P:
            def paginate(self, **kw: Any) -> Iterator[dict[str, Any]]:
                outer.calls.append(kw)
                yield {
                    "findings": [
                        {
                            "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
                            "findingType": "SECURITY_WARNING",
                            "findingDetails": "details",
                        },
                        {"issueCode": "X", "findingType": "OTHER", "findingDetails": "d"},
                    ]
                }

        return P()


def test_access_analyzer_mapping() -> None:
    aa = FakeAnalyzer()
    docs = [
        Document("t", "trust", good_deploy_trust()),
        Document("p", "permissions", json.dumps(doc([]))),
    ]
    found = access_analyzer_findings(aa, docs)
    assert aa.calls[0]["validatePolicyResourceType"] == "AWS::IAM::AssumeRolePolicyDocument"
    assert aa.calls[1]["policyType"] == "IDENTITY_POLICY"
    assert found[0].rule == "AA:PASS_ROLE_WITH_STAR_IN_RESOURCE"
    assert found[0].severity is Severity.HIGH
    assert found[1].severity is Severity.LOW
