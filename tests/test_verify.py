from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import ADMIN_ARN, DEPLOY_ARN, EXTERNAL_ID, PIPELINE_ARN, FakeWorld, Role
from xacct.verify import (
    ActionCheck,
    CheckResult,
    Expectations,
    check_permissions,
    check_trust,
    summary,
)


def by_name(results: list[CheckResult]) -> dict[str, bool]:
    return {r.name: r.passed for r in results}


def test_trust_all_pass_as_pipeline(world: FakeWorld) -> None:
    results = check_trust(
        world.session(PIPELINE_ARN), DEPLOY_ARN, EXTERNAL_ID, session_from_creds=world.from_creds
    )
    assert by_name(results) == {
        "no ExternalId is refused": True,
        "wrong ExternalId is refused": True,
        "correct ExternalId is accepted": True,
    }


def test_trust_via_role_adds_untrusted_check(world: FakeWorld) -> None:
    results = check_trust(
        world.session(ADMIN_ARN),
        DEPLOY_ARN,
        EXTERNAL_ID,
        via_role_arn=PIPELINE_ARN,
        tags={"ci-run-id": "1"},
        session_from_creds=world.from_creds,
    )
    assert all(r.passed for r in results), summary(results)
    assert results[0].name == "reach pipeline role"
    assert "non-pipeline principal is refused" in by_name(results)
    assert "session tags: ci-run-id" in results[3].detail


def test_trust_detects_missing_external_id_condition(world: FakeWorld) -> None:
    world.roles[DEPLOY_ARN] = Role(trusted=PIPELINE_ARN, external_id=None)
    results = by_name(
        check_trust(
            world.session(PIPELINE_ARN),
            DEPLOY_ARN,
            EXTERNAL_ID,
            session_from_creds=world.from_creds,
        )
    )
    assert results["no ExternalId is refused"] is False
    assert results["wrong ExternalId is refused"] is False
    assert results["correct ExternalId is accepted"] is True


def test_trust_detects_wrong_external_id_given(world: FakeWorld) -> None:
    results = by_name(
        check_trust(
            world.session(PIPELINE_ARN), DEPLOY_ARN, "stale-id", session_from_creds=world.from_creds
        )
    )
    assert results["correct ExternalId is accepted"] is False


def test_trust_detects_role_trusting_too_much(world: FakeWorld) -> None:
    # The deploy role trusts the admin user directly: the pin on the pipeline role is gone.
    world.roles[DEPLOY_ARN] = Role(trusted=ADMIN_ARN, external_id=EXTERNAL_ID)
    world.roles[PIPELINE_ARN] = Role(trusted=ADMIN_ARN, external_id=None)
    results = by_name(
        check_trust(
            world.session(ADMIN_ARN),
            DEPLOY_ARN,
            EXTERNAL_ID,
            via_role_arn=PIPELINE_ARN,
            session_from_creds=world.from_creds,
        )
    )
    assert results["non-pipeline principal is refused"] is False


def test_trust_cannot_reach_pipeline(world: FakeWorld) -> None:
    results = check_trust(
        world.session("arn:aws:iam::999999999999:user/stranger"),
        DEPLOY_ARN,
        EXTERNAL_ID,
        via_role_arn=PIPELINE_ARN,
        session_from_creds=world.from_creds,
    )
    assert [(r.name, r.passed) for r in results] == [("reach pipeline role", False)]


def test_trust_session_tags_refused(world: FakeWorld) -> None:
    world.roles[DEPLOY_ARN].allows_tags = False
    results = by_name(
        check_trust(
            world.session(PIPELINE_ARN),
            DEPLOY_ARN,
            EXTERNAL_ID,
            tags={"a": "b"},
            session_from_creds=world.from_creds,
        )
    )
    assert results["correct ExternalId is accepted"] is False


# --- permissions -----------------------------------------------------------------------


def test_permissions_allowed_and_denied(world: FakeWorld) -> None:
    world.decisions[("s3:PutObject", "arn:aws:s3:::b/artifacts/x")] = "allowed"
    world.decisions[("cloudtrail:StopLogging", "*")] = "explicitDeny"
    world.decisions[("s3:DeleteBucket", "arn:aws:s3:::b")] = "allowed"  # too wide!
    exp = Expectations(
        allowed=[ActionCheck("s3:PutObject", "arn:aws:s3:::b/artifacts/x")],
        denied=[
            ActionCheck("cloudtrail:StopLogging"),
            ActionCheck("s3:DeleteBucket", "arn:aws:s3:::b"),
            ActionCheck("ec2:RunInstances", context={"aws:RequestedRegion": ["eu-west-1"]}),
        ],
    )
    results = check_permissions(world.session(ADMIN_ARN).client("iam"), DEPLOY_ARN, exp)
    assert [(r.passed, r.detail) for r in results] == [
        (True, "allowed"),
        (True, "explicitDeny"),
        (False, "allowed"),
        (True, "implicitDeny"),
    ]
    ctx_call = world.calls[-1]
    assert ctx_call["ContextEntries"] == [
        {
            "ContextKeyName": "aws:RequestedRegion",
            "ContextKeyValues": ["eu-west-1"],
            "ContextKeyType": "string",
        }
    ]
    assert results[3].name == "denied: ec2:RunInstances on * [aws:RequestedRegion=eu-west-1]"


def test_simulate_aggregates_pages() -> None:
    from xacct.verify import _simulate

    class Iam:
        def __init__(self, decisions: list[str]) -> None:
            self.decisions = decisions

        def get_paginator(self, _: str) -> Iam:
            return self

        def paginate(self, **_: object) -> list[dict[str, object]]:
            return [{"EvaluationResults": [{"EvalDecision": d}]} for d in self.decisions]

    check = ActionCheck("s3:GetObject")
    assert _simulate(Iam([]), DEPLOY_ARN, check) == "no-result"
    assert _simulate(Iam(["allowed", "explicitDeny"]), DEPLOY_ARN, check) == "explicitDeny"
    assert _simulate(Iam(["allowed", "implicitDeny"]), DEPLOY_ARN, check) == "implicitDeny"
    assert _simulate(Iam(["allowed", "allowed"]), DEPLOY_ARN, check) == "allowed"


def test_expectations_load(tmp_path: Path) -> None:
    path = tmp_path / "e.json"
    path.write_text(
        json.dumps(
            {
                "allowed": [{"action": "s3:PutObject", "resource": "arn:aws:s3:::b/*"}],
                "denied": [{"action": "iam:CreateUser", "context": {"k": ["v"]}}],
            }
        )
    )
    exp = Expectations.load(path)
    assert exp.allowed[0].resource == "arn:aws:s3:::b/*"
    assert exp.denied[0].resource == "*"
    assert exp.denied[0].context == {"k": ["v"]}


def test_expectation_without_action() -> None:
    with pytest.raises(ValueError, match="without 'action'"):
        Expectations.from_dict({"allowed": [{"resource": "x"}]})


def test_summary_counts() -> None:
    text = summary(
        [CheckResult("trust", "a", True, "ok"), CheckResult("permissions", "b", False, "no")]
    )
    assert "[PASS] trust" in text and "[FAIL] permissions" in text
    assert text.endswith("1/2 checks passed\n")
