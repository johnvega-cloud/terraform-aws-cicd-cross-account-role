"""Shared fixtures.

Two kinds of fake AWS:

* moto (in memory) for STS/SSM/IAM calls where AWS behaviour is simple to model.
* ``FakeWorld``: a tiny STS + IAM simulator that DOES enforce trust policies
  (pinned principal + ExternalId) and answers SimulatePrincipalPolicy. moto
  accepts any AssumeRole, so it cannot prove that a wrong ExternalId is refused.

No test can reach real AWS: the credentials are fake.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from xacct.sts import Credentials

REGION = "us-east-1"
TOOLING = "111111111111"
TARGET = "222222222222"
PIPELINE_ARN = f"arn:aws:iam::{TOOLING}:role/cicd-pipeline"
DEPLOY_ARN = f"arn:aws:iam::{TARGET}:role/cicd-deploy-app1"
ADMIN_ARN = f"arn:aws:iam::{TOOLING}:user/admin"
EXTERNAL_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "XACCT_EXTERNAL_ID", "GITHUB_ENV"):
        monkeypatch.delenv(var, raising=False)
    for var in ("GITHUB_RUN_ID", "GITHUB_REPOSITORY", "CI_PIPELINE_ID", "BUILD_NUMBER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    """cli.main() replaces the root handlers; put them back so tests do not leak streams."""
    import logging

    root = logging.getLogger()
    saved = root.handlers[:]
    yield
    root.handlers[:] = saved


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


# --- FakeWorld ------------------------------------------------------------------------


def _denied(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, op)


@dataclass
class Role:
    trusted: str
    external_id: str | None
    allows_tags: bool = True


@dataclass
class FakeWorld:
    roles: dict[str, Role] = field(default_factory=dict)
    # (action, resource-or-*) -> EvalDecision
    decisions: dict[tuple[str, str], str] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def session(self, identity: str) -> FakeSession:
        return FakeSession(self, identity)

    def from_creds(self, creds: Credentials, region: str | None = None) -> FakeSession:
        # assumed-role ARN -> role ARN, so chained calls are evaluated as that role
        _, _, rest = creds.assumed_role_arn.partition(":assumed-role/")
        account = creds.assumed_role_arn.split(":")[4]
        role_name = rest.split("/", 1)[0]
        return FakeSession(self, f"arn:aws:iam::{account}:role/{role_name}", creds.assumed_role_arn)


@dataclass
class FakeSession:
    world: FakeWorld
    identity: str
    caller_arn: str | None = None

    def client(self, service: str, **_: Any) -> Any:
        if service == "sts":
            return FakeSts(self)
        if service == "iam":
            return FakeIam(self.world)
        raise AssertionError(f"unexpected client {service}")


@dataclass
class FakeSts:
    session: FakeSession

    def get_caller_identity(self) -> dict[str, str]:
        return {"Arn": self.session.caller_arn or self.session.identity}

    def assume_role(self, **params: Any) -> dict[str, Any]:
        self.session.world.calls.append({"caller": self.session.identity, **params})
        role = self.session.world.roles.get(params["RoleArn"])
        if role is None or role.trusted != self.session.identity:
            raise _denied("AssumeRole")
        if role.external_id is not None and params.get("ExternalId") != role.external_id:
            raise _denied("AssumeRole")
        if params.get("Tags") and not role.allows_tags:
            raise _denied("AssumeRole")
        account = params["RoleArn"].split(":")[4]
        name = params["RoleArn"].rsplit("/", 1)[-1]
        return {
            "Credentials": {
                "AccessKeyId": "ASIAFAKE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime.now(UTC) + timedelta(hours=1),
            },
            "AssumedRoleUser": {
                "Arn": f"arn:aws:sts::{account}:assumed-role/{name}/{params['RoleSessionName']}"
            },
        }


class _Paginator:
    def __init__(self, fn: Any) -> None:
        self.fn = fn

    def paginate(self, **kw: Any) -> Iterator[dict[str, Any]]:
        yield self.fn(**kw)


@dataclass
class FakeIam:
    world: FakeWorld

    def get_paginator(self, name: str) -> _Paginator:
        assert name == "simulate_principal_policy"
        return _Paginator(self.simulate)

    def simulate(self, **kw: Any) -> dict[str, Any]:
        self.world.calls.append(kw)
        action, resource = kw["ActionNames"][0], kw["ResourceArns"][0]
        decision = self.world.decisions.get((action, resource), "implicitDeny")
        return {"EvaluationResults": [{"EvalActionName": action, "EvalDecision": decision}]}


@pytest.fixture
def world() -> FakeWorld:
    w = FakeWorld()
    w.roles[PIPELINE_ARN] = Role(trusted=ADMIN_ARN, external_id=None)
    w.roles[DEPLOY_ARN] = Role(trusted=PIPELINE_ARN, external_id=EXTERNAL_ID)
    return w
