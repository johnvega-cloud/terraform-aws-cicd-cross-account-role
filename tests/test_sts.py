from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError

from tests.conftest import DEPLOY_ARN, EXTERNAL_ID, PIPELINE_ARN, FakeWorld
from xacct.sts import (
    AssumeError,
    Credentials,
    assume_role,
    ci_session_tags,
    format_credential_process,
    format_env,
    format_json,
    parse_tags,
    read_external_id,
    sanitize_session_name,
    session_name_from_env,
    write_github_env,
)

CREDS = Credentials("ASIAXXX", "se'cret", "tok", datetime(2026, 10, 20, 12, 0, tzinfo=UTC), "arn:x")


# --- session names and tags --------------------------------------------------------


def test_github_session_name() -> None:
    env = {"GITHUB_RUN_ID": "123", "GITHUB_REPOSITORY": "acme/app 1", "GITHUB_RUN_ATTEMPT": "2"}
    assert session_name_from_env(env) == "gha-app-1-123-2"


def test_gitlab_and_jenkins_session_names() -> None:
    assert session_name_from_env({"CI_PIPELINE_ID": "9", "CI_PROJECT_NAME": "app"}) == "gl-app-9"
    jenkins = {"BUILD_NUMBER": "7", "JOB_NAME": "folder/deploy"}
    assert session_name_from_env(jenkins) == "jenkins-folder-deploy-7"


def test_local_session_name() -> None:
    assert session_name_from_env({}).startswith("xacct-")


def test_sanitize_session_name_limits() -> None:
    assert len(sanitize_session_name("a" * 100)) == 64
    assert sanitize_session_name("!").startswith("xacct-")
    assert sanitize_session_name("a b/c") == "a-b-c"


def test_ci_session_tags() -> None:
    env = {"GITHUB_REPOSITORY": "acme/app", "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "j*v"}
    assert ci_session_tags(env) == {
        "ci-repository": "acme/app",
        "ci-ref": "refs/heads/main",
        "ci-actor": "j-v",
    }
    assert ci_session_tags({}) == {}


def test_parse_tags() -> None:
    assert parse_tags(["a=1", "b=x=y"]) == {"a": "1", "b": "x=y"}
    with pytest.raises(ValueError, match="KEY=VALUE"):
        parse_tags(["novalue"])


# --- assume_role ------------------------------------------------------------------


def test_assume_role_sends_external_id_tags_and_name(world: FakeWorld) -> None:
    pipeline = world.session(PIPELINE_ARN)
    creds = assume_role(
        pipeline,
        DEPLOY_ARN,
        external_id=EXTERNAL_ID,
        session_name="gha app",
        tags={"ci-run-id": "1"},
    )
    call = world.calls[-1]
    assert call["ExternalId"] == EXTERNAL_ID
    assert call["RoleSessionName"] == "gha-app"
    assert call["DurationSeconds"] == 900
    assert call["Tags"] == [{"Key": "ci-run-id", "Value": "1"}]
    assert creds.assumed_role_arn.endswith(":assumed-role/cicd-deploy-app1/gha-app")


def test_assume_role_without_external_id_omits_the_parameter(world: FakeWorld) -> None:
    with pytest.raises(AssumeError) as exc:
        assume_role(world.session(PIPELINE_ARN), DEPLOY_ARN, external_id=None, session_name="s")
    assert exc.value.denied
    assert "ExternalId matches" in str(exc.value)
    assert "ExternalId" not in world.calls[-1]


def test_assume_role_non_denied_error() -> None:
    class Sts:
        def assume_role(self, **_: object) -> None:
            raise ClientError({"Error": {"Code": "RegionDisabledException"}}, "AssumeRole")

    class Session:
        def client(self, *_: object, **__: object) -> Sts:
            return Sts()

    with pytest.raises(AssumeError) as exc:
        assume_role(Session(), DEPLOY_ARN, external_id="x", session_name="s")
    assert not exc.value.denied
    assert "check:" not in str(exc.value)


def test_assume_role_rejects_bad_duration(world: FakeWorld) -> None:
    with pytest.raises(ValueError, match="duration"):
        assume_role(
            world.session(PIPELINE_ARN), DEPLOY_ARN, external_id="x", session_name="s", duration=60
        )


def test_assume_role_against_moto_returns_usable_session(aws: None) -> None:
    iam = boto3.client("iam")
    arn = iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    creds = assume_role(boto3.Session(), arn, external_id=EXTERNAL_ID, session_name="t1")
    ident = creds.session("us-east-1").client("sts").get_caller_identity()
    assert ":assumed-role/r/t1" in ident["Arn"]


# --- SSM -------------------------------------------------------------------------------


def test_read_external_id_from_ssm(aws: None) -> None:
    boto3.client("ssm").put_parameter(Name="/cicd/x", Value=EXTERNAL_ID, Type="SecureString")
    assert read_external_id(boto3.Session(), "/cicd/x") == EXTERNAL_ID


def test_read_external_id_missing(aws: None) -> None:
    with pytest.raises(AssumeError, match="cannot read ExternalId") as exc:
        read_external_id(boto3.Session(), "/cicd/missing")
    assert not exc.value.denied


# --- formats -------------------------------------------------------------------------


def test_format_env_quotes_values() -> None:
    out = format_env(CREDS, "eu-west-1")
    assert "export AWS_SECRET_ACCESS_KEY='se'\\''cret'" in out
    assert "export AWS_REGION='eu-west-1'" in out


def test_format_credential_process() -> None:
    data = json.loads(format_credential_process(CREDS))
    assert data["Version"] == 1
    assert data["Expiration"] == "2026-10-20T12:00:00+00:00"


def test_format_json() -> None:
    assert json.loads(format_json(CREDS))["AssumedRoleArn"] == "arn:x"


def test_write_github_env_appends_and_masks(tmp_path: Path) -> None:
    env_file = tmp_path / "env"
    env_file.write_text("EXISTING=1\n")
    masks = write_github_env(CREDS, env_file, "us-east-1")
    text = env_file.read_text()
    assert text.startswith("EXISTING=1\n")
    assert "AWS_SESSION_TOKEN=tok\n" in text
    assert "AWS_DEFAULT_REGION=us-east-1\n" in text
    assert masks == "::add-mask::se'cret\n::add-mask::tok\n"
