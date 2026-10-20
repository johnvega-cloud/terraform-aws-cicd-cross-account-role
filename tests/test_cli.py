from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest

from tests.conftest import ADMIN_ARN, DEPLOY_ARN, EXTERNAL_ID, PIPELINE_ARN, FakeWorld
from xacct import cli
from xacct.sts import Credentials

WIDE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
NARROW = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}],
}


def write(tmp_path: Path, name: str, data: Any) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


# --- lint ------------------------------------------------------------------------------


def test_lint_clean_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["lint", "--policy", str(write(tmp_path, "p.json", NARROW))]) == cli.EXIT_OK
    assert "1 documents, 0 findings" in capsys.readouterr().out


def test_lint_findings_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "p.json", WIDE)
    assert cli.main(["lint", "--policy", str(path)]) == cli.EXIT_FAILED
    assert "HIGH   XA010" in capsys.readouterr().out
    assert cli.main(["lint", "--policy", str(path), "--fail-on", "never"]) == cli.EXIT_OK


def test_lint_fail_on_threshold(tmp_path: Path) -> None:
    star_write = {
        "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]  # MEDIUM
    }
    path = str(write(tmp_path, "p.json", star_write))
    assert cli.main(["lint", "--policy", path]) == cli.EXIT_OK
    assert cli.main(["lint", "--policy", path, "--fail-on", "medium"]) == cli.EXIT_FAILED


def test_lint_json_output_and_trust(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    path = write(tmp_path, "t.json", trust)
    assert cli.main(["lint", "--trust", str(path), "--output", "json", "-q"]) == cli.EXIT_FAILED
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule"] == "XA001" and data[0]["severity"] == "HIGH"


def test_lint_plan(tmp_path: Path) -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_iam_role_policy.p",
                        "type": "aws_iam_role_policy",
                        "values": {"policy": json.dumps(NARROW)},
                    }
                ]
            }
        }
    }
    assert cli.main(["lint", "--plan", str(write(tmp_path, "plan.json", plan))]) == cli.EXIT_OK


def test_lint_live_role(aws: None, capsys: pytest.CaptureFixture[str]) -> None:
    iam = boto3.client("iam")
    iam.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps(NARROW | {"Statement": []}))
    iam.put_role_policy(RoleName="r", PolicyName="p", PolicyDocument=json.dumps(WIDE))
    assert cli.main(["lint", "--role", "r"]) == cli.EXIT_FAILED
    assert "r/p" in capsys.readouterr().out


def test_lint_nothing_to_do() -> None:
    assert cli.main(["lint"]) == cli.EXIT_USAGE


def test_lint_missing_file(tmp_path: Path) -> None:
    assert cli.main(["lint", "--policy", str(tmp_path / "nope.json")]) == cli.EXIT_USAGE


# --- assume (moto) ---------------------------------------------------------------------


@pytest.fixture
def role_arn(aws: None) -> str:
    iam = boto3.client("iam")
    return str(iam.create_role(RoleName="deploy", AssumeRolePolicyDocument="{}")["Role"]["Arn"])


def test_assume_env(role_arn: str, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(
        ["assume", "--role-arn", role_arn, "--external-id", EXTERNAL_ID, "--region", "us-east-1"]
    )
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK
    assert "export AWS_SESSION_TOKEN=" in out and "export AWS_REGION='us-east-1'" in out


def test_assume_credential_process_from_ssm(
    role_arn: str, capsys: pytest.CaptureFixture[str]
) -> None:
    boto3.client("ssm").put_parameter(Name="/x/eid", Value=EXTERNAL_ID, Type="SecureString")
    rc = cli.main(
        [
            "assume",
            "--role-arn",
            role_arn,
            "--external-id-ssm",
            "/x/eid",
            "--format",
            "credential-process",
        ]
    )
    assert rc == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["Version"] == 1


def test_assume_json_with_env_external_id_and_via_role(
    role_arn: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XACCT_EXTERNAL_ID", EXTERNAL_ID)
    via = boto3.client("iam").create_role(RoleName="pipe", AssumeRolePolicyDocument="{}")
    rc = cli.main(
        [
            "assume",
            "--role-arn",
            role_arn,
            "--via-role",
            via["Role"]["Arn"],
            "--format",
            "json",
            "--tag",
            "team=platform",
        ]
    )
    assert rc == cli.EXIT_OK
    assert ":assumed-role/deploy/" in json.loads(capsys.readouterr().out)["AssumedRoleArn"]


def test_assume_github_env(
    role_arn: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env_file = tmp_path / "github_env"
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app1")
    rc = cli.main(
        [
            "assume",
            "--role-arn",
            role_arn,
            "--external-id",
            EXTERNAL_ID,
            "--format",
            "github-env",
            "--ci-tags",
        ]
    )
    assert rc == cli.EXIT_OK
    assert capsys.readouterr().out.startswith("::add-mask::")
    assert "AWS_SESSION_TOKEN=" in env_file.read_text()


def test_assume_github_env_outside_actions(role_arn: str) -> None:
    rc = cli.main(
        ["assume", "--role-arn", role_arn, "--external-id", EXTERNAL_ID, "--format", "github-env"]
    )
    assert rc == cli.EXIT_USAGE


def test_assume_from_tf_output(role_arn: str, tmp_path: Path) -> None:
    boto3.client("ssm").put_parameter(Name="/x/eid", Value=EXTERNAL_ID, Type="SecureString")
    out = write(
        tmp_path,
        "out.json",
        {
            "deploy_role_arn": {"value": role_arn, "sensitive": False},
            "external_id_parameter_name": {"value": "/x/eid", "sensitive": False},
        },
    )
    assert cli.main(["assume", "--tf-output", str(out)]) == cli.EXIT_OK


@pytest.mark.parametrize(
    "argv",
    [
        ["assume", "--external-id", EXTERNAL_ID],  # no role
        ["assume", "--role-arn", DEPLOY_ARN],  # no external id
        ["assume", "--role-arn", DEPLOY_ARN, "--external-id", EXTERNAL_ID, "--duration", "7200"],
        ["assume", "--role-arn", DEPLOY_ARN, "--external-id", EXTERNAL_ID, "--tag", "bad"],
    ],
)
def test_assume_usage_errors(aws: None, argv: list[str]) -> None:
    assert cli.main(argv) == cli.EXIT_USAGE


def test_assume_ssm_missing_is_fatal(aws: None) -> None:
    rc = cli.main(["assume", "--role-arn", DEPLOY_ARN, "--external-id-ssm", "/nope"])
    assert rc == cli.EXIT_FATAL


def test_bad_tf_output(tmp_path: Path) -> None:
    path = write(tmp_path, "o.json", ["not", "a", "map"])
    assert cli.main(["assume", "--tf-output", str(path)]) == cli.EXIT_USAGE


def test_no_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(var)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    rc = cli.main(["assume", "--role-arn", DEPLOY_ARN, "--external-id", EXTERNAL_ID])
    assert rc == cli.EXIT_FATAL


# --- verify (FakeWorld enforces trust) ------------------------------------------------


@pytest.fixture
def fake_aws(world: FakeWorld, monkeypatch: pytest.MonkeyPatch) -> FakeWorld:
    monkeypatch.setattr(cli.boto3, "Session", lambda **_: world.session(ADMIN_ARN))
    monkeypatch.setattr(Credentials, "session", lambda self, region=None: world.from_creds(self))
    monkeypatch.setenv("XACCT_EXTERNAL_ID", EXTERNAL_ID)
    world.decisions[("s3:PutObject", "arn:aws:s3:::b/artifacts/x")] = "allowed"
    world.decisions[("cloudtrail:StopLogging", "*")] = "explicitDeny"
    return world


def tf_output(tmp_path: Path) -> Path:
    return write(
        tmp_path,
        "out.json",
        {
            "deploy_role_arn": {"value": DEPLOY_ARN},
            "pipeline_role_arn": {"value": PIPELINE_ARN},
            "expectations": {
                "value": {
                    "allowed": [
                        {"action": "s3:PutObject", "resource": "arn:aws:s3:::b/artifacts/x"}
                    ],
                    "denied": [{"action": "cloudtrail:StopLogging"}],
                }
            },
        },
    )


def test_verify_all_pass(
    fake_aws: FakeWorld, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.json"
    rc = cli.main(["verify", "--tf-output", str(tf_output(tmp_path)), "--report", str(report)])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_OK, out
    assert out.endswith("7/7 checks passed\n")
    assert len(json.loads(report.read_text())) == 7


def test_verify_fails_when_permission_too_wide(fake_aws: FakeWorld, tmp_path: Path) -> None:
    fake_aws.decisions[("cloudtrail:StopLogging", "*")] = "allowed"
    rc = cli.main(["verify", "--tf-output", str(tf_output(tmp_path)), "--checks", "permissions"])
    assert rc == cli.EXIT_FAILED


def test_verify_trust_only_with_expectations_file(fake_aws: FakeWorld, tmp_path: Path) -> None:
    rc = cli.main(
        ["verify", "--role-arn", DEPLOY_ARN, "--via-role", PIPELINE_ARN, "--checks", "trust"]
    )
    assert rc == cli.EXIT_OK


def test_verify_reads_ssm_as_pipeline(fake_aws: FakeWorld, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XACCT_EXTERNAL_ID")
    seen: list[str] = []

    def fake_read(session: Any, parameter: str, region: str | None = None) -> str:
        seen.append(session.identity)
        return EXTERNAL_ID

    monkeypatch.setattr(cli, "read_external_id", fake_read)
    rc = cli.main(
        [
            "verify",
            "--role-arn",
            DEPLOY_ARN,
            "--via-role",
            PIPELINE_ARN,
            "--external-id-ssm",
            "/x/eid",
            "--checks",
            "trust",
        ]
    )
    assert rc == cli.EXIT_OK
    assert seen == [PIPELINE_ARN]


@pytest.mark.parametrize(
    "argv",
    [
        ["verify"],
        ["verify", "--role-arn", DEPLOY_ARN, "--checks", "bogus"],
        ["verify", "--role-arn", DEPLOY_ARN, "--checks", "permissions"],  # no expectations
    ],
)
def test_verify_usage(fake_aws: FakeWorld, argv: list[str]) -> None:
    assert cli.main(argv) == cli.EXIT_USAGE


def test_json_logging(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["lint", "--log-format", "json"])
    line = capsys.readouterr().err.strip().splitlines()[-1]
    assert json.loads(line)["level"] == "ERROR"
