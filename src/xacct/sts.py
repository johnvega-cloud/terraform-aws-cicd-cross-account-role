"""Assume a deploy role with an ExternalId and hand the credentials to the CI job."""

from __future__ import annotations

import getpass
import json
import logging
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=30,
    retries={"max_attempts": 5, "mode": "standard"},
    user_agent_extra="xacct",
)

MIN_DURATION = 900
MAX_CHAINED_DURATION = 3600  # AWS caps role-chained sessions at 1 hour

SESSION_NAME_BAD = re.compile(r"[^\w+=,.@-]")
TAG_VALUE_BAD = re.compile(r"[^\w\s.:/=+@-]")

DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException"})


class AssumeError(RuntimeError):
    """AssumeRole failed. ``denied`` tells a trust/ExternalId refusal from other errors."""

    def __init__(self, message: str, *, denied: bool) -> None:
        super().__init__(message)
        self.denied = denied


@dataclass(frozen=True)
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str

    def session(self, region: str | None = None) -> boto3.Session:
        return boto3.Session(
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            aws_session_token=self.session_token,
            region_name=region,
        )


# --- Session name and tags ----------------------------------------------------------


def sanitize_session_name(name: str) -> str:
    """RoleSessionName: 2-64 chars of [\\w+=,.@-]. It shows up in CloudTrail, so keep it."""
    clean = SESSION_NAME_BAD.sub("-", name).strip("-")[:64]
    return clean if len(clean) >= 2 else f"xacct-{int(time.time())}"


def session_name_from_env(env: Mapping[str, str]) -> str:
    """A session name that ties CloudTrail events back to the CI run that made them."""
    if env.get("GITHUB_RUN_ID"):
        repo = env.get("GITHUB_REPOSITORY", "repo").rsplit("/", 1)[-1]
        name = f"gha-{repo}-{env['GITHUB_RUN_ID']}-{env.get('GITHUB_RUN_ATTEMPT', '1')}"
    elif env.get("CI_PIPELINE_ID"):
        name = f"gl-{env.get('CI_PROJECT_NAME', 'project')}-{env['CI_PIPELINE_ID']}"
    elif env.get("BUILD_NUMBER") and env.get("JOB_NAME"):
        name = f"jenkins-{env['JOB_NAME']}-{env['BUILD_NUMBER']}"
    else:
        name = f"xacct-{getpass.getuser()}-{int(time.time())}"
    return sanitize_session_name(name)


def ci_session_tags(env: Mapping[str, str]) -> dict[str, str]:
    """Session tags from GitHub Actions variables (empty outside GitHub Actions)."""
    mapping = {
        "ci-repository": "GITHUB_REPOSITORY",
        "ci-ref": "GITHUB_REF",
        "ci-run-id": "GITHUB_RUN_ID",
        "ci-actor": "GITHUB_ACTOR",
    }
    return {
        key: TAG_VALUE_BAD.sub("-", env[var])[:256] for key, var in mapping.items() if env.get(var)
    }


def parse_tags(items: list[str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"tag {item!r} must be KEY=VALUE")
        tags[key] = value
    return tags


# --- STS / SSM ---------------------------------------------------------------------


def read_external_id(session: boto3.Session, parameter: str, region: str | None = None) -> str:
    """ExternalId from an SSM parameter (String or SecureString)."""
    ssm = session.client("ssm", region_name=region, config=BOTO_CONFIG)
    try:
        value = ssm.get_parameter(Name=parameter, WithDecryption=True)["Parameter"]["Value"]
    except ClientError as exc:
        raise AssumeError(
            f"cannot read ExternalId from SSM parameter {parameter}: {exc}",
            denied=exc.response["Error"]["Code"] in DENIED_CODES,
        ) from exc
    return str(value)


def assume_role(
    session: Any,
    role_arn: str,
    *,
    external_id: str | None,
    session_name: str,
    duration: int = MIN_DURATION,
    tags: Mapping[str, str] | None = None,
    region: str | None = None,
) -> Credentials:
    if not MIN_DURATION <= duration <= 43200:
        raise ValueError(f"duration must be 900-43200 seconds, got {duration}")
    params: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": sanitize_session_name(session_name),
        "DurationSeconds": duration,
    }
    if external_id is not None:
        params["ExternalId"] = external_id
    if tags:
        params["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]

    sts = session.client("sts", region_name=region, config=BOTO_CONFIG)
    try:
        resp = sts.assume_role(**params)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        denied = code in DENIED_CODES
        hint = (
            " (check: caller is a trusted pipeline role, ExternalId matches, and the caller's "
            "own policy allows sts:AssumeRole"
            + (" and sts:TagSession" if tags else "")
            + " on this role)"
            if denied
            else ""
        )
        raise AssumeError(f"AssumeRole {role_arn} failed: {code}{hint}", denied=denied) from exc

    c = resp["Credentials"]
    log.info("assumed %s as %s until %s", role_arn, params["RoleSessionName"], c["Expiration"])
    return Credentials(
        access_key_id=c["AccessKeyId"],
        secret_access_key=c["SecretAccessKey"],
        session_token=c["SessionToken"],
        expiration=c["Expiration"],
        assumed_role_arn=resp["AssumedRoleUser"]["Arn"],
    )


# --- Output formats ---------------------------------------------------------------


def _env_pairs(creds: Credentials, region: str | None) -> list[tuple[str, str]]:
    pairs = [
        ("AWS_ACCESS_KEY_ID", creds.access_key_id),
        ("AWS_SECRET_ACCESS_KEY", creds.secret_access_key),
        ("AWS_SESSION_TOKEN", creds.session_token),
    ]
    if region:
        pairs += [("AWS_REGION", region), ("AWS_DEFAULT_REGION", region)]
    return pairs


def format_env(creds: Credentials, region: str | None = None) -> str:
    """``eval "$(xacct assume ...)"`` in a shell."""
    return "\n".join(f"export {k}={_shell_quote(v)}" for k, v in _env_pairs(creds, region)) + "\n"


def format_credential_process(creds: Credentials) -> str:
    """AWS CLI/SDK ``credential_process`` JSON (Version 1)."""
    return json.dumps(
        {
            "Version": 1,
            "AccessKeyId": creds.access_key_id,
            "SecretAccessKey": creds.secret_access_key,
            "SessionToken": creds.session_token,
            "Expiration": creds.expiration.isoformat(),
        }
    )


def format_json(creds: Credentials) -> str:
    return json.dumps(
        {
            "AccessKeyId": creds.access_key_id,
            "SecretAccessKey": creds.secret_access_key,
            "SessionToken": creds.session_token,
            "Expiration": creds.expiration.isoformat(),
            "AssumedRoleArn": creds.assumed_role_arn,
        }
    )


def write_github_env(creds: Credentials, env_file: Path, region: str | None = None) -> str:
    """Append the credentials to $GITHUB_ENV for later steps.

    Returns the ``::add-mask::`` commands to print, so the secret values are
    redacted from the job log even if a later step echoes them.
    """
    with env_file.open("a", encoding="utf-8") as fh:
        for key, value in _env_pairs(creds, region):
            fh.write(f"{key}={value}\n")
    secrets = (creds.secret_access_key, creds.session_token)
    return "".join(f"::add-mask::{s}\n" for s in secrets)


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
