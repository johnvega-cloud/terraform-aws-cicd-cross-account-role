"""Command line: ``xacct assume``, ``xacct lint`` and ``xacct verify``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from xacct import __version__
from xacct.lint import (
    Document,
    Severity,
    access_analyzer_findings,
    documents_from_plan,
    documents_from_role,
    lint,
)
from xacct.sts import (
    BOTO_CONFIG,
    AssumeError,
    assume_role,
    ci_session_tags,
    format_credential_process,
    format_env,
    format_json,
    parse_tags,
    read_external_id,
    session_name_from_env,
    write_github_env,
)
from xacct.verify import Expectations, check_permissions, check_trust, summary

log = logging.getLogger("xacct")

# Exit codes: documented in the README so CI can react to them.
EXIT_OK = 0
EXIT_FATAL = 1  # AWS/credential error before the work could be done
EXIT_USAGE = 2
EXIT_FAILED = 3  # finished, but findings at/above --fail-on, or a check failed

# Keys read from `terraform output -json` (see e2e/aws/outputs.tf).
TF_KEYS = {
    "role_arn": "deploy_role_arn",
    "via_role": "pipeline_role_arn",
    "external_id_ssm": "external_id_parameter_name",
    "expectations": "expectations",
}


class UsageError(Exception):
    pass


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


def setup_logging(verbosity: int, fmt: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.WARNING)
    log.setLevel(logging.DEBUG if verbosity > 1 else logging.INFO if verbosity else logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="AWS profile to start from (default: environment)")
    common.add_argument("--region", default=None, help="AWS region (default: from profile/env)")
    common.add_argument("-v", "--verbose", action="count", default=1, help="-vv for debug")
    common.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    common.add_argument("--log-format", choices=("text", "json"), default="text")

    target = argparse.ArgumentParser(add_help=False)
    target.add_argument("--role-arn", help="deploy role to assume")
    ext = target.add_mutually_exclusive_group()
    ext.add_argument("--external-id", help="ExternalId (prefer --external-id-ssm or the env var)")
    ext.add_argument("--external-id-ssm", metavar="PARAMETER", help="read ExternalId from SSM")
    target.add_argument(
        "--via-role",
        metavar="ARN",
        help="first assume this pipeline role (role chaining), then the deploy role",
    )
    target.add_argument(
        "--tf-output",
        type=Path,
        metavar="FILE",
        help="`terraform output -json` file: fills role ARNs, SSM parameter and expectations",
    )
    target.add_argument("--session-name", help="default: derived from the CI run (see README)")
    target.add_argument(
        "--tag", action="append", default=[], metavar="KEY=VALUE", help="session tag; repeatable"
    )
    target.add_argument(
        "--ci-tags", action="store_true", help="tag the session with repo/ref/run id/actor (GHA)"
    )

    parser = argparse.ArgumentParser(
        prog="xacct",
        description="Assume, lint and verify cross-account CI/CD deploy roles.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assume", parents=[common, target], help="get deploy-role credentials")
    a.add_argument("--duration", type=int, default=900, help="seconds, 900-3600 (default 900)")
    a.add_argument(
        "--format",
        choices=("env", "github-env", "json", "credential-process"),
        default="env",
        help="env: export lines for eval; github-env: append to $GITHUB_ENV and mask",
    )

    lp = sub.add_parser("lint", parents=[common], help="static checks on trust/permission policies")
    lp.add_argument("--policy", type=Path, action="append", default=[], help="permissions JSON")
    lp.add_argument("--trust", type=Path, action="append", default=[], help="trust policy JSON")
    lp.add_argument("--plan", type=Path, help="`terraform show -json <plan>` output")
    lp.add_argument("--role", action="append", default=[], help="live role name; repeatable")
    lp.add_argument("--account-id", help="account the roles live in (cross-account detection)")
    lp.add_argument(
        "--access-analyzer", action="store_true", help="also run IAM Access Analyzer ValidatePolicy"
    )
    lp.add_argument("--fail-on", choices=("low", "medium", "high", "never"), default="high")
    lp.add_argument("--output", choices=("text", "json"), default="text")

    v = sub.add_parser("verify", parents=[common, target], help="live checks after apply")
    v.add_argument("--expectations", type=Path, help="JSON: {allowed: [...], denied: [...]}")
    v.add_argument(
        "--checks",
        default="trust,permissions",
        help="comma list: trust, permissions (default both)",
    )
    v.add_argument(
        "--simulate-profile",
        help="profile with iam:SimulatePrincipalPolicy in the target account (default: --profile)",
    )
    v.add_argument("--report", type=Path, help="also write results as JSON")
    return parser


# --- helpers -------------------------------------------------------------------------


def load_tf_output(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise UsageError(f"{path}: not a `terraform output -json` document")
    return {k: v["value"] if isinstance(v, Mapping) and "value" in v else v for k, v in raw.items()}


def apply_tf_output(args: argparse.Namespace) -> Mapping[str, Any]:
    """Fill unset options from --tf-output. Explicit flags always win."""
    if not args.tf_output:
        return {}
    out = load_tf_output(args.tf_output)
    if not args.role_arn:
        args.role_arn = out.get(TF_KEYS["role_arn"])
    if not args.via_role:
        args.via_role = out.get(TF_KEYS["via_role"])
    if not args.external_id and not args.external_id_ssm:
        args.external_id_ssm = out.get(TF_KEYS["external_id_ssm"])
    return out


def resolve_external_id(args: argparse.Namespace, session: boto3.Session) -> str:
    if args.external_id:
        return str(args.external_id)
    if os.environ.get("XACCT_EXTERNAL_ID"):
        return os.environ["XACCT_EXTERNAL_ID"]
    if args.external_id_ssm:
        return read_external_id(session, args.external_id_ssm, args.region)
    raise UsageError("no ExternalId: use --external-id-ssm, XACCT_EXTERNAL_ID or --external-id")


def session_tags(args: argparse.Namespace) -> dict[str, str]:
    try:
        tags = ci_session_tags(os.environ) if args.ci_tags else {}
        tags.update(parse_tags(args.tag))
    except ValueError as exc:
        raise UsageError(str(exc)) from exc
    return tags


# --- commands ------------------------------------------------------------------------


def cmd_assume(args: argparse.Namespace) -> int:
    apply_tf_output(args)
    if not args.role_arn:
        raise UsageError("--role-arn (or --tf-output) is required")
    if not 900 <= args.duration <= 3600:
        raise UsageError("--duration must be 900-3600 seconds")
    base = boto3.Session(profile_name=args.profile, region_name=args.region)
    name = args.session_name or session_name_from_env(os.environ)
    caller = base
    if args.via_role:
        hop = assume_role(base, args.via_role, external_id=None, session_name=name)
        caller = hop.session(args.region)
    # The ExternalId parameter lives in the tooling account: read it as the pipeline.
    external_id = resolve_external_id(args, caller)
    creds = assume_role(
        caller,
        args.role_arn,
        external_id=external_id,
        session_name=name,
        duration=args.duration,
        tags=session_tags(args),
        region=args.region,
    )
    if args.format == "env":
        sys.stdout.write(format_env(creds, args.region))
    elif args.format == "json":
        sys.stdout.write(format_json(creds) + "\n")
    elif args.format == "credential-process":
        sys.stdout.write(format_credential_process(creds) + "\n")
    else:
        env_file = os.environ.get("GITHUB_ENV")
        if not env_file:
            raise UsageError("--format github-env needs $GITHUB_ENV (run inside GitHub Actions)")
        sys.stdout.write(write_github_env(creds, Path(env_file), args.region))
        log.info("credentials for %s written to $GITHUB_ENV", creds.assumed_role_arn)
    return EXIT_OK


def cmd_lint(args: argparse.Namespace) -> int:
    docs: list[Document] = []
    for path in args.trust:
        docs.append(Document(str(path), "trust", path.read_text(encoding="utf-8"), args.account_id))
    for path in args.policy:
        docs.append(Document(str(path), "permissions", path.read_text(encoding="utf-8")))
    if args.plan:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        docs.extend(documents_from_plan(plan, args.account_id))
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.role:
        iam = session.client("iam", config=BOTO_CONFIG)
        for name in args.role:
            docs.extend(documents_from_role(iam, name))
    if not docs:
        raise UsageError("nothing to lint: give --trust, --policy, --plan or --role")

    findings = lint(docs)
    if args.access_analyzer:
        aa = session.client("accessanalyzer", config=BOTO_CONFIG)
        findings += access_analyzer_findings(aa, docs)

    if args.output == "json":
        sys.stdout.write(json.dumps([f.to_dict() for f in findings], indent=2) + "\n")
    else:
        for f in findings:
            sys.stdout.write(
                f"{f.severity.name:<6} {f.rule:<8} {f.document} [{f.sid}] {f.message}\n"
            )
        sys.stdout.write(f"{len(docs)} documents, {len(findings)} findings\n")

    if args.fail_on == "never":
        return EXIT_OK
    threshold = Severity.parse(args.fail_on)
    return EXIT_FAILED if any(f.severity >= threshold for f in findings) else EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    out = apply_tf_output(args)
    if not args.role_arn:
        raise UsageError("--role-arn (or --tf-output) is required")
    checks = {c.strip() for c in args.checks.split(",") if c.strip()}
    unknown = checks - {"trust", "permissions"}
    if unknown or not checks:
        raise UsageError(f"--checks: unknown {sorted(unknown)} (use trust, permissions)")

    base = boto3.Session(profile_name=args.profile, region_name=args.region)
    results = []
    if "trust" in checks:
        reader = base
        if args.via_role and args.external_id_ssm:
            # The parameter is in the pipeline's account and readable by the pipeline role.
            hop = assume_role(base, args.via_role, external_id=None, session_name="xacct-verify")
            reader = hop.session(args.region)
        external_id = resolve_external_id(args, reader)
        results += check_trust(
            base,
            args.role_arn,
            external_id,
            via_role_arn=args.via_role,
            session_name=args.session_name or "xacct-verify",
            tags=session_tags(args) or None,
            region=args.region,
        )
    if "permissions" in checks:
        if args.expectations:
            expectations = Expectations.load(args.expectations)
        elif TF_KEYS["expectations"] in out:
            expectations = Expectations.from_dict(out[TF_KEYS["expectations"]])
        else:
            raise UsageError("permissions checks need --expectations (or it in --tf-output)")
        sim = boto3.Session(
            profile_name=args.simulate_profile or args.profile, region_name=args.region
        )
        results += check_permissions(
            sim.client("iam", config=BOTO_CONFIG), args.role_arn, expectations
        )

    sys.stdout.write(summary(results))
    if args.report:
        args.report.write_text(
            json.dumps([r.to_dict() for r in results], indent=2) + "\n", encoding="utf-8"
        )
    return EXIT_OK if all(r.passed for r in results) else EXIT_FAILED


COMMANDS = {"assume": cmd_assume, "lint": cmd_lint, "verify": cmd_verify}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(0 if args.quiet else args.verbose, args.log_format)
    try:
        return COMMANDS[args.command](args)
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except AssumeError as exc:
        log.error("%s", exc)
        return EXIT_FATAL
    except NoCredentialsError:
        log.error("no AWS credentials found (profile, environment or instance role)")
        return EXIT_FATAL
    except (BotoCoreError, ClientError) as exc:
        log.error("AWS error: %s", exc)
        return EXIT_FATAL
