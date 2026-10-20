"""Live checks that the deployed roles behave as designed.

Two groups, because they need different identities:

* **trust** runs as the pipeline (or reaches it with ``via_role``): no
  ExternalId and a wrong ExternalId must be refused, the right one accepted,
  and a principal that is not the pipeline must be refused even with the
  right ExternalId.
* **permissions** asks IAM's policy simulator (SimulatePrincipalPolicy) whether
  the deploy role is allowed exactly what it should be and denied the rest.
  It needs ``iam:SimulatePrincipalPolicy`` in the target account, so it runs
  with an admin/auditor session there, not as the pipeline.
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from xacct.sts import BOTO_CONFIG, AssumeError, Credentials, assume_role

log = logging.getLogger(__name__)

SessionFromCreds = Callable[[Credentials, str | None], Any]


def _default_session(creds: Credentials, region: str | None) -> Any:
    return creds.session(region)


@dataclass(frozen=True)
class ActionCheck:
    action: str
    resource: str = "*"
    context: Mapping[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ActionCheck:
        if "action" not in raw:
            raise ValueError(f"expectation without 'action': {raw!r}")
        ctx = {str(k): [str(v) for v in vs] for k, vs in (raw.get("context") or {}).items()}
        return cls(str(raw["action"]), str(raw.get("resource", "*")), ctx)

    def label(self) -> str:
        ctx = ", ".join(f"{k}={'|'.join(v)}" for k, v in self.context.items())
        return f"{self.action} on {self.resource}" + (f" [{ctx}]" if ctx else "")


@dataclass(frozen=True)
class Expectations:
    allowed: list[ActionCheck] = field(default_factory=list)
    denied: list[ActionCheck] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Expectations:
        return cls(
            [ActionCheck.from_dict(x) for x in raw.get("allowed", [])],
            [ActionCheck.from_dict(x) for x in raw.get("denied", [])],
        )

    @classmethod
    def load(cls, path: Path) -> Expectations:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


@dataclass(frozen=True)
class CheckResult:
    group: str
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- trust ---------------------------------------------------------------------------


def check_trust(
    base_session: Any,
    role_arn: str,
    external_id: str,
    *,
    via_role_arn: str | None = None,
    session_name: str = "xacct-verify",
    tags: Mapping[str, str] | None = None,
    region: str | None = None,
    session_from_creds: SessionFromCreds = _default_session,
) -> list[CheckResult]:
    results: list[CheckResult] = []

    def add(name: str, passed: bool, detail: str) -> None:
        results.append(CheckResult("trust", name, passed, detail))
        log.info("%s %s: %s", "PASS" if passed else "FAIL", name, detail)

    pipeline = base_session
    if via_role_arn:
        try:
            creds = assume_role(
                base_session,
                via_role_arn,
                external_id=None,
                session_name=session_name,
                region=region,
            )
        except AssumeError as exc:
            add("reach pipeline role", False, str(exc))
            return results
        add("reach pipeline role", True, creds.assumed_role_arn)
        pipeline = session_from_creds(creds, region)

    def expect_denied(name: str, ext: str | None, session: Any) -> None:
        try:
            assume_role(
                session, role_arn, external_id=ext, session_name=session_name, region=region
            )
        except AssumeError as exc:
            add(name, exc.denied, "refused (AccessDenied)" if exc.denied else str(exc))
            return
        add(name, False, "AssumeRole SUCCEEDED but must be refused")

    expect_denied("no ExternalId is refused", None, pipeline)
    expect_denied("wrong ExternalId is refused", "wrong-" + secrets.token_hex(12), pipeline)

    try:
        creds = assume_role(
            pipeline,
            role_arn,
            external_id=external_id,
            session_name=session_name,
            tags=tags,
            region=region,
        )
    except AssumeError as exc:
        add("correct ExternalId is accepted", False, str(exc))
    else:
        sts = session_from_creds(creds, region).client("sts", config=BOTO_CONFIG)
        arn = str(sts.get_caller_identity()["Arn"])
        role_name = role_arn.rsplit("/", 1)[-1]
        ok = f":assumed-role/{role_name}/" in arn
        detail = arn + (f" (session tags: {', '.join(tags)})" if tags else "")
        add("correct ExternalId is accepted", ok, detail)

    if via_role_arn:
        # The base identity is not the pipeline role: even with the right
        # ExternalId it must be refused (proves the aws:PrincipalArn pin).
        expect_denied("non-pipeline principal is refused", external_id, base_session)
    return results


# --- permissions ---------------------------------------------------------------------


def check_permissions(
    iam: Any, role_arn: str, expectations: Expectations, *, batch: int = 20
) -> list[CheckResult]:
    """Ask the IAM policy simulator about each expected action.

    Identity policies, the permissions boundary and explicit denies are
    evaluated. SCPs and resource policies are not (simulator limitation).
    """
    results: list[CheckResult] = []
    for want_allowed, checks in ((True, expectations.allowed), (False, expectations.denied)):
        for check in checks:
            decision = _simulate(iam, role_arn, check)
            allowed = decision == "allowed"
            passed = allowed == want_allowed
            name = ("allowed: " if want_allowed else "denied: ") + check.label()
            results.append(CheckResult("permissions", name, passed, decision))
            log.info("%s %s -> %s", "PASS" if passed else "FAIL", name, decision)
    return results


def _simulate(iam: Any, role_arn: str, check: ActionCheck) -> str:
    params: dict[str, Any] = {
        "PolicySourceArn": role_arn,
        "ActionNames": [check.action],
        "ResourceArns": [check.resource],
    }
    if check.context:
        # One value -> "string". A "stringList" makes the key multi-valued, and
        # plain operators (StringLike, StringNotEquals) do not match multi-valued
        # keys, so the simulator would skip conditions like s3:prefix or
        # aws:RequestedRegion. Found in the real-AWS e2e run.
        params["ContextEntries"] = [
            {
                "ContextKeyName": k,
                "ContextKeyValues": v,
                "ContextKeyType": "string" if len(v) == 1 else "stringList",
            }
            for k, v in check.context.items()
        ]
    decisions: list[str] = []
    for page in iam.get_paginator("simulate_principal_policy").paginate(**params):
        decisions += [r["EvalDecision"] for r in page["EvaluationResults"]]
    if not decisions:
        return "no-result"
    # Any explicit deny wins; otherwise every result must be "allowed".
    if "explicitDeny" in decisions:
        return "explicitDeny"
    return "allowed" if all(d == "allowed" for d in decisions) else "implicitDeny"


def summary(results: list[CheckResult]) -> str:
    lines = []
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        lines.append(f"[{mark}] {r.group:<11} {r.name} -> {r.detail}")
    failed = sum(not r.passed for r in results)
    lines.append(f"{len(results) - failed}/{len(results)} checks passed")
    return "\n".join(lines) + "\n"
