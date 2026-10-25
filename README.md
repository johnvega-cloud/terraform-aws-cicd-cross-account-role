# terraform-aws-cicd-cross-account-role

[![ci](https://github.com/johnvega-cloud/terraform-aws-cicd-cross-account-role/actions/workflows/ci.yml/badge.svg)](https://github.com/johnvega-cloud/terraform-aws-cicd-cross-account-role/actions/workflows/ci.yml)

Reusable Terraform modules plus a small Python CLI (`xacct`) for the standard
way a CI/CD pipeline deploys into other AWS accounts: the pipeline gets a role
in a tooling account (GitHub OIDC, no stored keys), and from there assumes a
**deploy role** in each target account. The deploy role trusts only that
pipeline role, requires an **ExternalId**, lasts at most an hour, and can do
only what the deploy needs.

- **Terraform** builds both roles: trust policies, least-privilege permissions
  and explicit-deny guardrails.
- **Python (`xacct`)** uses them and checks them:
  - `assume`: credentials for the CI job (shell env, `$GITHUB_ENV` with
    masking, `credential_process`, JSON).
  - `lint`: static checks on the policies in a Terraform plan, in files, or on
    live roles, optionally with IAM Access Analyzer.
  - `verify`: after apply, real STS calls prove that no ExternalId, a wrong
    one, and a non-pipeline principal are refused, and the IAM policy
    simulator proves the role is allowed what it should be and denied the rest.

## Problem it solves

A pipeline that deploys to several accounts needs credentials in each one.
The usual shortcuts are long-lived access keys in CI secrets, or one role per
account that trusts the whole tooling account and has `AdministratorAccess`.
Either way, one leaked secret or one compromised workflow owns every account.

This repository makes the safe version the easy one:

1. **No long-lived keys.** GitHub Actions gets the pipeline role through OIDC,
   pinned to one repository and environment/branch.
2. **One narrow hop.** The pipeline role can only assume the listed deploy roles
   and read their ExternalIds.
3. **A deploy role that trusts exactly one caller,** with an ExternalId, and
   that cannot touch IAM users, audit trails, KMS key deletion, other regions,
   or its own policies, even if someone later adds a permission by mistake.
4. **Proof, not assumptions.** `xacct verify` runs the negative tests against
   AWS after every apply.

## Architecture

![Architecture](docs/architecture-cross-account-role.svg)

```text
GitHub Actions ──OIDC──▶ pipeline role (tooling) ──AssumeRole + ExternalId──▶ deploy role (target)
                         sts:AssumeRole → exact ARNs                          trust: account root
                         ssm:GetParameter → ExternalId                               + aws:PrincipalArn
                                                                                     + sts:ExternalId
                                                                              deploy: exact actions/ARNs
                                                                              guardrails: explicit Deny
```

See [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for the build order and the
design decisions.

### Why an ExternalId for our own pipeline?

AWS created the ExternalId for the "confused deputy" problem: a third party
that assumes roles in many customers' accounts must not be tricked into using
its access on behalf of the wrong customer. For an internal pipeline the main
controls are the exact principal pin (`aws:PrincipalArn`) and the OIDC `sub`
condition. The ExternalId adds a second, independent condition: knowing the
pipeline role's ARN is not enough, the caller also needs a value that lives in
one SSM parameter only the pipeline role can read. AWS treats the ExternalId
as an identifier, not a secret, so it is not a replacement for the other two.

## Repository layout

```text
.
├── modules/
│   ├── pipeline-role/      # tooling account: GitHub OIDC and/or AWS principals → assume deploy roles only
│   └── deploy-role/        # target account: pinned trust + ExternalId, deploy policy, guardrails
│       └── tests/          # terraform test with a mocked AWS provider (both modules)
├── src/xacct/              # Python CLI: assume, lint, verify
├── tests/                  # pytest: moto + a small STS/IAM fake that enforces trust policies
├── examples/
│   ├── multi-account/      # tooling + target accounts with two provider aliases (ECS deploy)
│   ├── github-actions-deploy.yml
│   └── policies/           # sample good and bad policies (used by CI)
├── e2e/aws/                # real-AWS harness: both roles + S3 bucket + ECR repo, one account
└── docs/                   # architecture diagram, build guide
```

## Prerequisites

- Terraform >= 1.7 (for `terraform test` with mock providers), AWS provider 6.x.
- Python 3.11+ for `xacct`.
- For GitHub Actions: the account's `token.actions.githubusercontent.com` OIDC
  provider. The module takes its ARN as input instead of creating it, because
  there can be only one per account and it is usually owned by the platform team.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .            # or: pip install -e ".[dev]" for development
```

## Usage

### Terraform

```hcl
module "pipeline_role" {
  source    = "github.com/johnvega-cloud/terraform-aws-cicd-cross-account-role//modules/pipeline-role?ref=v1.0.0"
  providers = { aws = aws.tooling }

  name = "cicd-pipeline-orders-api"
  path = "/cicd/"
  github_oidc = {
    provider_arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    subjects     = ["repo:acme/orders-api:environment:prod"]
  }
  target_role_arns           = ["arn:aws:iam::222222222222:role/cicd/cicd-deploy-orders-api"]
  external_id_parameter_arns = [aws_ssm_parameter.external_id.arn]
}

module "deploy_role" {
  source    = "github.com/johnvega-cloud/terraform-aws-cicd-cross-account-role//modules/deploy-role?ref=v1.0.0"
  providers = { aws = aws.target }

  name              = "cicd-deploy-orders-api"
  path              = "/cicd/"
  trusted_role_arns = ["arn:aws:iam::111111111111:role/cicd/cicd-pipeline-orders-api"]
  external_id       = random_password.external_id.result
  principal_org_id  = "o-abc123def4"
  allowed_regions   = ["us-east-1"]

  policy_statements = [
    {
      sid       = "EcrPush"
      actions   = ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchCheckLayerAvailability"]
      resources = ["arn:aws:ecr:us-east-1:222222222222:repository/orders-api"]
    },
  ]
}
```

The complete version (SSM parameter, ECS deploy permissions, `iam:PassRole`
with `iam:PassedToService`) is in [examples/multi-account](examples/multi-account),
and the matching workflow in [examples/github-actions-deploy.yml](examples/github-actions-deploy.yml).

#### deploy-role inputs

| Name | Default | Notes |
|---|---|---|
| `name`, `path` | — , `/` | A dedicated path (`/cicd/`) makes SCPs and audits easier to scope |
| `trusted_role_arns` | — | Exact pipeline role ARNs, no wildcards |
| `external_id` | — | Sensitive, 16–1224 chars of `[A-Za-z0-9+=,.@:/_-]` |
| `principal_org_id` | `null` | Adds `aws:PrincipalOrgID` |
| `allow_session_tags` | `false` | Adds `sts:TagSession` to the trust |
| `max_session_duration` | `3600` | Role chaining caps sessions at 1 h anyway |
| `policy_statements` | — | Allow statements reject `*` and `service:*` actions |
| `managed_policy_arns` | `[]` | Prefer `policy_statements` |
| `permissions_boundary_arn` | `null` | |
| `enable_guardrails` | `true` | Explicit-deny policy below |
| `deny_actions` | account takeover + audit tampering | See [variables.tf](modules/deploy-role/variables.tf) |
| `allowed_regions` | `[]` | Denies regional actions elsewhere; IAM, STS, CloudFront, Route 53 and other global services are exempt |

Outputs: `role_arn`, `role_name`, `role_unique_id`, `trust_policy_json`
(sensitive), `deploy_policy_json`, `guardrails_policy_json`.

#### pipeline-role inputs

| Name | Default | Notes |
|---|---|---|
| `github_oidc` | `null` | `{ provider_arn, subjects, audience = "sts.amazonaws.com" }`; each subject must name one repository |
| `trusted_principal_arns` | `[]` | Exact role/user ARNs (Jenkins on EC2, CodeBuild, a manual e2e test) |
| `target_role_arns` | — | Exact deploy role ARNs |
| `external_id_parameter_arns` | `[]` | `ssm:GetParameter` on exactly these |
| `allow_session_tags`, `max_session_duration`, `permissions_boundary_arn`, `path`, `tags` | | |

At least one of `github_oidc` or `trusted_principal_arns` is required.

### xacct assume

```bash
# Shell (local, Jenkins, GitLab): export the deploy-role credentials
eval "$(xacct assume --role-arn "$DEPLOY_ROLE_ARN" --external-id-ssm /cicd/orders-api/external-id)"

# GitHub Actions: write them to $GITHUB_ENV for later steps; secrets are masked in the log
xacct assume --role-arn "$DEPLOY_ROLE_ARN" --external-id-ssm /cicd/orders-api/external-id \
  --ci-tags --format github-env

# AWS CLI profile (~/.aws/config), refreshed automatically
[profile orders-prod-deploy]
credential_process = xacct assume --role-arn arn:aws:iam::222222222222:role/cicd/cicd-deploy-orders-api --external-id-ssm /cicd/orders-api/external-id --format credential-process
```

| Option | Notes |
|---|---|
| `--external-id-ssm` / `XACCT_EXTERNAL_ID` / `--external-id` | In that order of preference; the flag puts the value in the process list |
| `--via-role ARN` | Assume the pipeline role first (role chaining) |
| `--session-name` | Default from the CI run: `gha-<repo>-<run id>-<attempt>`, `gl-<project>-<pipeline>`, `jenkins-<job>-<build>` |
| `--ci-tags`, `--tag KEY=VALUE` | Session tags (repo, ref, run id, actor) for CloudTrail and ABAC; the roles need `allow_session_tags` |
| `--duration` | 900–3600 s, default 900 |
| `--tf-output FILE` | Read the role ARNs and SSM parameter name from `terraform output -json` |

In GitHub Actions you can also chain with the official
`aws-actions/configure-aws-credentials` action (`role-chaining: true`,
`role-external-id`). `xacct assume` gives the same result outside GitHub
Actions and reads the ExternalId from SSM at run time instead of a CI secret.

### xacct lint

```bash
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
xacct lint --plan plan.json                      # before apply
xacct lint --role cicd-deploy-orders-api --access-analyzer   # after apply, live
xacct lint --trust trust.json --policy policy.json --account-id 222222222222
```

| Rule | Severity | Finds |
|---|---|---|
| XA001 | HIGH | `Principal: "*"` (without an org/ARN condition) or `NotPrincipal` in a trust policy |
| XA002 | HIGH | An account root trusted without `aws:PrincipalArn` |
| XA003 | HIGH | Cross-account `sts:AssumeRole` without `sts:ExternalId` |
| XA004 | HIGH | GitHub OIDC trust without `sub`, or a `sub` that spans repositories |
| XA006 / XA007 | MEDIUM | Wildcard in `sub` within one repo / no `aud` check |
| XA005 | LOW | `max_session_duration` over 1 h |
| XA010 | HIGH | `"*"` or `"service:*"` actions |
| XA011 | HIGH | Allow with `NotAction` / `NotResource` |
| XA012 | HIGH / MEDIUM | IAM privilege-escalation actions (on `"*"` / on ARNs) |
| XA013 | HIGH / MEDIUM | `iam:PassRole` on `"*"` / without `iam:PassedToService` |
| XA014 | HIGH | `sts:AssumeRole` on `"*"` |
| XA015 | MEDIUM | Write action on `Resource: "*"` (actions without resource-level permissions are exempt) |
| XA016 | LOW | Partial wildcard in an action name (`s3:Put*`) |
| AA:\<code\> | by type | IAM Access Analyzer `ValidatePolicy` findings (`--access-analyzer`) |

`--fail-on high|medium|low|never` (default `high`). Explicit Deny statements
are never findings: they can only remove permissions.

Output: the verdict first, problems grouped by policy (worst first), each with
how to fix it and the rule code last. Colors only on a terminal (`NO_COLOR=1`
turns them off). `--output json` keeps a machine-readable list for CI.

```text
✗ FAIL — 1 high in 1 policy

examples/policies/bad-permissions.json
  ✗ HIGH   iam:PassRole on Resource "*" can pass any role
           Fix: Scope Resource to the exact role ARNs and add  "StringEquals": {"iam:PassedToService": "<service>"}
           (XA013 · statement PassAnything)
```

Try it: `xacct lint --policy examples/policies/bad-permissions.json` (exit `3`),
`xacct lint --trust examples/policies/deploy-trust.json --account-id 222222222222` (exit `0`).

**Plan limitation:** policies that depend on values created during apply
(a generated ExternalId, a new bucket ARN) show as "known after apply" in the
plan and are skipped with a warning. Lint the live roles after apply
(`--role`) to cover them; the e2e run does both.

### xacct verify

```bash
terraform output -json > out.json
xacct verify --tf-output out.json --report report.json
```

| Group | Runs as | Checks |
|---|---|---|
| `trust` | the pipeline role (directly, or reached with `--via-role`) | no ExternalId refused · wrong ExternalId refused · correct one accepted (with session tags if given) · with `--via-role`: the base identity is refused even with the right ExternalId |
| `permissions` | a session with `iam:SimulatePrincipalPolicy` in the target account (`--simulate-profile`) | every `allowed` expectation is `allowed`, every `denied` one is not |

Expectations are JSON (`{"allowed": [{"action", "resource", "context"}], "denied": [...]}`)
or the `expectations` Terraform output, so they are built from the same names
Terraform used ([e2e/aws/outputs.tf](e2e/aws/outputs.tf)). The simulator
evaluates identity policies, the permissions boundary and explicit denies;
it does not evaluate SCPs or resource policies.

Output: the verdict first, then "Who can get in" (every trust check, always
listed) and "What the role can do" (only failures, unless `--details`). A
failed check shows what AWS answered. `--report FILE` writes every result as JSON.

```text
✓ PASS — 20 of 20 checks

Who can get in  5/5 ✓
  ✓ You can reach the pipeline role
  ✓ Without ExternalId → refused
  ✓ Wrong ExternalId → refused
  ✓ Correct ExternalId → accepted
  ✓ Someone else with the right ExternalId → refused

What the role can do  15/15 ✓
  (15 passed; --details lists them)
```

### Exit codes (all commands)

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Fatal: no credentials, AssumeRole/SSM/AWS error |
| `2` | Usage error (missing option, unreadable file) |
| `3` | Finished, but lint findings at/above `--fail-on`, or a verify check failed |

## Security

- **No long-lived keys anywhere:** OIDC for GitHub, STS sessions of at most 1 h
  (900 s by default for `xacct assume`).
- **Trust pinned three ways** on the deploy role: account principal,
  `aws:PrincipalArn` = the exact pipeline role, `sts:ExternalId`; optionally
  `aws:PrincipalOrgID`.
- **Inputs validated before anything reaches AWS:** wildcard principals,
  subjects spanning repositories, `"*"`/`"service:*"` allow actions, short or
  malformed ExternalIds and over-long sessions are rejected by the modules.
- **Guardrails as explicit Deny,** which no Allow can override: account
  takeover (IAM users/keys, identity providers, Organizations), audit
  tampering (CloudTrail, Config, GuardDuty), KMS key deletion, any change to
  the deploy role itself, and regions outside `allowed_regions`.
- **The ExternalId never appears in the workflow or the repo:** generated by
  `random_password`, stored as an SSM SecureString in the tooling account,
  readable only by the pipeline role, and marked sensitive in Terraform
  (`trust_policy_json` is a sensitive output).
- **CloudTrail traceability:** the session name and tags carry the repository,
  ref, run id and actor.
- **Credentials in CI logs:** `--format github-env` prints `::add-mask::` for
  the secret key and session token.
- **Terraform state contains the ExternalId** (as it contains every generated
  value): use an encrypted remote backend with restricted access.

## Idempotency

- Both modules are plain resources with no `local-exec`: `terraform plan`
  after apply shows no changes.
- Trust policies name account principals and pin the role with
  `aws:PrincipalArn`, so each role can be created before the other exists and
  re-creating the pipeline role does not break the deploy role's trust.
- `xacct lint` and `xacct verify` change nothing. `verify` only creates STS
  sessions, which expire by themselves.

## Development

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest                                  # 125 tests, coverage gate 90%
pytest tests/test_render.py -v          # just the human-readable output
(cd modules/deploy-role && terraform init -backend=false && terraform test)    # 18 tests
(cd modules/pipeline-role && terraform init -backend=false && terraform test)  # 10 tests
```

Terraform tests use a mock AWS provider and assert on the trust, deploy and
guardrail documents and on input validation. Python tests use moto for STS,
SSM and IAM, and a small fake STS/IAM (`tests/conftest.py`) that **enforces**
trust policies: moto accepts any AssumeRole, so it cannot show that a wrong
ExternalId is refused.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs terraform
fmt/validate/test, tflint, checkov, ruff, mypy, pytest on Python 3.11 and 3.13,
and `xacct lint` on the example policies (a deliberately bad one must fail).
`main` is protected: changes go through a PR and must pass CI.

### Tested against real AWS (2026-10-20, single account, us-east-1)

The [e2e harness](e2e/aws/README.md) deployed both modules (11 resources),
was checked as below, and was destroyed with nothing left behind. One account
played both the tooling and the target role: STS evaluates the trust policy
the same way across accounts.

| Check | Result |
|---|---|
| `xacct verify` trust (real STS) | 5/5: pipeline reached; no ExternalId refused; wrong ExternalId refused; correct one accepted **with session tags**; the IAM user (who has `sts:AssumeRole *`) refused even with the right ExternalId |
| `xacct verify` permissions (IAM simulator) | 15/15: 5 allowed, 10 denied (3 by explicit guardrail deny: `iam:CreateUser`, `iam:PutRolePolicy` on itself, `cloudtrail:StopLogging`; 1 by the region deny) |
| `xacct lint --role ... --access-analyzer` on the live roles | 5 documents, 0 findings |
| Real calls as the deploy role | S3 put/list under `artifacts/` OK; put under `other/` and list of the bucket root AccessDenied; ECR login OK in us-east-1, explicit deny in eu-west-1; `iam create-user` explicit deny; `DeleteBucket` AccessDenied |
| `terraform plan -detailed-exitcode` after apply | `0` (idempotent) |

The first run failed 3 of 20 checks and found two bugs that no mocked test
could show (both fixed, with tests):

1. **Session tags broke AssumeRole.** `sts:TagSession` was in the same trust
   statement as the `sts:ExternalId` condition. STS evaluates `TagSession` as
   its own action, without the `sts:ExternalId` key, so every AssumeRole that
   carried tags was refused. It now has its own statement, still pinned to the
   pipeline role.
2. **`xacct verify` skipped conditions in the simulator.** Context values were
   sent as `stringList` (multi-valued); plain operators such as `StringLike`
   and `StringNotEquals` do not match multi-valued keys, so the `s3:prefix`
   allow and the region deny were ignored. Single values are now sent as
   `string`.

Not tested for real: a GitHub Actions job assuming the pipeline role through
OIDC (the harness starts the chain from an IAM user), and two separate AWS
accounts.

## License

MIT
