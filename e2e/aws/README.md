# End-to-end test (real AWS)

Deploys both modules in one real account, proves with real STS calls that the
trust works the way the design says, checks the permissions with the IAM
policy simulator and with real S3 calls, and is destroyed afterwards.

Unit tests (`terraform test` with a mocked provider, pytest with moto and
fakes) prove the configuration is right; this proves AWS agrees.

**Identity chain:** you (IAM user) → `jv-e2e-pipeline` → `jv-e2e-deploy` (ExternalId).
One account plays both the tooling and the target account: STS evaluates the
trust policy exactly as it would across accounts.

**Cost:** nothing measurable (IAM, SSM standard parameter, empty S3 bucket and
ECR repository).

**Caller:** run it as an IAM **user** or a role ARN that is stable: the
pipeline role trusts `data.aws_caller_identity.current.arn`, and an
assumed-role session ARN (`arn:aws:sts::...:assumed-role/...`) is rejected by
the module's validation.

## Run

```bash
cd e2e/aws
terraform init
# Accounts whose IAM policies only allow names matching a pattern:
#   add -var iam_role_name_prefix=<prefix>
terraform plan -out=tfplan
terraform show -json tfplan > plan.json && xacct lint --plan plan.json
terraform apply tfplan
terraform output -json > out.json
```

## Checks

```bash
# 1. Trust (real STS) + permissions (IAM policy simulator), 20 checks
xacct verify --tf-output out.json --region us-east-1 --tag ci-run-id=e2e --report report.json

# 2. Lint the live roles (every inline/attached policy and the trust policy)
xacct lint --role "$(terraform output -raw deploy_role_arn | cut -d/ -f2)" \
           --role "$(terraform output -raw pipeline_role_arn | cut -d/ -f2)" --access-analyzer

# 3. Real calls as the deploy role
eval "$(xacct assume --tf-output out.json --region us-east-1 --tag ci-run-id=e2e)"
BUCKET=$(terraform output -raw bucket)
echo ok | aws s3 cp - "s3://$BUCKET/artifacts/app.txt"            # expected: works
echo no | aws s3 cp - "s3://$BUCKET/other/app.txt"                # expected: AccessDenied
aws s3 ls "s3://$BUCKET/artifacts/"                               # expected: works
aws ecr get-login-password >/dev/null && echo ECR_LOGIN=ok        # expected: ok
aws ecr get-login-password --region eu-west-1                     # expected: AccessDenied (granted, but the region guardrail denies)
aws iam create-user --user-name should-fail                       # expected: AccessDenied
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# 4. Idempotency
terraform plan -detailed-exitcode                                 # expected: exit 0
```

| Check | Expected | Proves |
|---|---|---|
| verify: reach pipeline role | PASS | hop 1 works for the trusted user |
| verify: no / wrong ExternalId | refused | the `sts:ExternalId` condition is enforced |
| verify: correct ExternalId (with session tags) | accepted, `assumed-role/...-deploy/` | hop 2 + `sts:TagSession` |
| verify: non-pipeline principal | refused | the `aws:PrincipalArn` pin (your user has `sts:AssumeRole *`, still refused) |
| verify: 5 allowed / 10 denied actions | match | least privilege, guardrail denies, region deny |
| `s3 cp .../artifacts/` vs `.../other/` | works / AccessDenied | the real S3 request, not just the simulator |
| `terraform plan -detailed-exitcode` | `0` | modules are idempotent |

## Destroy

```bash
terraform plan -destroy -out=tfdestroy   # same -var values as apply
terraform apply tfdestroy
rm -f out.json plan.json report.json
```
