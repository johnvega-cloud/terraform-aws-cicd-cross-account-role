# Unit tests for the deploy-role module.
#
# They run with a MOCK AWS provider: no credentials, no AWS calls, no cost.
# Run them from modules/deploy-role:   terraform init -backend=false && terraform test
#
# What they prove: the trust policy pins the exact pipeline role and the
# ExternalId, the guardrails are wired, and bad inputs are rejected before
# anything reaches AWS. What they do NOT prove: that STS and IAM really enforce
# it (that is what e2e/aws/ and `xacct verify` are for).

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "222222222222"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::222222222222:role/mock"
    }
  }
}

variables {
  name              = "cicd-deploy-app1"
  trusted_role_arns = ["arn:aws:iam::111111111111:role/cicd-pipeline"]
  external_id       = "0123456789abcdef0123456789abcdef"
  policy_statements = [
    {
      sid       = "PushArtifacts"
      actions   = ["s3:PutObject"]
      resources = ["arn:aws:s3:::app1-artifacts/releases/*"]
    },
  ]
}

# --- Trust policy -----------------------------------------------------------------

run "trust_pins_account_role_and_external_id" {
  command = plan

  assert {
    condition     = one(data.aws_iam_policy_document.trust.statement[0].principals).identifiers == toset(["arn:aws:iam::111111111111:root"])
    error_message = "Principal must be the pipeline account, not \"*\" and not the role's unique ID."
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.test == "ArnEquals" && c.variable == "aws:PrincipalArn" && c.values == tolist(["arn:aws:iam::111111111111:role/cicd-pipeline"])
    ])
    error_message = "Trust must pin the exact pipeline role with aws:PrincipalArn."
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.test == "StringEquals" && c.variable == "sts:ExternalId" && c.values == tolist([var.external_id])
    ])
    error_message = "Trust must require the ExternalId."
  }

  assert {
    condition     = data.aws_iam_policy_document.trust.statement[0].actions == toset(["sts:AssumeRole"])
    error_message = "Without allow_session_tags only sts:AssumeRole is trusted."
  }

  assert {
    condition     = length(data.aws_iam_policy_document.trust.statement[0].condition) == 2
    error_message = "No org condition unless principal_org_id is set."
  }

  assert {
    condition     = aws_iam_role.this.max_session_duration == 3600
    error_message = "Default session must be 1 hour."
  }
}

run "two_roles_same_account_one_principal" {
  command = plan

  variables {
    trusted_role_arns = [
      "arn:aws:iam::111111111111:role/cicd-pipeline",
      "arn:aws:iam::111111111111:role/ci/cicd-pipeline-hotfix",
      "arn:aws:iam::333333333333:role/cicd-pipeline",
    ]
  }

  assert {
    condition = one(data.aws_iam_policy_document.trust.statement[0].principals).identifiers == toset([
      "arn:aws:iam::111111111111:root",
      "arn:aws:iam::333333333333:root",
    ])
    error_message = "Account roots must be de-duplicated."
  }
}

run "org_condition_and_session_tags" {
  command = plan

  variables {
    principal_org_id   = "o-abc123def4"
    allow_session_tags = true
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.variable == "aws:PrincipalOrgID" && c.values == tolist(["o-abc123def4"])
    ])
    error_message = "principal_org_id must add an aws:PrincipalOrgID condition."
  }

  assert {
    condition     = data.aws_iam_policy_document.trust.statement[0].actions == toset(["sts:AssumeRole", "sts:TagSession"])
    error_message = "allow_session_tags must add sts:TagSession."
  }
}

# --- Permissions and guardrails --------------------------------------------------

run "guardrails_on_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_role_policy.guardrails) == 1
    error_message = "Guardrails must be attached by default."
  }

  assert {
    condition     = contains(data.aws_iam_policy_document.guardrails.statement[0].actions, "cloudtrail:StopLogging")
    error_message = "Default deny list must cover audit tampering."
  }

  assert {
    condition     = data.aws_iam_policy_document.guardrails.statement[1].resources == toset(["arn:aws:iam::222222222222:role/cicd-deploy-app1"])
    error_message = "Self-protection must target this role's own ARN."
  }

  assert {
    condition     = length(data.aws_iam_policy_document.guardrails.statement) == 2
    error_message = "No region statement unless allowed_regions is set."
  }

  assert {
    condition     = data.aws_iam_policy_document.deploy.statement[0].actions == toset(["s3:PutObject"])
    error_message = "Deploy statements must be passed through unchanged."
  }
}

run "self_protection_uses_path" {
  command = plan

  variables {
    path = "/cicd/"
  }

  assert {
    condition     = data.aws_iam_policy_document.guardrails.statement[1].resources == toset(["arn:aws:iam::222222222222:role/cicd/cicd-deploy-app1"])
    error_message = "Self-protection ARN must include the IAM path."
  }
}

run "region_guardrail" {
  command = plan

  variables {
    allowed_regions = ["us-east-1", "eu-west-1"]
  }

  assert {
    condition     = data.aws_iam_policy_document.guardrails.statement[2].sid == "DenyOutsideAllowedRegions"
    error_message = "allowed_regions must add the region deny."
  }

  assert {
    condition     = contains(data.aws_iam_policy_document.guardrails.statement[2].not_actions, "iam:*")
    error_message = "Global services must be exempt from the region deny."
  }
}

run "guardrails_can_be_disabled" {
  command = plan

  variables {
    enable_guardrails = false
  }

  assert {
    condition     = length(aws_iam_role_policy.guardrails) == 0
    error_message = "enable_guardrails = false must drop the guardrail policy."
  }
}

run "managed_policies_attached" {
  command = plan

  variables {
    managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.managed) == 1
    error_message = "Each managed policy ARN must be attached."
  }
}

run "explicit_deny_with_service_wildcard_is_allowed" {
  command = plan

  variables {
    policy_statements = [
      { sid = "Push", actions = ["s3:PutObject"], resources = ["arn:aws:s3:::b/*"] },
      { sid = "NoDeletes", effect = "Deny", actions = ["s3:*"], resources = ["arn:aws:s3:::prod-data/*"] },
    ]
  }
}

# --- Input validation ----------------------------------------------------------

run "rejects_short_external_id" {
  command = plan

  variables {
    external_id = "short"
  }

  expect_failures = [var.external_id]
}

run "rejects_external_id_bad_chars" {
  command = plan

  variables {
    external_id = "0123456789abcdef 0123456789abcdef"
  }

  expect_failures = [var.external_id]
}

run "rejects_wildcard_trusted_role" {
  command = plan

  variables {
    trusted_role_arns = ["arn:aws:iam::111111111111:role/*"]
  }

  expect_failures = [var.trusted_role_arns]
}

run "rejects_account_root_as_trusted_role" {
  command = plan

  variables {
    trusted_role_arns = ["arn:aws:iam::111111111111:root"]
  }

  expect_failures = [var.trusted_role_arns]
}

run "rejects_star_action" {
  command = plan

  variables {
    policy_statements = [{ sid = "All", actions = ["*"], resources = ["*"] }]
  }

  expect_failures = [var.policy_statements]
}

run "rejects_service_wildcard_allow" {
  command = plan

  variables {
    policy_statements = [{ sid = "AllS3", actions = ["s3:*"], resources = ["arn:aws:s3:::b/*"] }]
  }

  expect_failures = [var.policy_statements]
}

run "rejects_bad_sid" {
  command = plan

  variables {
    policy_statements = [{ sid = "push-artifacts", actions = ["s3:PutObject"], resources = ["arn:aws:s3:::b/*"] }]
  }

  expect_failures = [var.policy_statements]
}

run "rejects_long_session" {
  command = plan

  variables {
    max_session_duration = 86400
  }

  expect_failures = [var.max_session_duration]
}

run "rejects_bad_org_id" {
  command = plan

  variables {
    principal_org_id = "123456789012"
  }

  expect_failures = [var.principal_org_id]
}
