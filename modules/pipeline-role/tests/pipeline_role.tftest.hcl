# Unit tests for the pipeline-role module (mock AWS provider, no credentials).
# Run them from modules/pipeline-role:   terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111111111111:role/mock"
    }
  }
}

variables {
  name             = "cicd-pipeline"
  target_role_arns = ["arn:aws:iam::222222222222:role/cicd-deploy-app1"]
  github_oidc = {
    provider_arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    subjects     = ["repo:acme/app1:ref:refs/heads/main"]
  }
}

# --- Trust ------------------------------------------------------------------------

run "github_oidc_trust" {
  command = plan

  assert {
    condition     = data.aws_iam_policy_document.trust.statement[0].actions == toset(["sts:AssumeRoleWithWebIdentity"])
    error_message = "GitHub OIDC must use AssumeRoleWithWebIdentity."
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.variable == "token.actions.githubusercontent.com:aud" && c.values == tolist(["sts.amazonaws.com"])
    ])
    error_message = "Trust must check the audience."
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.variable == "token.actions.githubusercontent.com:sub" && c.values == tolist(["repo:acme/app1:ref:refs/heads/main"])
    ])
    error_message = "Trust must pin the repository and ref (sub claim)."
  }

  assert {
    condition     = length(data.aws_iam_policy_document.trust.statement) == 1
    error_message = "No AWS principal statement unless trusted_principal_arns is set."
  }
}

run "aws_principals_trust" {
  command = plan

  variables {
    github_oidc            = null
    trusted_principal_arns = ["arn:aws:iam::111111111111:role/jenkins-agent"]
  }

  assert {
    condition     = one(data.aws_iam_policy_document.trust.statement[0].principals).identifiers == toset(["arn:aws:iam::111111111111:root"])
    error_message = "AWS principals must be the account, pinned by aws:PrincipalArn."
  }

  assert {
    condition = anytrue([
      for c in data.aws_iam_policy_document.trust.statement[0].condition :
      c.variable == "aws:PrincipalArn" && c.values == tolist(["arn:aws:iam::111111111111:role/jenkins-agent"])
    ])
    error_message = "Trust must pin the exact principal ARN."
  }
}

run "nobody_trusted_fails" {
  command = plan

  variables {
    github_oidc = null
  }

  expect_failures = [aws_iam_role.this]
}

# --- Permissions ------------------------------------------------------------------

run "only_assume_listed_targets" {
  command = plan

  assert {
    condition     = data.aws_iam_policy_document.permissions.statement[0].actions == toset(["sts:AssumeRole"])
    error_message = "The pipeline role may only assume roles."
  }

  assert {
    condition     = data.aws_iam_policy_document.permissions.statement[0].resources == toset(var.target_role_arns)
    error_message = "AssumeRole must be limited to the target ARNs."
  }

  assert {
    condition     = length(data.aws_iam_policy_document.permissions.statement) == 1
    error_message = "No SSM statement unless parameter ARNs are given."
  }
}

run "ssm_and_session_tags" {
  command = plan

  variables {
    allow_session_tags         = true
    external_id_parameter_arns = ["arn:aws:ssm:us-east-1:111111111111:parameter/cicd/app1/external-id"]
  }

  assert {
    condition     = data.aws_iam_policy_document.permissions.statement[0].actions == toset(["sts:AssumeRole", "sts:TagSession"])
    error_message = "allow_session_tags must add sts:TagSession."
  }

  assert {
    condition     = data.aws_iam_policy_document.permissions.statement[1].resources == toset(["arn:aws:ssm:us-east-1:111111111111:parameter/cicd/app1/external-id"])
    error_message = "SSM read must be limited to the given parameters."
  }
}

# --- Input validation ----------------------------------------------------------

run "rejects_any_repo_subject" {
  command = plan

  variables {
    github_oidc = {
      provider_arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      subjects     = ["repo:acme/*"]
    }
  }

  expect_failures = [var.github_oidc]
}

run "rejects_star_subject" {
  command = plan

  variables {
    github_oidc = {
      provider_arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      subjects     = ["*"]
    }
  }

  expect_failures = [var.github_oidc]
}

run "rejects_other_oidc_provider" {
  command = plan

  variables {
    github_oidc = {
      provider_arn = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC"
      subjects     = ["repo:acme/app1:ref:refs/heads/main"]
    }
  }

  expect_failures = [var.github_oidc]
}

run "rejects_wildcard_target" {
  command = plan

  variables {
    target_role_arns = ["arn:aws:iam::222222222222:role/*"]
  }

  expect_failures = [var.target_role_arns]
}

run "rejects_wildcard_parameter" {
  command = plan

  variables {
    external_id_parameter_arns = ["arn:aws:ssm:us-east-1:111111111111:parameter/cicd/*"]
  }

  expect_failures = [var.external_id_parameter_arns]
}
