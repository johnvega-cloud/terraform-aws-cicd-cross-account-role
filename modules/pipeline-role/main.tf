# Pipeline role: lives in the TOOLING (CI/CD) account. The CI runner gets it
# (GitHub OIDC, or an existing AWS identity) and the only thing it can do is
# assume the listed deploy roles and read their ExternalIds.

data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition

  trusted_principal_accounts = distinct([
    for arn in var.trusted_principal_arns :
    "arn:${local.partition}:iam::${split(":", arn)[4]}:root"
  ])

  assume_actions = var.allow_session_tags ? ["sts:AssumeRole", "sts:TagSession"] : ["sts:AssumeRole"]
}

# --- Trust policy -------------------------------------------------------------------

data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = var.github_oidc == null ? [] : [var.github_oidc]
    content {
      sid     = "GitHubActionsOidc"
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]

      principals {
        type        = "Federated"
        identifiers = [statement.value.provider_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = [statement.value.audience]
      }

      # StringLike so a caller may pass e.g. "repo:org/app:ref:refs/tags/v*";
      # the variable validation already rejects subjects that span repositories.
      condition {
        test     = "StringLike"
        variable = "token.actions.githubusercontent.com:sub"
        values   = statement.value.subjects
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) > 0 ? [var.trusted_principal_arns] : []
    content {
      sid     = "TrustedAwsPrincipals"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = local.trusted_principal_accounts
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = statement.value
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.name
  path                 = var.path
  description          = "CI/CD pipeline role: may only assume the listed deploy roles."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags

  lifecycle {
    precondition {
      condition     = var.github_oidc != null || length(var.trusted_principal_arns) > 0
      error_message = "Set github_oidc and/or trusted_principal_arns: otherwise nobody can assume the pipeline role."
    }
  }
}

# --- Permissions --------------------------------------------------------------------

data "aws_iam_policy_document" "permissions" {
  statement {
    sid       = "AssumeDeployRoles"
    effect    = "Allow"
    actions   = local.assume_actions
    resources = var.target_role_arns
  }

  dynamic "statement" {
    for_each = length(var.external_id_parameter_arns) > 0 ? [var.external_id_parameter_arns] : []
    content {
      sid       = "ReadExternalIds"
      effect    = "Allow"
      actions   = ["ssm:GetParameter"]
      resources = statement.value
    }
  }
}

resource "aws_iam_role_policy" "permissions" {
  name   = "assume-deploy-roles"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.permissions.json
}
