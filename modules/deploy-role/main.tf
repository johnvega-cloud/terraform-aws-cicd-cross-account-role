# Deploy role: lives in each TARGET account. The CI/CD pipeline role (in the
# tooling account) assumes it with an ExternalId and gets only the deploy
# permissions listed in var.policy_statements, minus the guardrail denies.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  partition = data.aws_partition.current.partition

  # Principal = the trusted accounts; the exact role is pinned by aws:PrincipalArn.
  # Naming the role ARN as the principal would also work, but IAM then stores the
  # role's unique ID: if the pipeline role is ever re-created the trust silently
  # breaks, and the role has to exist before this one can be created.
  trusted_account_roots = distinct([
    for arn in var.trusted_role_arns :
    "arn:${local.partition}:iam::${split(":", arn)[4]}:root"
  ])

  role_arn = "arn:${local.partition}:iam::${data.aws_caller_identity.current.account_id}:role${var.path}${var.name}"

  # Global services: their API calls are not tied to a region, so a region
  # guardrail must not block them.
  global_actions = [
    "iam:*",
    "sts:*",
    "organizations:*",
    "cloudfront:*",
    "route53:*",
    "route53domains:*",
    "waf:*",
    "support:*",
    "budgets:*",
    "ce:*",
    "health:*",
    "trustedadvisor:*",
  ]
}

# --- Trust policy -------------------------------------------------------------------

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "PipelineRoleWithExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = local.trusted_account_roots
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = var.trusted_role_arns
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }

    dynamic "condition" {
      for_each = var.principal_org_id == null ? [] : [var.principal_org_id]
      content {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [condition.value]
      }
    }
  }

  # sts:TagSession is evaluated as its own action, and the sts:ExternalId key is
  # not in its request context: putting it in the statement above (with the
  # ExternalId condition) makes every AssumeRole with tags fail. Found in the
  # real-AWS e2e run. TagSession alone grants nothing; AssumeRole still needs
  # the ExternalId.
  dynamic "statement" {
    for_each = var.allow_session_tags ? [1] : []
    content {
      sid     = "PipelineRoleSessionTags"
      effect  = "Allow"
      actions = ["sts:TagSession"]

      principals {
        type        = "AWS"
        identifiers = local.trusted_account_roots
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = var.trusted_role_arns
      }

      dynamic "condition" {
        for_each = var.principal_org_id == null ? [] : [var.principal_org_id]
        content {
          test     = "StringEquals"
          variable = "aws:PrincipalOrgID"
          values   = [condition.value]
        }
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.name
  path                 = var.path
  description          = "CI/CD deploy role, assumed cross-account by the pipeline role with an ExternalId."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

# --- Deploy permissions -----------------------------------------------------------

data "aws_iam_policy_document" "deploy" {
  dynamic "statement" {
    for_each = var.policy_statements
    content {
      sid       = statement.value.sid
      effect    = statement.value.effect
      actions   = statement.value.actions
      resources = statement.value.resources

      dynamic "condition" {
        for_each = statement.value.conditions
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

# Inline policies: they live and die with the role, cannot be attached to
# anything else by mistake, and need no extra IAM policy ARNs.
resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.deploy.json
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = each.value
}

# --- Guardrails (explicit deny) -----------------------------------------------------

data "aws_iam_policy_document" "guardrails" {
  statement {
    sid       = "DenyAccountTakeoverAndAuditTampering"
    effect    = "Deny"
    actions   = var.deny_actions
    resources = ["*"]
  }

  # The pipeline must not be able to widen its own permissions or trust.
  statement {
    sid    = "DenyChangesToThisRole"
    effect = "Deny"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePermissionsBoundary",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = [local.role_arn]
  }

  dynamic "statement" {
    for_each = length(var.allowed_regions) > 0 ? [var.allowed_regions] : []
    content {
      sid         = "DenyOutsideAllowedRegions"
      effect      = "Deny"
      not_actions = local.global_actions
      resources   = ["*"]

      condition {
        test     = "StringNotEquals"
        variable = "aws:RequestedRegion"
        values   = statement.value
      }
    }
  }
}

resource "aws_iam_role_policy" "guardrails" {
  count = var.enable_guardrails ? 1 : 0

  name   = "guardrails"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.guardrails.json
}
