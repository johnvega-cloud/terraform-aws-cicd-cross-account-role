# Real-world layout: a tooling account runs CI/CD (GitHub Actions via OIDC),
# and each workload account gets a deploy role the pipeline assumes with an
# ExternalId. One root config, two provider aliases.
#
#   GitHub Actions --OIDC--> pipeline role (tooling) --AssumeRole + ExternalId--> deploy role (target)
#
# Run it with credentials that can reach both accounts (e.g. a platform admin
# role in tooling that can assume `target_admin_role_arn`).

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  alias  = "tooling"
  region = var.region
}

provider "aws" {
  alias  = "target"
  region = var.region

  assume_role {
    role_arn = var.target_admin_role_arn
  }
}

data "aws_caller_identity" "tooling" {
  provider = aws.tooling
}

data "aws_caller_identity" "target" {
  provider = aws.target
}

locals {
  pipeline_role_name = "cicd-pipeline-${var.app}"
  deploy_role_name   = "cicd-deploy-${var.app}"

  pipeline_role_arn = "arn:aws:iam::${data.aws_caller_identity.tooling.account_id}:role/cicd/${local.pipeline_role_name}"
  deploy_role_arn   = "arn:aws:iam::${data.aws_caller_identity.target.account_id}:role/cicd/${local.deploy_role_name}"
}

# --- ExternalId: generated once, stored in the tooling account -----------------

resource "random_password" "external_id" {
  length  = 40
  special = false
}

resource "aws_ssm_parameter" "external_id" {
  # checkov:skip=CKV_AWS_337:The default aws/ssm key is enough: an ExternalId is not a credential (AWS treats it as an identifier), it only has to be unguessable and not public.
  provider = aws.tooling

  name  = "/cicd/${var.app}/external-id"
  type  = "SecureString"
  value = random_password.external_id.result
}

# --- Tooling account --------------------------------------------------------------

module "pipeline_role" {
  source = "../../modules/pipeline-role"
  providers = {
    aws = aws.tooling
  }

  name = local.pipeline_role_name
  path = "/cicd/"
  github_oidc = {
    provider_arn = var.github_oidc_provider_arn
    subjects     = ["repo:${var.github_repository}:environment:${var.github_environment}"]
  }
  target_role_arns           = [local.deploy_role_arn]
  external_id_parameter_arns = [aws_ssm_parameter.external_id.arn]
  allow_session_tags         = true
}

# --- Target (workload) account ----------------------------------------------------

module "deploy_role" {
  source = "../../modules/deploy-role"
  providers = {
    aws = aws.target
  }

  name               = local.deploy_role_name
  path               = "/cicd/"
  trusted_role_arns  = [local.pipeline_role_arn]
  external_id        = random_password.external_id.result
  principal_org_id   = var.organization_id
  allow_session_tags = true
  allowed_regions    = [var.region]

  # A container app on ECS: push the image, register a task definition,
  # roll the service, and pass only the app's own task roles to ECS.
  policy_statements = [
    {
      sid = "EcrPush"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
      ]
      resources = ["arn:aws:ecr:${var.region}:${data.aws_caller_identity.target.account_id}:repository/${var.app}"]
    },
    {
      sid       = "EcrLogin"
      actions   = ["ecr:GetAuthorizationToken"]
      resources = ["*"]
    },
    {
      sid       = "TaskDefinitions"
      actions   = ["ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition"]
      resources = ["*"] # no resource-level permissions for these two
    },
    {
      sid       = "RollService"
      actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
      resources = ["arn:aws:ecs:${var.region}:${data.aws_caller_identity.target.account_id}:service/${var.ecs_cluster}/${var.app}"]
    },
    {
      sid     = "PassAppTaskRoles"
      actions = ["iam:PassRole"]
      resources = [
        "arn:aws:iam::${data.aws_caller_identity.target.account_id}:role/${var.app}-task",
        "arn:aws:iam::${data.aws_caller_identity.target.account_id}:role/${var.app}-execution",
      ]
      conditions = [{
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["ecs-tasks.amazonaws.com"]
      }]
    },
  ]
}
