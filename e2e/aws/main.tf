# End-to-end harness: deploys BOTH modules in one real account and the two
# resources the deploy role is allowed to touch (an S3 artifact bucket and an
# ECR repository). The same-account setup exercises exactly the same STS/IAM
# evaluation as the cross-account one: the trust policy is still checked
# (account principal + aws:PrincipalArn + sts:ExternalId), because a role is
# never trusted implicitly, not even by its own account.
#
# Identity chain:  you (IAM user) -> pipeline role -> deploy role (ExternalId)
#
# Cost: IAM and SSM standard parameters are free; an empty S3 bucket and ECR
# repository cost nothing. Destroy it when the checks pass.

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
  region = var.region

  default_tags {
    tags = {
      Project   = "terraform-aws-cicd-cross-account-role"
      Purpose   = "e2e"
      ManagedBy = "terraform"
    }
  }
}

variable "region" {
  description = "Region for the e2e resources."
  type        = string
  default     = "us-east-1"
}

variable "iam_role_name_prefix" {
  description = "Prefix for every IAM/SSM name, for accounts that only allow names matching a pattern."
  type        = string
  default     = ""
}

variable "github_subjects" {
  description = "Optional: also trust GitHub Actions OIDC for these `sub` claims (the account's provider must exist)."
  type        = list(string)
  default     = []
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account   = data.aws_caller_identity.current.account_id
  partition = data.aws_partition.current.partition
  name      = "${var.iam_role_name_prefix}jv-e2e"

  # ARNs computed from names, so each module can reference the other role
  # without a dependency cycle (and the deploy trust does not need the
  # pipeline role to exist first: see docs/BUILD_GUIDE.md).
  pipeline_role_arn = "arn:${local.partition}:iam::${local.account}:role/${local.name}-pipeline"
  deploy_role_arn   = "arn:${local.partition}:iam::${local.account}:role/${local.name}-deploy"
}

resource "random_password" "external_id" {
  length  = 40
  special = false
}

resource "random_id" "suffix" {
  byte_length = 4
}

# --- What the pipeline deploys to -----------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts-${random_id.suffix.hex}"
  force_destroy = true # e2e only: destroy must work with objects inside
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ecr_repository" "app" {
  name                 = "${local.name}-app"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true # e2e only

  image_scanning_configuration {
    scan_on_push = true
  }
}

# --- ExternalId hand-off ----------------------------------------------------------

resource "aws_ssm_parameter" "external_id" {
  name        = "/${local.name}/external-id"
  description = "ExternalId the pipeline passes when assuming ${local.name}-deploy"
  type        = "SecureString" # default aws/ssm key
  value       = random_password.external_id.result
}

# --- The two roles --------------------------------------------------------------

module "pipeline_role" {
  source = "../../modules/pipeline-role"

  name                       = "${local.name}-pipeline"
  trusted_principal_arns     = [data.aws_caller_identity.current.arn]
  target_role_arns           = [local.deploy_role_arn]
  external_id_parameter_arns = [aws_ssm_parameter.external_id.arn]
  allow_session_tags         = true

  github_oidc = length(var.github_subjects) == 0 ? null : {
    provider_arn = "arn:${local.partition}:iam::${local.account}:oidc-provider/token.actions.githubusercontent.com"
    subjects     = var.github_subjects
  }
}

module "deploy_role" {
  source = "../../modules/deploy-role"

  name               = "${local.name}-deploy"
  trusted_role_arns  = [local.pipeline_role_arn]
  external_id        = random_password.external_id.result
  allow_session_tags = true
  allowed_regions    = [var.region]

  policy_statements = [
    {
      sid       = "ArtifactsReadWrite"
      actions   = ["s3:PutObject", "s3:GetObject"]
      resources = ["${aws_s3_bucket.artifacts.arn}/artifacts/*"]
    },
    {
      sid       = "ArtifactsList"
      actions   = ["s3:ListBucket"]
      resources = [aws_s3_bucket.artifacts.arn]
      conditions = [{
        test     = "StringLike"
        variable = "s3:prefix"
        values   = ["artifacts/*"]
      }]
    },
    {
      sid = "EcrPush"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
        "ecr:BatchGetImage",
      ]
      resources = [aws_ecr_repository.app.arn]
    },
    {
      sid       = "EcrLogin"
      actions   = ["ecr:GetAuthorizationToken"] # no resource-level permissions
      resources = ["*"]
    },
  ]
}
