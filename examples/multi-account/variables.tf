variable "region" {
  description = "Region for both accounts."
  type        = string
  default     = "us-east-1"
}

variable "app" {
  description = "Application name; used in role names, the ECR repository and the ECS service."
  type        = string
}

variable "target_admin_role_arn" {
  description = "Role Terraform assumes in the target account to create the deploy role."
  type        = string
}

variable "github_oidc_provider_arn" {
  description = "Existing token.actions.githubusercontent.com provider in the tooling account."
  type        = string
}

variable "github_repository" {
  description = "owner/repo allowed to deploy."
  type        = string
}

variable "github_environment" {
  description = "GitHub environment the deploy job runs in (its protection rules gate the deploy)."
  type        = string
  default     = "prod"
}

variable "organization_id" {
  description = "AWS Organization ID (o-...) both accounts belong to, or null."
  type        = string
  default     = null
}

variable "ecs_cluster" {
  description = "ECS cluster that runs the app."
  type        = string
}
