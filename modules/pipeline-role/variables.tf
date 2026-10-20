# --- Identity ---------------------------------------------------------------------

variable "name" {
  description = "Name of the pipeline role in the tooling (CI/CD) account."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.name))
    error_message = "IAM role names are 1-64 characters from [A-Za-z0-9+=,.@_-]."
  }
}

variable "path" {
  description = "IAM path for the role."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([A-Za-z0-9+=,.@_-]+/)*$", var.path))
    error_message = "path must start and end with \"/\"."
  }
}

# --- Who is the pipeline ------------------------------------------------------------

variable "github_oidc" {
  description = <<-EOT
    Trust GitHub Actions through OIDC (no long-lived keys). provider_arn is the
    account's existing token.actions.githubusercontent.com provider (one per
    account, usually managed by the platform team). subjects are the exact
    `sub` claims allowed, e.g. "repo:my-org/my-app:ref:refs/heads/main" or
    "repo:my-org/my-app:environment:prod".
  EOT
  type = object({
    provider_arn = string
    subjects     = list(string)
    audience     = optional(string, "sts.amazonaws.com")
  })
  default = null

  validation {
    condition = var.github_oidc == null || can(regex(
      "^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$",
      var.github_oidc.provider_arn
    ))
    error_message = "github_oidc.provider_arn must be the token.actions.githubusercontent.com OIDC provider ARN."
  }

  validation {
    condition = var.github_oidc == null || (
      length(var.github_oidc.subjects) > 0 &&
      alltrue([
        for s in var.github_oidc.subjects :
        can(regex("^repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+$", s))
      ])
    )
    error_message = "Each subject must name one repository: \"repo:<owner>/<repo>:<ref|environment|pull_request>...\". \"*\" or \"repo:<owner>/*\" would let any repository assume the role."
  }
}

variable "trusted_principal_arns" {
  description = <<-EOT
    IAM principals (roles or users) that may assume the pipeline role, for CI
    systems that already run with an AWS identity (Jenkins on EC2, CodeBuild)
    or for a manual end-to-end test.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.trusted_principal_arns :
      can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/.+$", arn)) && !strcontains(arn, "*")
    ])
    error_message = "trusted_principal_arns must be exact IAM role or user ARNs, no wildcards."
  }
}

# --- What the pipeline may do -------------------------------------------------------

variable "target_role_arns" {
  description = "Deploy roles (one per target account/app) the pipeline may assume. Exact ARNs: this role can do nothing else."
  type        = list(string)

  validation {
    condition     = length(var.target_role_arns) > 0
    error_message = "At least one target deploy role ARN is required."
  }

  validation {
    condition = alltrue([
      for arn in var.target_role_arns :
      can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn)) && !strcontains(arn, "*")
    ])
    error_message = "target_role_arns must be exact IAM role ARNs, no wildcards."
  }
}

variable "external_id_parameter_arns" {
  description = "SSM parameters holding the ExternalIds. The pipeline gets ssm:GetParameter on exactly these."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.external_id_parameter_arns :
      can(regex("^arn:aws[a-z-]*:ssm:[a-z0-9-]+:[0-9]{12}:parameter/.+$", arn)) && !strcontains(arn, "*")
    ])
    error_message = "external_id_parameter_arns must be exact SSM parameter ARNs."
  }
}

variable "allow_session_tags" {
  description = "Also allow sts:TagSession on the targets (they must allow it too)."
  type        = bool
  default     = false
}

variable "max_session_duration" {
  description = "Maximum session length in seconds for the pipeline role itself."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 3600 and 43200 seconds."
  }
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary for the role."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for the role."
  type        = map(string)
  default     = {}
}
