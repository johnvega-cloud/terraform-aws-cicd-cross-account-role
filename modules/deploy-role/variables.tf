# --- Identity ---------------------------------------------------------------------

variable "name" {
  description = "Name of the deploy role in the target account (e.g. \"cicd-deploy-app1\")."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.name))
    error_message = "IAM role names are 1-64 characters from [A-Za-z0-9+=,.@_-]."
  }
}

variable "path" {
  description = "IAM path for the role. A dedicated path (e.g. \"/cicd/\") makes SCPs and audits easier to scope."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([A-Za-z0-9+=,.@_-]+/)*$", var.path))
    error_message = "path must start and end with \"/\" (e.g. \"/\" or \"/cicd/\")."
  }
}

# --- Who may assume the role --------------------------------------------------------

variable "trusted_role_arns" {
  description = <<-EOT
    ARNs of the pipeline role(s) allowed to assume this role. Exact ARNs only:
    the trust policy names their accounts as principals and pins the role with
    an aws:PrincipalArn condition, so the role does not have to exist yet and
    re-creating it does not break the trust.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.trusted_role_arns) > 0
    error_message = "At least one trusted pipeline role ARN is required."
  }

  validation {
    condition = alltrue([
      for arn in var.trusted_role_arns :
      can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn)) && !strcontains(arn, "*")
    ])
    error_message = "trusted_role_arns must be exact IAM role ARNs (arn:<partition>:iam::<12 digits>:role/<name>), no wildcards."
  }
}

variable "external_id" {
  description = <<-EOT
    Value the pipeline must pass as ExternalId. Generate it (random_password)
    and hand it to the pipeline out of band (SSM parameter or CI secret).
    At least 16 characters so it cannot be guessed.
  EOT
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.external_id) >= 16 && length(var.external_id) <= 1224
    error_message = "external_id must be 16-1224 characters long."
  }

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@:/_-]+$", var.external_id))
    error_message = "external_id may only contain [A-Za-z0-9+=,.@:/_-] (the characters STS accepts)."
  }
}

variable "principal_org_id" {
  description = "If set, the caller must also belong to this AWS Organization (aws:PrincipalOrgID), e.g. \"o-abc123def4\"."
  type        = string
  default     = null

  validation {
    condition     = var.principal_org_id == null || can(regex("^o-[a-z0-9]{10,32}$", var.principal_org_id))
    error_message = "principal_org_id must look like o-xxxxxxxxxx."
  }
}

variable "allow_session_tags" {
  description = "Allow sts:TagSession, so the pipeline can tag its session (repo, run id) for CloudTrail and ABAC."
  type        = bool
  default     = false
}

variable "max_session_duration" {
  description = "Maximum session length in seconds. The pipeline reaches this role by role chaining, which AWS caps at 1 hour anyway."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 3600 and 43200 seconds (AWS limits)."
  }
}

# --- What the role may do -------------------------------------------------------

variable "policy_statements" {
  description = <<-EOT
    The deploy permissions, as IAM statements. Keep them narrow: exact
    actions and resource ARNs. Wildcard actions ("*", "service:*") are rejected
    here; `xacct lint` checks the finer rules (Resource "*", PassRole, escalation).
  EOT
  type = list(object({
    sid       = string
    effect    = optional(string, "Allow")
    actions   = list(string)
    resources = list(string)
    conditions = optional(list(object({
      test     = string
      variable = string
      values   = list(string)
    })), [])
  }))

  validation {
    condition     = length(var.policy_statements) > 0
    error_message = "A deploy role needs at least one policy statement."
  }

  validation {
    condition     = alltrue([for s in var.policy_statements : contains(["Allow", "Deny"], s.effect)])
    error_message = "effect must be \"Allow\" or \"Deny\"."
  }

  validation {
    condition     = alltrue([for s in var.policy_statements : can(regex("^[A-Za-z0-9]+$", s.sid))])
    error_message = "sid must be alphanumeric (IAM rule)."
  }

  validation {
    condition = alltrue(flatten([
      for s in var.policy_statements : [
        for a in s.actions : s.effect == "Deny" || !can(regex("^(\\*|[a-z0-9-]+:\\*)$", a))
      ]
    ]))
    error_message = "Allow statements may not use \"*\" or \"service:*\" actions: list the exact actions the pipeline needs."
  }
}

variable "managed_policy_arns" {
  description = "Extra managed policies to attach (e.g. a shared read-only policy). Prefer policy_statements."
  type        = list(string)
  default     = []
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary for the role. Recommended where the organization defines one for CI/CD roles."
  type        = string
  default     = null
}

# --- Guardrails -------------------------------------------------------------------

variable "enable_guardrails" {
  description = "Attach the explicit-deny guardrail policy (deny_actions, self-protection, allowed_regions)."
  type        = bool
  default     = true
}

variable "deny_actions" {
  description = "Actions denied even if a future policy statement allows them. The default covers account takeover and audit tampering."
  type        = list(string)
  default = [
    "organizations:*",
    "account:*",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AddUserToGroup",
    "iam:CreateOpenIDConnectProvider",
    "iam:CreateSAMLProvider",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors",
    "config:StopConfigurationRecorder",
    "config:DeleteConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "guardduty:DeleteDetector",
    "guardduty:UpdateDetector",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
    "kms:PutKeyPolicy",
  ]
}

variable "allowed_regions" {
  description = "If not empty, deny every regional action outside these regions (global services such as IAM, STS and CloudFront are exempt)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.allowed_regions : can(regex("^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-[0-9]$", r))])
    error_message = "allowed_regions must be region codes such as us-east-1."
  }
}

variable "tags" {
  description = "Tags for the role."
  type        = map(string)
  default     = {}
}
