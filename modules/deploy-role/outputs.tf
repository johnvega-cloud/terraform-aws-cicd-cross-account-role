output "role_arn" {
  description = "ARN of the deploy role. The pipeline passes it to sts:AssumeRole."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Name of the deploy role."
  value       = aws_iam_role.this.name
}

output "role_unique_id" {
  description = "Unique ID (AROA...) of the role, as it appears in CloudTrail."
  value       = aws_iam_role.this.unique_id
}

output "trust_policy_json" {
  description = "Rendered trust policy. Feed it to `xacct lint --trust`. Contains the ExternalId, so it is marked sensitive."
  value       = data.aws_iam_policy_document.trust.json
  sensitive   = true
}

output "deploy_policy_json" {
  description = "Rendered deploy (permissions) policy. Feed it to `xacct lint --policy`."
  value       = data.aws_iam_policy_document.deploy.json
}

output "guardrails_policy_json" {
  description = "Rendered guardrail (explicit deny) policy, or null when guardrails are disabled."
  value       = var.enable_guardrails ? data.aws_iam_policy_document.guardrails.json : null
}
