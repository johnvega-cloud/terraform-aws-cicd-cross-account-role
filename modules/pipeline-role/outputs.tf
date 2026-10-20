output "role_arn" {
  description = "ARN of the pipeline role: give it to the CI runner (e.g. role-to-assume in GitHub Actions)."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Name of the pipeline role."
  value       = aws_iam_role.this.name
}

output "trust_policy_json" {
  description = "Rendered trust policy. Feed it to `xacct lint --trust`."
  value       = data.aws_iam_policy_document.trust.json
}

output "permissions_policy_json" {
  description = "Rendered permissions policy. Feed it to `xacct lint --policy`."
  value       = data.aws_iam_policy_document.permissions.json
}
