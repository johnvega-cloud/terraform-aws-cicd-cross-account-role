output "pipeline_role_arn" {
  description = "Put this in the workflow as role-to-assume."
  value       = module.pipeline_role.role_arn
}

output "deploy_role_arn" {
  description = "The deploy role the workflow assumes second."
  value       = module.deploy_role.role_arn
}

output "external_id_parameter_name" {
  description = "SSM parameter the workflow reads the ExternalId from."
  value       = aws_ssm_parameter.external_id.name
}
