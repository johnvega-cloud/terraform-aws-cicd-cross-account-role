# Output names match what `xacct --tf-output` reads:
#   terraform output -json > out.json && xacct verify --tf-output out.json

output "pipeline_role_arn" {
  description = "Pipeline role (first hop)."
  value       = module.pipeline_role.role_arn
}

output "deploy_role_arn" {
  description = "Deploy role (second hop, needs the ExternalId)."
  value       = module.deploy_role.role_arn
}

output "external_id_parameter_name" {
  description = "SSM parameter holding the ExternalId (readable by the pipeline role only)."
  value       = aws_ssm_parameter.external_id.name
}

output "bucket" {
  description = "Artifact bucket the deploy role may write under artifacts/."
  value       = aws_s3_bucket.artifacts.bucket
}

output "ecr_repository_url" {
  description = "ECR repository the deploy role may push to."
  value       = aws_ecr_repository.app.repository_url
}

# What `xacct verify` asks the IAM policy simulator. Built here, from the same
# names Terraform used, so the expectations cannot drift from the deployment.
output "expectations" {
  description = "Allowed/denied action checks for `xacct verify`."
  value = {
    allowed = [
      { action = "s3:PutObject", resource = "${aws_s3_bucket.artifacts.arn}/artifacts/app.zip" },
      { action = "s3:GetObject", resource = "${aws_s3_bucket.artifacts.arn}/artifacts/app.zip" },
      { action = "s3:ListBucket", resource = aws_s3_bucket.artifacts.arn, context = { "s3:prefix" = ["artifacts/"] } },
      { action = "ecr:PutImage", resource = aws_ecr_repository.app.arn },
      { action = "ecr:GetAuthorizationToken", resource = "*" },
    ]
    denied = [
      { action = "s3:PutObject", resource = "${aws_s3_bucket.artifacts.arn}/other/app.zip" },
      { action = "s3:ListBucket", resource = aws_s3_bucket.artifacts.arn, context = { "s3:prefix" = ["secrets/"] } },
      { action = "s3:DeleteBucket", resource = aws_s3_bucket.artifacts.arn },
      { action = "ecr:PutImage", resource = "${aws_ecr_repository.app.arn}-other" },
      { action = "ecr:DeleteRepository", resource = aws_ecr_repository.app.arn },
      { action = "iam:CreateUser", resource = "*" },
      { action = "iam:PutRolePolicy", resource = module.deploy_role.role_arn },
      { action = "cloudtrail:StopLogging", resource = "*" },
      { action = "ec2:RunInstances", resource = "*" },
      { action = "ecr:GetAuthorizationToken", resource = "*", context = { "aws:RequestedRegion" = ["eu-west-1"] } },
    ]
  }
}
