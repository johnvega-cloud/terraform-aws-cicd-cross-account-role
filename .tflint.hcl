# TFLint: catches what `terraform validate` cannot (unused declarations,
# missing descriptions/types, invalid AWS values such as instance types).
# Run from the repo root:  tflint --init && tflint --recursive

config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "0.49.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# Module best practices that "recommended" leaves off
rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_naming_convention" {
  enabled = true
}
