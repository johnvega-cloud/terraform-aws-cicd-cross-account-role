# Version constraints for the reusable pipeline-role module.
#
# A reusable MODULE declares the widest range it is known to work with; each
# ROOT configuration (examples/, e2e/) pins the exact build in its lock file.

terraform {
  # 1.7+ is required for `terraform test` with mock providers (used in tests/).
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}
