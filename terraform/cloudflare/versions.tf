terraform {
  required_version = ">= 1.6"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# The token is read from the CLOUDFLARE_API_TOKEN environment variable, never
# from a Terraform variable. A variable would be recorded in tfstate in
# cleartext; an environment variable is not recorded anywhere.
#
#   CLOUDFLARE_API_TOKEN=$(cat ~/.cloudflare/token) tofu apply
provider "cloudflare" {}
