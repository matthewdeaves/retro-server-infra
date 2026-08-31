terraform {
  required_version = ">= 1.6"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 7.0"
    }
  }
}

# Auth comes from ~/.oci/config, not from this repo. Nothing here should ever
# need the private key inline; if it does, something is wrong.
provider "oci" {
  config_file_profile = var.oci_profile
  region              = var.region
}
