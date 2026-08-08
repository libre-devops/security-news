terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0.0, < 4.0.0"
    }
  }

  # Deliberately empty: the backend is configured at init time by the terraform-azure action, from
  # the org TFSTATE_* secrets. For local work, copy backend_override.tf.example to
  # backend_override.tf (gitignored) to fall back to local state.
  backend "azurerm" {}
}
