# OIDC in the pipeline, per the Libre DevOps Terraform standard: ARM_CLIENT_ID, ARM_TENANT_ID and
# ARM_SUBSCRIPTION_ID come from the org Actions variables and ARM_OIDC_TOKEN is injected by the
# runner, so no client secret exists anywhere in this repository.
#
# The provider still falls back to Azure CLI auth when no OIDC token is present, so `az login` and
# a local plan work unchanged.
provider "azuread" {
  use_oidc = true
}
