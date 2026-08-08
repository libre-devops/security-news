# The workload identity behind the Microsoft 365 Message Center ingestion. Message Center has no
# RSS: it is Graph only, at /admin/serviceAnnouncement/messages, and that endpoint needs an
# authenticated tenant-scoped caller. This stack creates the one Entra application that provides it,
# federated to GitHub Actions by OIDC so the repository holds no client secret and there is nothing
# to rotate.
#
# Nothing else is provisioned. The site itself is static, built by Actions and served by GitHub
# Pages, so there is no Azure infrastructure to speak of.
locals {
  spn_name = "svp-${var.short}-${var.loc}-${var.env}-mc-001"

  github_issuer = "https://token.actions.githubusercontent.com"

  # A job that declares an `environment:` presents the environment form of the OIDC subject, not the
  # ref form. The feed job declares one (github-pages, for the Pages deployment), so the environment
  # subject is the one that actually matters today. The ref subject is registered alongside it so
  # that splitting the Graph fetch into its own environment-less job later needs no Entra change.
  github_subjects = {
    environment = "repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}"
    branch      = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}"
  }

  # GitHub forces an immutable subject (the org@id form) on repositories created or renamed after
  # 2026-07-15. This repository was created before that date, so the plain subjects above are what
  # the runner presents, but a rename would silently flip the format and fail the run with
  # AADSTS7002131. Registering both forms up front makes that a non-event.
  github_immutable_subjects = var.register_immutable_subjects ? {
    for key, subject in local.github_subjects :
    "${key}-immutable" => replace(
      subject,
      "repo:${var.github_org}/",
      "repo:${var.github_org}@${var.github_org_id}/",
    )
  } : {}

  federated_subjects = merge(local.github_subjects, local.github_immutable_subjects)
}

data "azuread_client_config" "current" {}

# Microsoft Graph's own service principal in this tenant, used only to resolve app role ids for the
# manual consent commands in the outputs. The module resolves the same ids internally when it grants
# consent itself, so this is not on the critical path.
data "azuread_service_principal" "microsoft_graph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

module "message_center_spn" {
  source  = "libre-devops/service-principal/azuread"
  version = "~> 4.0"

  service_principals = {
    (local.spn_name) = {
      description      = "Reads the Microsoft 365 Message Center for the security.libredevops.org feed."
      sign_in_audience = "AzureADMyOrg"
      notes            = "Managed by Terraform in libre-devops/security-news (terraform/). Read only, no credentials: the sole credential is a GitHub Actions federated identity."

      owners                   = [data.azuread_client_config.current.object_id]
      service_principal_owners = [data.azuread_client_config.current.object_id]
      service_principal_tags   = ["security-news", "message-center"]

      # Application roles, not delegated scopes: the feed job runs unattended on a schedule, so
      # there is no signed-in user whose consent could be carried.
      microsoft_graph_application_roles   = var.graph_application_roles
      microsoft_graph_grant_admin_consent = var.grant_admin_consent

      # No client_secrets and no client_certificates, deliberately. The federated credentials below
      # are the only way to authenticate as this application, which means nothing secret ever lands
      # in the repository, in Actions secrets, or in this stack's state.
      federated_credentials = {
        for key, subject in local.federated_subjects : key => {
          display_name = "github-${key}"
          issuer       = local.github_issuer
          subject      = subject
          audiences    = ["api://AzureADTokenExchange"]
          description  = "GitHub Actions OIDC for ${var.github_org}/${var.github_repo}, subject ${subject}."
        }
      }
    }
  }
}
