output "application_client_id" {
  description = "The application (client) id. Not a secret: publish it as the AZURE_CLIENT_ID Actions variable, see github_variable_commands."
  value       = module.message_center_spn.client_ids[local.spn_name]
}

output "application_name" {
  description = "Display name of the application registration, as it appears in Entra ID."
  value       = local.spn_name
}

output "application_object_id" {
  description = "Object id of the application registration, for the Entra portal deep link and any manual follow-up."
  value       = module.message_center_spn.application_object_ids[local.spn_name]
}

output "federated_credential_subjects" {
  description = "The OIDC subjects trusted by this application, keyed by credential name. A GitHub Actions run whose sub claim is not in this list cannot authenticate, so compare against the run log when azure/login fails with AADSTS7002131."
  value       = local.federated_subjects
}

output "github_variable_commands" {
  description = "The two Actions variables the feed workflow reads. Neither is a secret (a client id and a tenant id are identifiers, not credentials), so they are variables rather than secrets and are safe to show in run logs."
  value = [
    "gh variable set AZURE_CLIENT_ID --repo ${var.github_org}/${var.github_repo} --body ${module.message_center_spn.client_ids[local.spn_name]}",
    "gh variable set AZURE_TENANT_ID --repo ${var.github_org}/${var.github_repo} --body ${data.azuread_client_config.current.tenant_id}",
  ]
}

output "grant_admin_consent_commands" {
  description = "The az CLI alternative to grant_admin_consent: one tenant-wide admin consent grant per requested Graph application role, ready to run by someone holding AppRoleAssignment.ReadWrite.All. Only needed when grant_admin_consent is false."
  value = [
    for role in var.graph_application_roles : join(" ", [
      "az rest --method POST",
      "--url https://graph.microsoft.com/v1.0/servicePrincipals/${module.message_center_spn.service_principal_object_ids[local.spn_name]}/appRoleAssignments",
      "--body '{\"principalId\":\"${module.message_center_spn.service_principal_object_ids[local.spn_name]}\",\"resourceId\":\"${data.azuread_service_principal.microsoft_graph.object_id}\",\"appRoleId\":\"${data.azuread_service_principal.microsoft_graph.app_role_ids[role]}\"}'",
    ])
  ]
}

output "service_principal_object_id" {
  description = "Object id of the service principal (the enterprise application). This is the principal that holds the Graph role grants."
  value       = module.message_center_spn.service_principal_object_ids[local.spn_name]
}

output "tenant_id" {
  description = "Tenant the application belongs to. Not a secret: publish it as the AZURE_TENANT_ID Actions variable."
  value       = data.azuread_client_config.current.tenant_id
}
