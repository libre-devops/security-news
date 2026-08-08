# Local, personal-tenant deployment: Azure CLI user auth and local state, matching the other
# single-tenant helper stacks in this estate. Run `az login` before applying.
#
# The applier needs Application.ReadWrite.All (or Application Administrator) to create the
# registration. When grant_admin_consent is true it also needs AppRoleAssignment.ReadWrite.All (or
# Privileged Role Administrator), because granting a Graph application role IS tenant-wide admin
# consent. Set grant_admin_consent to false to apply as a plain Application Administrator and hand
# the consent step to someone who holds it, using the commands in the grant_admin_consent_commands
# output.
provider "azuread" {}
