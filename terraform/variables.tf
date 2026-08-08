variable "env" {
  description = "Suffix: environment code used in the application name. The feed job runs against the live site, so this defaults to prd."
  type        = string
  default     = "prd"
}

variable "github_branch" {
  description = "Branch the scheduled feed job runs on. Used to build the ref form of the OIDC subject, which is what a job WITHOUT an environment presents."
  type        = string
  default     = "master"
}

variable "github_environment" {
  description = "Deployment environment the feed job declares. Used to build the environment form of the OIDC subject, which is what a job WITH an environment presents (and the feed job does, for Pages)."
  type        = string
  default     = "github-pages"
}

variable "github_org" {
  description = "GitHub organisation owning the repository, as it appears in the OIDC subject claim."
  type        = string
  default     = "libre-devops"
}

variable "github_org_id" {
  description = "Numeric GitHub organisation id, used only to build the immutable (org@id) form of the OIDC subject. See register_immutable_subjects."
  type        = number
  default     = 101948202
}

variable "github_repo" {
  description = "GitHub repository running the feed job, as it appears in the OIDC subject claim."
  type        = string
  default     = "security-news"
}

variable "grant_admin_consent" {
  description = "Grant the requested Graph application roles from this stack. Defaults to false because granting one IS tenant-wide admin consent, which needs AppRoleAssignment.ReadWrite.All: a permission that lets its holder assign ANY app role of ANY API to ANY principal, including granting itself directory write. That is not something the shared org CI identity should carry, so the pipeline requests the roles and a human consents once using the grant_admin_consent_commands output. Set true only when applying interactively as someone who already holds it."
  type        = bool
  default     = false
}

variable "graph_application_roles" {
  description = "Microsoft Graph APPLICATION roles the identity requests. ServiceMessage.Read.All is the only one the Message Center ingestion needs: it is read only and grants nothing beyond the service announcement surface. Keep this list minimal."
  type        = set(string)
  default     = ["ServiceMessage.Read.All"]

  validation {
    condition     = length(var.graph_application_roles) > 0
    error_message = "graph_application_roles must request at least one role, otherwise the identity cannot read the Message Center."
  }
}

variable "loc" {
  description = "Outfix: short Azure region code used in the application name. Entra ID objects are not regional, so this is naming consistency only."
  type        = string
  default     = "uks"
}

variable "register_immutable_subjects" {
  description = "Also register the immutable (org@id) form of each OIDC subject. GitHub forces that format on repositories created or renamed after 2026-07-15. This repository predates it, so the plain form is what the runner presents today, but registering both means a later rename cannot break the scheduled run with AADSTS7002131."
  type        = bool
  default     = true
}

variable "short" {
  description = "Infix: short product code used in the application name."
  type        = string
  default     = "ldo"
}
