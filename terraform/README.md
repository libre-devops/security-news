# Message Center workload identity

Terraform for the one Entra ID application that lets the feed job read the Microsoft 365 Message
Center.

Every other source in `scripts/fetch_feeds.py` is a public RSS or Atom feed and needs no
credentials. Message Center is the exception: it has no feed at all, only Microsoft Graph at
`/admin/serviceAnnouncement/messages`, and that endpoint is tenant scoped and requires an
authenticated caller holding `ServiceMessage.Read.All`.

This stack creates that caller. It creates nothing else: the site is static and served by GitHub
Pages, so there is no Azure infrastructure behind it.

## What it creates

One application registration and its service principal, named to the Libre DevOps convention
(`svp-${short}-${loc}-${env}-mc-001`, so `svp-ldo-uks-prd-mc-001` by default), carrying:

- The `ServiceMessage.Read.All` Microsoft Graph **application** role, with tenant-wide admin consent
  granted by default. Application rather than delegated because the feed job runs unattended on a
  schedule, with no signed-in user.
- Federated identity credentials trusting GitHub Actions OIDC from `libre-devops/security-news`.

There is **no client secret and no certificate**, by design. The federated credentials are the only
way to authenticate as this application, so nothing secret exists to commit, store in Actions, or
rotate. That also means this stack's state file holds no credentials.

## The subject claim gotcha

A GitHub Actions job that declares an `environment:` presents a different OIDC subject from one that
does not:

| Job | `sub` claim |
| --- | --- |
| With `environment: github-pages` | `repo:libre-devops/security-news:environment:github-pages` |
| Without an environment | `repo:libre-devops/security-news:ref:refs/heads/master` |

`fetch-feeds.yml` declares `environment: github-pages` for the Pages deployment, so the environment
form is the one that matters today. Both are registered anyway, so splitting the Graph fetch into
its own job later needs no Entra change.

Both are also registered in GitHub's **immutable** subject format (`repo:libre-devops@101948202/...`),
which GitHub forces on repositories created or renamed after 2026-07-15. This repository predates
that, so it presents the plain form, but a rename would flip the format and fail the run with
`AADSTS7002131 No matching federated identity record`. Registering both up front makes that a
non-event. Set `register_immutable_subjects = false` to skip them.

If a run ever does fail with `AADSTS7002131`, compare the subject in the run log against the
`federated_credential_subjects` output.

## Applying

State is local and auth is Azure CLI user auth, matching the other single-tenant helper stacks in
this estate. This is applied by hand, occasionally, and is not wired into CI.

```bash
az login
terraform -chdir=terraform init
terraform -chdir=terraform plan
terraform -chdir=terraform apply
```

The applier needs:

- `Application.ReadWrite.All`, or the Application Administrator role, to create the registration.
- `AppRoleAssignment.ReadWrite.All`, or Privileged Role Administrator, **when
  `grant_admin_consent` is true** (the default). Granting a Graph application role is tenant-wide
  admin consent, which is a privileged action.

If you cannot consent yourself, apply with `-var 'grant_admin_consent=false'`. The roles are still
requested on the application, and the `grant_admin_consent_commands` output prints ready-to-run
`az rest` commands for whoever can grant them.

## After applying

Publish the two identifiers the workflow needs. Neither is a secret, so they are Actions **variables**
rather than secrets, and the `terraform output github_variable_commands` output prints both commands:

```bash
gh variable set AZURE_CLIENT_ID --repo libre-devops/security-news --body <application_client_id>
gh variable set AZURE_TENANT_ID --repo libre-devops/security-news --body <tenant_id>
```

`fetch-feeds.yml` already sets `id-token: write`, so no permission change is needed there.

## Cost

Nothing. Entra ID application registrations are free.
