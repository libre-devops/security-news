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

- A request for the `ServiceMessage.Read.All` Microsoft Graph **application** role. Application
  rather than delegated because the feed job runs unattended on a schedule, with no signed-in user.
  The request is managed here; the consent is not (see below).
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

Through the pipeline, like everything else in the estate. `.github/workflows/terraform.yml` runs
the `libre-devops/terraform-azure` action against the shared remote state:

- **Plan** happens automatically on any pull request touching `terraform/**`.
- **Apply** happens only on a manual dispatch with the `apply` input ticked:

```bash
gh workflow run terraform.yml --repo libre-devops/security-news -f apply=true
```

Auth is OIDC through the org CI identity (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID` org variables) and state lives in the org's firewalled tfstate account
(`TFSTATE_*` org secrets). No local state, no client secret, and drift shows up on the next plan.

Fork pull requests are skipped rather than failed: GitHub issues them no OIDC token, so they could
never authenticate.

### Consent is not in the pipeline, deliberately

`grant_admin_consent` defaults to **false**, so the stack requests `ServiceMessage.Read.All` but
does not consent to it. Granting a Graph application role requires `AppRoleAssignment.ReadWrite.All`,
and that permission lets its holder assign **any** app role of **any** API to **any** principal,
including granting itself directory write. Handing that to the shared org CI identity, which every
repository in the org can use, would turn a workflow-file change into a tenant escalation path.

So consent is a one-off human act. After the first apply, run what
`terraform output grant_admin_consent_commands` prints, as someone who holds the permission:

```bash
az rest --method POST \
  --url https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/appRoleAssignments \
  --body '{"principalId":"<sp-object-id>","resourceId":"<graph-sp-object-id>","appRoleId":"<role-id>"}'
```

Terraform does not manage that grant, so it will not fight you over it or try to remove it. If you
would rather manage it here, set `grant_admin_consent = true` and apply interactively as someone
who already holds the permission.

### Local plans

For a local plan without touching the shared state, copy `backend_override.tf.example` to
`backend_override.tf` (gitignored) and re-run `terraform init`. Plan only: applying from a local
state file would fork the real one.

## After applying

Publish the two identifiers the feed workflow needs. Neither is a secret, so they are Actions
**variables**, and `terraform output github_variable_commands` prints both:

```bash
gh variable set MESSAGE_CENTER_CLIENT_ID --repo libre-devops/security-news --body <application_client_id>
gh variable set MESSAGE_CENTER_TENANT_ID --repo libre-devops/security-news --body <tenant_id>
```

They are **not** called `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` on purpose. Those already exist as
org variables for the CI identity, and a repository variable of the same name silently shadows the
org one, which would break this repository's own Terraform pipeline.

`fetch-feeds.yml` already sets `id-token: write`, so no permission change is needed there.

## Cost

Nothing. Entra ID application registrations are free.
