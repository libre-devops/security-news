# Local development task runner for security-news. Run `just` to list recipes.
#
# Install just with either:
#   brew install just
#   uv tool add rust-just     # then call recipes as: uv run just <recipe>
#
# The terraform recipes wrap the LibreDevOpsHelpers engine functions so local work mirrors the
# libre-devops/terraform-azure action: the same fmt, validate, tflint and trivy gates, the same
# remote azurerm backend, and the same storage firewall open-before close-after dance. They read
# the state coordinates from the environment the tenant bootstrap publishes:
#   $env:TFSTATE_RESOURCE_GROUP, $env:TFSTATE_STORAGE_ACCOUNT, $env:TFSTATE_BLOB_CONTAINER
# Authenticate first with `az login`. A local .env file next to this justfile is loaded too.
#
# The feed recipes need no credentials at all, except the Message Center, which borrows your Azure
# CLI token. Every other source is a public feed.

set shell := ["pwsh", "-NoProfile", "-Command"]
set dotenv-load

workspace := env_var_or_default("TF_WORKSPACE", "prd")

# The backend key is pinned rather than left to the helper's auto-computed one. That key is derived
# from the folder layout, which resolves differently on a runner (where GitHub nests the repo
# inside a directory of the same name) than on a laptop. An auto key would quietly give local and
# CI two separate states, and therefore two application registrations.
state_key := "security-news-message-center.tfstate"

# List available recipes.
default:
    just --list

# Install or force-update LibreDevOpsHelpers (the engine the terraform recipes wrap) from PSGallery.
update-ldo-pwsh:
    if (Get-Module -ListAvailable LibreDevOpsHelpers) { Update-Module LibreDevOpsHelpers -Force; Write-Host 'Updated LibreDevOpsHelpers to the latest from PSGallery.' } else { Install-Module LibreDevOpsHelpers -Scope CurrentUser -Force -AllowClobber; Write-Host 'Installed LibreDevOpsHelpers from PSGallery.' }

# --- Terraform ----------------------------------------------------------------------------

# Format every Terraform file in place.
fmt:
    terraform fmt -recursive

# Offline gates for the stack: format check, validate, tflint, trivy. No cloud access needed.
validate:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-Module LibreDevOpsHelpers -Force
    Set-LdoLogFormat -Format Text
    Clear-LdoFinding
    Invoke-LdoTerraformFmtCheck -CodePath ./terraform
    terraform -chdir=terraform init -backend=false -input=false | Out-Null
    Invoke-LdoTerraformValidate -CodePath ./terraform
    Invoke-LdoTfLint -CodePath ./terraform
    Invoke-LdoTrivy -CodePath ./terraform
    Show-LdoFindingsSummary

# Trivy config scan only, gating on HIGH and CRITICAL like the action does.
scan:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-Module LibreDevOpsHelpers -Force
    Set-LdoLogFormat -Format Text
    Clear-LdoFinding
    Invoke-LdoTrivy -CodePath ./terraform
    Show-LdoFindingsSummary

# Plan against the real remote state. Read only: safe to run any time.
plan:
    just _run plan {{ workspace }}

# Apply against the real remote state. Prefer the pipeline (`just dispatch`) for anything shared.
apply:
    just _run apply {{ workspace }}

# Show the stack outputs, including the consent command and the gh variable commands.
output:
    just _run output {{ workspace }}

# Shared terraform driver: firewall the state account open, run, close it again whatever happens.
_run op ws:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-Module LibreDevOpsHelpers -Force
    Set-LdoLogFormat -Format Text
    Set-LdoTraceContext -Generate
    Clear-LdoFinding

    $rg = $env:TFSTATE_RESOURCE_GROUP
    $sa = $env:TFSTATE_STORAGE_ACCOUNT
    $cn = $env:TFSTATE_BLOB_CONTAINER
    if (-not ($rg -and $sa -and $cn)) {
        throw 'Set TFSTATE_RESOURCE_GROUP, TFSTATE_STORAGE_ACCOUNT and TFSTATE_BLOB_CONTAINER (the values the tenant bootstrap publishes).'
    }

    $path = './terraform'
    $added = $false
    try {
        Add-LdoStorageCurrentIpRule -ResourceGroup $rg -StorageAccountName $sa
        $added = $true

        Invoke-LdoTerraformInit -CodePath $path -InitArgs @(
            '-reconfigure',
            "-backend-config=resource_group_name=$rg",
            "-backend-config=storage_account_name=$sa",
            "-backend-config=container_name=$cn",
            "-backend-config=key={{ state_key }}"
        )
        Invoke-LdoTerraformWorkspaceSelect -CodePath $path -WorkspaceName '{{ ws }}'

        switch ('{{ op }}') {
            'output' {
                terraform -chdir=terraform output
            }
            default {
                Invoke-LdoTerraformFmtCheck -CodePath $path
                Invoke-LdoTerraformValidate -CodePath $path
                Invoke-LdoTfLint -CodePath $path
                Invoke-LdoTrivy -CodePath $path
                Invoke-LdoTerraformPlan -CodePath $path
                Show-LdoFindingsSummary
                if ('{{ op }}' -eq 'apply') {
                    Invoke-LdoTerraformApply -CodePath $path -SkipApprove
                }
            }
        }
    }
    finally {
        if ($added) { Remove-LdoStorageCurrentIpRule -ResourceGroup $rg -StorageAccountName $sa }
    }

# Run the pipeline instead of applying locally. This is the preferred path for a shared change.
dispatch:
    gh workflow run terraform.yml --repo libre-devops/security-news -f apply=true

# --- Message Center identity --------------------------------------------------------------

# Print the one-off tenant-wide admin consent command (needs AppRoleAssignment.ReadWrite.All).
consent:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Write-Host 'Run this once, as someone holding AppRoleAssignment.ReadWrite.All:' -ForegroundColor Cyan
    just _run output {{ workspace }} | Select-String -Pattern 'az rest'

# Publish the client and tenant ids as repository Actions VARIABLES (neither is a secret).
publish-vars:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $clientId = (terraform -chdir=terraform output -raw application_client_id)
    $tenantId = (terraform -chdir=terraform output -raw tenant_id)
    gh variable set MESSAGE_CENTER_CLIENT_ID --repo libre-devops/security-news --body $clientId
    gh variable set MESSAGE_CENTER_TENANT_ID --repo libre-devops/security-news --body $tenantId
    Write-Host 'Published MESSAGE_CENTER_CLIENT_ID and MESSAGE_CENTER_TENANT_ID.' -ForegroundColor Green

# --- Feeds ---------------------------------------------------------------------------------

# Regenerate data/feeds.json and data/feed.xml in place, as the scheduled job does (az login first).
feeds:
    uv run --with-requirements scripts/requirements.txt python scripts/fetch_feeds.py

# Same, but into a scratch directory, so the committed data files are left alone.
feeds-dry:
    #!/usr/bin/env pwsh
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("security-news-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $scratch | Out-Null
    try {
        Push-Location $scratch
        uv run --with-requirements '{{ justfile_directory() }}/scripts/requirements.txt' python '{{ justfile_directory() }}/scripts/fetch_feeds.py'
    }
    finally {
        Pop-Location
        Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }

# Format the Python with black, in place.
py-fmt:
    uv run --with black black scripts/fetch_feeds.py

# Offline gates for the Python: black format check plus an import smoke test.
py-check:
    uv run --with black black --check scripts/fetch_feeds.py
    uv run --with-requirements scripts/requirements.txt python -c "import ast, pathlib; ast.parse(pathlib.Path('scripts/fetch_feeds.py').read_text()); print('fetch_feeds.py parses clean')"

# --- Site ----------------------------------------------------------------------------------

# Serve the site locally at http://localhost:8000 for a quick look before pushing.
serve:
    python3 -m http.server 8000

# Everything that can run offline: Python gates plus the Terraform gates.
check: py-check validate
