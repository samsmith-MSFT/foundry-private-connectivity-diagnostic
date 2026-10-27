<#
.SYNOPSIS
    Troubleshoots connectivity for a privately deployed Microsoft Foundry (Azure AI Foundry)
    account and its private dependencies (Storage, Cosmos DB, AI Search, Key Vault).

.DESCRIPTION
    Runs a read-only diagnostic sweep and prints a console verdict table.

    Control-plane checks (via Azure CLI):
      * Deployment topology - delegated subnet injection vs Microsoft-managed network vs none
      * publicNetworkAccess, network ACLs, custom subdomain
      * Inbound private endpoints - existence, approval state, DNS zone group, NIC private IP
      * Private DNS zones - zone exists, A record matches the PE NIC IP, VNet links
      * Injected subnet health - delegation, prefix size, NSG, UDR, free IPs
      * Dependency resources discovered from project connections, each checked the same way

    Authorization checks (via Azure CLI):
      * Account and per-project managed identities, and the calling principal
      * Capability host state, which gates the post-provisioning role assignments
      * Required role assignments for each project identity on each BYO dependency,
        matched by role definition GUID rather than display name
      * ABAC conditions on those assignments - a conditioned grant can be present
        and still not apply
      * Cosmos DB data-plane role assignments, which live on the DocumentDB
        resource provider and are invisible to Azure RBAC queries
      * Local-auth posture per dependency (Storage allowSharedKeyAccess, AI Search
        apiKeyOnly vs aadOrApiKey, Cosmos disableLocalAuth, Key Vault access model),
        which determines whether an RBAC gap is fatal or merely untidy
      * Connection authType per project connection
      * Foundry role assignments for the caller and for each project identity

    Data-plane checks (from this machine):
      * Which resolver answered, and whether the name resolves to the private
        endpoint or falls through to the public frontend
      * Address is RFC1918 / private, not a public frontend
      * TCP reachability on 443

    Authorization findings are raised as WARN rather than FAIL when the role
    assignment cannot be READ, because a missing assignment and a missing
    Microsoft.Authorization/roleAssignments/read permission are indistinguishable
    from the outside.

    Private DNS zone selection (v3):
      The same privatelink zone name often exists many times across a tenant
      (per spoke, per dev subscription, abandoned landing zones). A client only
      resolves through the instance linked to the VNet whose DNS it uses, so each
      zone instance is classified first:
        On path    - referenced by the private endpoint's DNS zone group, or
                     linked to the injected VNet, the -HubVNetId, or the private
                     endpoint's own VNet. These get A-record PASS/FAIL verdicts.
        Bystander  - same name, linked to none of those. No verdict; summarised
                     in one line (list them with -ShowAllZones).
      If no instance is on path, the script reports where a correct record DOES
      exist (WARN) or that none exists anywhere visible (FAIL).
      Two on-path instances answering with different IPs is flagged as split-brain.

    DNS VNet-link rule (for on-path zones):
      PASS       - zone is linked to the injected/delegated VNet (or to the private
                   endpoint's VNet when there is no injected VNet)
      PASS-NOTE  - zone is linked to a hub/centralized VNet or the PE VNet instead
      FAIL       - zone has no VNet links at all

.PARAMETER ResourceGroup
    Resource group holding the Foundry account.

.PARAMETER AccountName
    Name of the Foundry / Azure AI Services account.

.PARAMETER SubscriptionId
    Optional. Defaults to the current az CLI subscription.

.PARAMETER HubVNetId
    Optional. Resource ID of the known hub / centralized VNet. Supplying it upgrades the
    "centralized VNet" verdict from a guess to a confirmed match.

.PARAMETER SkipClientTests
    Skip the from-this-machine DNS and TCP tests (use when running from a jump box that
    is deliberately outside the private network).

.PARAMETER Detailed
    Print the full detail column without truncation.

.PARAMETER ShowAllZones
    Also list every bystander private DNS zone instance (same zone name, not on this
    deployment's resolution path) as an INFO row. Off by default to keep the report
    focused on the zones that actually affect resolution.

.PARAMETER ExportHtml
    Write an HTML report without prompting. Intended for CI and scheduled runs;
    interactive runs are offered the export at the end instead.

.PARAMETER HtmlPath
    Path for the HTML report. Implies -ExportHtml.

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
        -HubVNetId "/subscriptions/xxx/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub" -Detailed

.EXAMPLE
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
        -SkipClientTests -HtmlPath .\reports\foundry.html
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ResourceGroup,
    [Parameter(Mandatory = $true)][string] $AccountName,
    [string] $SubscriptionId,
    [string] $HubVNetId,
    [switch] $SkipClientTests,
    [switch] $Detailed,
    [switch] $ShowAllZones,
    # Write the HTML report without prompting. Use in CI, scheduled runs, or any
    # non-interactive host; interactive runs get an offer at the end instead.
    [switch] $ExportHtml,
    [string] $HtmlPath
)

$ErrorActionPreference = 'Stop'
$script:Results  = New-Object System.Collections.Generic.List[object]
$script:ApiCS    = '2026-07-01'
$script:ApiNet   = '2024-05-01'
$script:ApiAuth  = '2022-04-01'
$script:ApiSearch = '2025-05-01'
# Cosmos data-plane role assignments live on the DocumentDB RP, not on
# Microsoft.Authorization. Negotiate the api-version the same way as the
# Foundry sub-resources - older accounts reject the newest one.
$script:ApiCosmosSqlCandidates = @('2026-03-15', '2024-11-15', '2023-04-15', '2022-05-15')

# --- role definition GUIDs ---------------------------------------------------
# Match on GUID, never on display name. The Foundry roles were renamed
# (Azure AI User -> Foundry User, and so on) with the GUIDs left unchanged, so
# a name-based check breaks depending on when the tenant saw the rename.
$script:RoleNames = @{
    'ba92f5b4-2d11-453d-a403-e96b0029c9fe' = 'Storage Blob Data Contributor'
    'b7e6dc6d-f1e8-4753-8033-0f276bb0955b' = 'Storage Blob Data Owner'
    '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1' = 'Storage Blob Data Reader'
    '230815da-be43-4aae-9cb4-875f7bd000aa' = 'Cosmos DB Operator'
    '00000000-0000-0000-0000-000000000002' = 'Cosmos DB Built-in Data Contributor'
    '00000000-0000-0000-0000-000000000001' = 'Cosmos DB Built-in Data Reader'
    '8ebe5a00-799e-43f5-93ac-243d3dce84a7' = 'Search Index Data Contributor'
    '7ca78c08-252a-4471-8644-bb5ff32d4ba0' = 'Search Service Contributor'
    '1407120a-92aa-4202-b7e9-c0e197c71c8f' = 'Search Index Data Reader'
    '4633458b-17de-408a-b874-0445c86b69e6' = 'Key Vault Secrets User'
    '21090545-7ca7-4776-b22c-e363652d74d2' = 'Key Vault Reader'
    '53ca6127-db72-4b80-b1b0-d745d6d5456d' = 'Foundry User'
    'c883944f-8b7b-4483-af10-35834be79c4a' = 'Foundry Owner'
    'e47c6f54-e4a2-4754-9501-8e0985b135e1' = 'Foundry Account Owner'
    'eadc314b-1a2d-4efa-be10-5d325db5065e' = 'Foundry Project Manager'
    'eed3b665-ab3a-47b6-8f48-c9382fb1dad6' = 'Foundry Agent Consumer'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
}

# Roles that look relevant but are NOT honoured by project-based Foundry.
# Microsoft Learn is explicit: the Cognitive Services * roles target AI Services
# accounts directly, and Azure AI Developer is scoped to Azure ML workspaces and
# Foundry *hubs*. Holding one of these and nothing else is a common reason a
# developer can see the resource but cannot use the project.
$script:RoleNotApplicable = @{
    '64702f94-c441-49e6-a78b-ef80e0188fee' = 'Azure AI Developer (Azure ML / Foundry hub scoped)'
    'b78c5d69-af96-48a3-bf8d-a8b4d589de94' = 'Azure AI Administrator (Azure ML / Foundry hub scoped)'
    '25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68' = 'Cognitive Services Contributor'
    'a97b65f3-24c7-4388-baec-2e87135dc908' = 'Cognitive Services User'
    '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd' = 'Cognitive Services OpenAI User'
}

# Required role GUIDs per BYO dependency type, for the PROJECT managed identity.
# Sourced from Microsoft's reference Bicep for the private-network standard
# agent setup. 'Phase' records whether the assignment is expected before or
# after the capability host exists - a deployment that never provisioned its
# capability host will legitimately be missing the post-caphost grants, and
# that is a different root cause than a forgotten role assignment.
$script:RequiredRoles = @{
    'Microsoft.Storage/storageAccounts'     = @(
        @{ Guid = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'; Phase = 'pre'  ; Condition = $false }
        @{ Guid = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'; Phase = 'post' ; Condition = $true  }
    )
    'Microsoft.DocumentDB/databaseAccounts' = @(
        @{ Guid = '230815da-be43-4aae-9cb4-875f7bd000aa'; Phase = 'pre'  ; Condition = $false }
    )
    'Microsoft.Search/searchServices'       = @(
        @{ Guid = '8ebe5a00-799e-43f5-93ac-243d3dce84a7'; Phase = 'pre'  ; Condition = $false }
        @{ Guid = '7ca78c08-252a-4471-8644-bb5ff32d4ba0'; Phase = 'pre'  ; Condition = $false }
    )
    'Microsoft.KeyVault/vaults'             = @(
        @{ Guid = '4633458b-17de-408a-b874-0445c86b69e6'; Phase = 'pre'  ; Condition = $false }
    )
}
# Sub-resources of a Foundry account trail the account's own API version, so the
# newest account api-version is often rejected for projects/connections. Negotiate.
$script:ApiCandidates = @('2026-07-01', '2026-05-01', '2026-03-01', '2025-12-01', '2025-09-01', '2025-06-01')
$script:ApiUsed  = @{}

# Findings stream to the console as they are discovered - empty section headers
# during a multi-minute run look indistinguishable from a hang.
$script:Live        = $true
$script:CheckWidth  = 42
# Per-resource publicNetworkAccess=Disabled. Drives client-side severity: if the
# service refuses public traffic, resolving to the public frontend is a hard
# failure, not a vantage-point artifact.
$script:PublicDisabled = @{}
# Every private endpoint NIC address discovered on the control plane. Lets the
# client phase distinguish a genuine private endpoint hit from a proxy VIP that
# merely lives in private address space.
$script:KnownPeIps = New-Object System.Collections.Generic.List[string]
$script:LiveDetail  = if ($Detailed) { 4000 } else { 150 }
$script:ColorFor    = @{
    'PASS'      = 'Green'
    'PASS-NOTE' = 'DarkGreen'
    'WARN'      = 'Yellow'
    'FAIL'      = 'Red'
    'INFO'      = 'Gray'
    'SKIP'      = 'DarkGray'
}

#region ---------------------------------------------------------------- helpers

function Write-ResultLine {
    param(
        [Parameter(Mandatory)][pscustomobject] $Row,
        [int] $MaxDetail = 150,
        [string] $Indent = '    ',
        [switch] $ShowArea
    )
    $detail = $Row.Detail
    if ($detail.Length -gt $MaxDetail) { $detail = $detail.Substring(0, $MaxDetail) + '...' }
    $check = if ($Row.Check.Length -gt $script:CheckWidth) {
        $Row.Check.Substring(0, $script:CheckWidth - 1) + '~'
    } else { $Row.Check }

    Write-Host ("$Indent{0,-10}" -f $Row.Status) -ForegroundColor $script:ColorFor[$Row.Status] -NoNewline
    if ($ShowArea) { Write-Host ("{0,-20}" -f $Row.Area) -ForegroundColor DarkCyan -NoNewline }
    Write-Host ("{0,-$($script:CheckWidth)}" -f $check) -ForegroundColor White -NoNewline
    Write-Host $detail -ForegroundColor DarkGray
}

function Add-Result {
    param(
        [Parameter(Mandatory)][string] $Area,
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][ValidateSet('PASS', 'PASS-NOTE', 'WARN', 'FAIL', 'INFO', 'SKIP')][string] $Status,
        [string] $Detail = ''
    )
    $row = [pscustomobject]@{
        Area = $Area; Check = $Check; Status = $Status; Detail = $Detail
        # Client findings depend on WHERE the script ran, not on whether the
        # deployment is correct, so they are scored separately and never drive
        # the overall verdict or the exit code.
        Scope = if ($Area -eq 'Client') { 'Client' } else { 'Deployment' }
    }
    $script:Results.Add($row) | Out-Null
    if ($script:Live) { Write-ResultLine -Row $row -MaxDetail $script:LiveDetail }
}

function Write-Phase {
    param([string] $Text)
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "  $('-' * $Text.Length)" -ForegroundColor DarkCyan
}

function Invoke-Az {
    <# Runs an az command, returns parsed JSON or $null. Never throws. #>
    param([Parameter(Mandatory)][string[]] $Args)
    try {
        $raw = & az @Args 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
    } catch { return $null }
}

function Get-ArmToken {
    <#
      Cache an ARM bearer token. Every `az rest` invocation spawns a Python
      interpreter and costs ~8s; a direct REST call with a cached token costs
      ~1s. Over the 40+ reads a full run makes, that is the difference between
      minutes and seconds.
    #>
    if ($script:ArmToken -and (Get-Date) -lt $script:ArmTokenExpiry) { return $script:ArmToken }
    $t = Invoke-Az @('account', 'get-access-token', '--resource', 'https://management.azure.com', '-o', 'json')
    if (-not $t) { return $null }
    $script:ArmToken = $t.accessToken
    # Refresh well before the real expiry; a long run must not die mid-sweep.
    $script:ArmTokenExpiry = (Get-Date).AddMinutes(30)
    return $script:ArmToken
}

function Invoke-Arm {
    <# GET an ARM resource by id + api-version. Falls back to `az rest` if the
       direct REST path is unavailable for any reason. #>
    param([Parameter(Mandatory)][string] $Id, [Parameter(Mandatory)][string] $ApiVersion)
    $url = "https://management.azure.com$($Id)?api-version=$ApiVersion"

    $tok = Get-ArmToken
    if ($tok) {
        try {
            return Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            # 401 means the cached token went stale - drop it and retry once.
            if ($code -eq 401) {
                $script:ArmToken = $null
                $tok = Get-ArmToken
                if ($tok) {
                    try {
                        return Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
                    } catch { return $null }
                }
            }
            # 404 / 400 (unsupported api-version) are legitimate "no" answers.
            if ($code -in 400, 403, 404) { return $null }
            return $null
        }
    }
    return Invoke-Az @('rest', '--method', 'get', '--url', $url)
}

function Invoke-ArmNegotiated {
    <#
      GET an ARM resource, trying successive api-versions until one answers.
      Foundry sub-resources (projects, connections) frequently reject the newest
      account api-version with NoRegisteredProviderFound; without this the call
      returns null and the caller silently concludes "nothing there".
    #>
    param([Parameter(Mandatory)][string] $Id, [string] $CacheKey = $Id)
    if ($script:ApiUsed.ContainsKey($CacheKey)) {
        return Invoke-Arm -Id $Id -ApiVersion $script:ApiUsed[$CacheKey]
    }
    foreach ($v in $script:ApiCandidates) {
        $r = Invoke-Arm -Id $Id -ApiVersion $v
        if ($null -ne $r) {
            $script:ApiUsed[$CacheKey] = $v
            return $r
        }
    }
    return $null
}

function Invoke-ArmBatch {
    <#
      Fetch many ARM resources concurrently and return a hashtable of id -> result.
      Runspaces cannot see script-scoped state or functions, so this deliberately
      takes plain data in and hands plain data back; all reporting stays on the
      main thread so live output and ordering are preserved.
    #>
    param(
        [Parameter(Mandatory)][object[]] $Requests,   # @{ Key=..; Id=..; ApiVersion=.. }
        [int] $Throttle = 8
    )
    $out = [hashtable]::Synchronized(@{})
    if (-not $Requests -or $Requests.Count -eq 0) { return $out }

    $tok = Get-ArmToken
    if (-not $tok) {
        foreach ($r in $Requests) { $out[$r.Key] = Invoke-Arm -Id $r.Id -ApiVersion $r.ApiVersion }
        return $out
    }

    $Requests | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $bag = $using:out
        $t   = $using:tok
        $url = "https://management.azure.com$($_.Id)?api-version=$($_.ApiVersion)"
        try {
            $bag[$_.Key] = Invoke-RestMethod -Uri $url -Method Get -Headers @{ Authorization = "Bearer $t" } -ErrorAction Stop
        } catch {
            $bag[$_.Key] = $null
        }
    }
    return $out
}

function Test-EndpointReachability {
    <#
      Resolve + TCP 443 + TLS issuer for many FQDNs concurrently. Returns plain
      objects; the caller decides severity and emits the findings in order.
      Parallelism matters most here because an unreachable endpoint costs a full
      TCP timeout, and those timeouts otherwise stack up serially.
    #>
    param(
        [Parameter(Mandatory)][object[]] $Items,
        [int] $Throttle = 8
    )
    if (-not $Items -or $Items.Count -eq 0) { return @() }

    # Resolve probe URLs on the main thread - runspaces cannot see script functions.
    $probeUrls = @{}
    foreach ($i in $Items) { $probeUrls[$i.Fqdn] = Get-ServiceProbeUrl -Fqdn $i.Fqdn }

    return $Items | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $fqdn = $_.Fqdn
        $r = [pscustomobject]@{
            Fqdn = $fqdn; Source = $_.Source
            Addrs = @(); ResolveError = $null
            Tcp = $false; TcpTarget = $null
            TlsIssuer = $null; TlsSubject = $null; TlsSan = $null; TlsError = $null
            HttpStatus = $null; HttpIdHeader = $null; HttpIdValue = $null
            HttpBody = $null; HttpError = $null; HttpUrl = $null
        }
        try {
            $recs = Resolve-DnsName -Name $fqdn -Type A -DnsOnly -ErrorAction Stop
            $r.Addrs = @($recs | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object { $_.IPAddress })
        } catch {
            $r.ResolveError = $_.Exception.Message
            return $r
        }
        if ($r.Addrs.Count -eq 0) { return $r }

        # Prefer a private answer for the transport test when one exists.
        $privAddr = $r.Addrs | Where-Object {
            $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and (
                ($_ -split '\.')[0] -eq '10' -or
                (($_ -split '\.')[0] -eq '172' -and [int]($_ -split '\.')[1] -ge 16 -and [int]($_ -split '\.')[1] -le 31) -or
                (($_ -split '\.')[0] -eq '192' -and ($_ -split '\.')[1] -eq '168') -or
                (($_ -split '\.')[0] -eq '100' -and [int]($_ -split '\.')[1] -ge 64 -and [int]($_ -split '\.')[1] -le 127)
            )
        }
        $ip = if ($privAddr) { $privAddr[0] } else { $r.Addrs[0] }
        $r.TcpTarget = $ip

        # Bounded async connect - Test-NetConnection's own timeout is long and
        # not adjustable, which is exactly what makes a serial sweep drag.
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $iar = $c.BeginConnect($ip, 443, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(5000, $false) -and $c.Connected) {
                $c.EndConnect($iar)
                $r.Tcp = $true
                try {
                    $ssl = [System.Net.Security.SslStream]::new($c.GetStream(), $false, { $true })
                    $ssl.AuthenticateAsClient($fqdn)
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
                    $r.TlsIssuer = $cert.Issuer
                    $r.TlsSubject = $cert.Subject
                    $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                    $r.TlsSan = if ($san) { $san.Format($false) } else { $cert.Subject }
                    $ssl.Dispose()
                } catch { $r.TlsError = $_.Exception.Message }
            }
            $c.Close()
        } catch { $r.Tcp = $false }

        # --- unauthenticated identity probe -------------------------------
        # The certificate proves we reached *a* genuine Azure frontend, but a
        # wildcard SAN (e.g. *.openai.azure.com) covers every account in the
        # namespace - so it cannot prove we reached THIS account. The service's
        # own error response can: it is signed with a per-request id header that
        # only the real service emits. No credentials are sent and nothing is
        # read; a 401/403 is the expected and desired outcome.
        if ($r.Tcp) {
            $probeUrl = $using:probeUrls
            $url = $probeUrl[$fqdn]
            if ($url) {
                $r.HttpUrl = $url
                try {
                    $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 15 `
                                -SkipHttpErrorCheck -SkipCertificateCheck -ErrorAction Stop
                    $r.HttpStatus = [int]$resp.StatusCode
                    foreach ($h in 'apim-request-id', 'x-ms-request-id', 'x-ms-activity-id', 'request-id') {
                        if ($resp.Headers.ContainsKey($h)) {
                            $r.HttpIdHeader = $h
                            $r.HttpIdValue = ($resp.Headers[$h] | Select-Object -First 1)
                            break
                        }
                    }
                    if ($resp.Content) {
                        $r.HttpBody = [string]$resp.Content
                        if ($r.HttpBody.Length -gt 400) { $r.HttpBody = $r.HttpBody.Substring(0, 400) }
                    }
                } catch {
                    $r.HttpError = $_.Exception.Message
                }
            }
        }
        return $r
    }
}
function Invoke-Graph {
    <#
      Run an Azure Resource Graph KQL query via direct REST and return the rows.
      ARG answers tenant-wide questions in one round trip that would otherwise
      cost dozens of per-resource reads. Note it indexes resources, not child
      record sets - private DNS A records are NOT queryable here and still need
      a direct read.
    #>
    param([Parameter(Mandatory)][string] $Query, [int] $First = 500)
    $tok = Get-ArmToken
    if (-not $tok) { return @() }
    try {
        $body = @{ query = $Query; options = @{ '$top' = $First } }
        if ($script:SubScope -and $script:SubScope.Count -gt 0) {
            $body['subscriptions'] = @($script:SubScope)
        }
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' `
            -Headers @{ Authorization = "Bearer $tok" } `
            -ContentType 'application/json' `
            -Body ($body | ConvertTo-Json -Depth 6) -ErrorAction Stop
        if ($resp -and $resp.data) { return ConvertTo-Array $resp.data }
    } catch { return @() }
    return @()
}

function Get-ServiceProbeUrl {
    <#
      An unauthenticated URL per service type that provokes a response the real
      service signs with an identifying header. No credentials are ever sent and
      no data is read - the point is purely "who answered".
    #>
    param([string] $Fqdn)
    switch -Regex ($Fqdn) {
        '\.openai\.azure\.com$'          { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.services\.ai\.azure\.com$'    { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.cognitiveservices\.azure\.com$' { return "https://$Fqdn/openai/models?api-version=2024-10-21" }
        '\.blob\.core\.windows\.net$'    { return "https://$Fqdn/?comp=list" }
        '\.file\.core\.windows\.net$'    { return "https://$Fqdn/?comp=list" }
        '\.documents\.azure\.com$'       { return "https://$Fqdn/" }
        '\.search\.windows\.net$'        { return "https://$Fqdn/indexes?api-version=2023-11-01" }
        '\.vaultcore\.azure\.net$'       { return "https://$Fqdn/secrets?api-version=7.4" }
        default                          { return "https://$Fqdn/" }
    }
}

function Test-CertNameMatch {
    <#
      Does the presented certificate actually vouch for the FQDN we asked for?
      Through a proxy or load-balancer VIP this is the strongest client-side
      evidence that traffic reached the intended backend: the address tells you
      nothing, but the certificate identity does.
    #>
    param([string] $Fqdn, [string] $SanText, [string] $Subject)
    if (-not $Fqdn) { return $null }

    $names = @()
    if ($SanText) {
        foreach ($m in [regex]::Matches($SanText, 'DNS Name=([^\s,]+)')) {
            $names += $m.Groups[1].Value.Trim()
        }
    }
    if (-not $names -and $Subject -match 'CN=([^,]+)') { $names += $Matches[1].Trim() }
    if (-not $names) { return $null }

    foreach ($n in $names) {
        if ($n -ieq $Fqdn) { return $true }
        if ($n.StartsWith('*.')) {
            $suffix = $n.Substring(1)                     # ".openai.azure.com"
            $hostPart = $Fqdn.Substring(0, [Math]::Max(0, $Fqdn.Length - $suffix.Length))
            if ($Fqdn -like "*$suffix" -and $hostPart -and $hostPart -notmatch '\.') { return $true }
        }
    }
    return $false
}

function Get-IdSegment {
    <# Pulls a named segment out of an ARM resource id, e.g. 'virtualNetworks'. #>
    param([string] $Id, [string] $Segment)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    $parts = $Id.Trim('/') -split '/'
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if ($parts[$i] -ieq $Segment) { return $parts[$i + 1] }
    }
    return $null
}

function Get-VNetIdFromSubnetId {
    param([string] $SubnetId)
    if ([string]::IsNullOrWhiteSpace($SubnetId)) { return $null }
    if ($SubnetId -match '^(?<v>.+/virtualNetworks/[^/]+)/subnets/') { return $Matches['v'] }
    return $null
}

function Test-PrivateIPv4 {
    param([string] $Address)
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $o = $Address -split '\.' | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $true }   # CGNAT, used by some hubs
    return $false
}

function Get-PrefixSize {
    param([string] $Prefix)
    if ($Prefix -match '/(\d+)$') { return [int]$Matches[1] }
    return $null
}

function ConvertTo-Array {
    <# Normalises $null / single object / array into an array. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return $Value }
    return @($Value)
}

function Get-TokenClaim {
    <#
      Read a claim out of the cached ARM access token. Used to learn the calling
      principal's object id without calling Microsoft Graph - Graph reads need a
      separate consent that a read-only diagnostic should not demand, and the
      claim is already sitting in the token we hold.
    #>
    param([Parameter(Mandatory)][string] $Token, [Parameter(Mandatory)][string] $Claim)
    try {
        $parts = $Token -split '\.'
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
        return ($json | ConvertFrom-Json).$Claim
    } catch { return $null }
}

function Invoke-ArmUrl {
    <#
      GET a fully-formed ARM URL (one that already carries query parameters, so
      Invoke-Arm cannot build it) and follow nextLink. Returns a hashtable:
        Ok    - whether the call succeeded
        Value - accumulated 'value' array
        Code  - HTTP status when it failed
      The caller needs Ok separately from an empty Value: "no role assignments"
      and "not allowed to read role assignments" are the same empty list
      otherwise, and reporting the second as the first invents a finding.
    #>
    param([Parameter(Mandatory)][string] $Url)
    $items = New-Object System.Collections.Generic.List[object]
    $next  = $Url
    $tok   = Get-ArmToken
    if (-not $tok) { return @{ Ok = $false; Value = @(); Code = $null } }

    $guard = 0
    while ($next -and $guard -lt 20) {
        $guard++
        try {
            $r = Invoke-RestMethod -Uri $next -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 401) {
                $script:ArmToken = $null
                $tok = Get-ArmToken
                if ($tok) {
                    try {
                        $r = Invoke-RestMethod -Uri $next -Method Get -Headers @{ Authorization = "Bearer $tok" } -ErrorAction Stop
                    } catch { return @{ Ok = $false; Value = @(); Code = $code } }
                } else { return @{ Ok = $false; Value = @(); Code = $code } }
            } else {
                return @{ Ok = $false; Value = @(); Code = $code }
            }
        }
        foreach ($v in (ConvertTo-Array $r.value)) { $items.Add($v) | Out-Null }
        $next = $r.nextLink
    }
    # .ToArray() rather than @($items): on PowerShell 7.6 the array-subexpression
    # operator throws "Argument types do not match" against a
    # System.Collections.Generic.List[object], empty or not.
    return @{ Ok = $true; Value = $items.ToArray(); Code = 200 }
}

function Get-RoleAssignment {
    <#
      Every role assignment held by one principal that bears on a scope.

      Two filters are needed and neither is sufficient alone:
        principalId eq {id}  - returns assignments at, ABOVE and BELOW the
                               scope, but ONLY those naming the principal
                               directly. Group-derived access is invisible.
        assignedTo('{id}')   - resolves transitive group membership, but does
                               not reach below-scope assignments.
      Most human access in a large tenant is granted through Entra groups, so
      querying only the first reports "no access" for users who plainly have
      it. The results are unioned on assignment id.
    #>
    param([Parameter(Mandatory)][string] $Scope, [Parameter(Mandatory)][string] $PrincipalId)

    $base = "https://management.azure.com$Scope/providers/Microsoft.Authorization/roleAssignments?api-version=$($script:ApiAuth)"
    $direct = Invoke-ArmUrl -Url ("$base&`$filter=" + [uri]::EscapeDataString("principalId eq '$PrincipalId'"))
    $viaGrp = Invoke-ArmUrl -Url ("$base&`$filter=" + [uri]::EscapeDataString("assignedTo('$PrincipalId')"))

    # Only a total failure is a failure. If either query answered, the union is
    # usable - and reporting a read error when half the picture arrived would
    # suppress findings that are already in hand.
    if (-not $direct.Ok -and -not $viaGrp.Ok) {
        return @{ Ok = $false; Value = @(); Code = $direct.Code; ViaGroupOk = $false }
    }

    $merged = @{}
    foreach ($set in @($direct, $viaGrp)) {
        if (-not $set.Ok) { continue }
        foreach ($a in $set.Value) {
            $k = if ($a.id) { $a.id } else { "$($a.properties.roleDefinitionId)|$($a.properties.scope)|$($a.properties.principalId)" }
            $merged[$k] = $a
        }
    }
    return @{ Ok = $true; Value = @($merged.Values); Code = 200; ViaGroupOk = $viaGrp.Ok }
}

function Get-RoleGuid {
    <# Trailing GUID of a fully-qualified roleDefinitionId. #>
    param([string] $RoleDefinitionId)
    if (-not $RoleDefinitionId) { return $null }
    return ($RoleDefinitionId -split '/')[-1]
}

function Resolve-RoleName {
    <# Friendly name for a role GUID; falls back to an ARM read, then the GUID. #>
    param([Parameter(Mandatory)][string] $Guid)
    if ($script:RoleNames.ContainsKey($Guid))       { return $script:RoleNames[$Guid] }
    if ($script:RoleNotApplicable.ContainsKey($Guid)) { return $script:RoleNotApplicable[$Guid] }
    if (-not $script:RoleNameCache) { $script:RoleNameCache = @{} }
    if ($script:RoleNameCache.ContainsKey($Guid))   { return $script:RoleNameCache[$Guid] }
    $rd = Invoke-Arm -Id "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$Guid" -ApiVersion $script:ApiAuth
    $name = if ($rd.properties.roleName) { $rd.properties.roleName } else { $Guid }
    $script:RoleNameCache[$Guid] = $name
    return $name
}

#endregion

#region ---------------------------------------------------- 0. preflight / context

Write-Host ''
Write-Host '  Microsoft Foundry - private connectivity diagnostics' -ForegroundColor White
Write-Host "  account: $AccountName   rg: $ResourceGroup   $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host ''
    Write-Host '  FATAL: Azure CLI (az) not found on PATH.' -ForegroundColor Red
    Write-Host '  Install it, then re-run:' -ForegroundColor Yellow
    Write-Host '      winget install --exact --id Microsoft.AzureCLI' -ForegroundColor Gray
    Write-Host '      https://aka.ms/InstallAzureCLIWindows' -ForegroundColor Gray
    Write-Host ''
    exit 2
}
$azVer = Invoke-Az @('version', '-o', 'json')
Add-Result 'Prereq' 'Azure CLI' 'PASS' "v$($azVer.'azure-cli')"

# PowerShell 7+ is required for ForEach-Object -Parallel, which the ARM and
# endpoint probes rely on.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host ''
    Write-Host "  FATAL: PowerShell 7+ required (found $($PSVersionTable.PSVersion)). Parallel execution is unavailable on Windows PowerShell 5.1." -ForegroundColor Red
    Write-Host '      winget install --exact --id Microsoft.PowerShell' -ForegroundColor Gray
    Write-Host ''
    exit 2
}
Add-Result 'Prereq' 'PowerShell' 'PASS' "$($PSVersionTable.PSVersion) (parallel execution available)"

# The resource-graph extension makes tenant-wide private endpoint and DNS link
# discovery a single query instead of dozens of per-resource reads. Install it
# automatically rather than silently degrading to the slow path.
$argExt = Invoke-Az @('extension', 'show', '--name', 'resource-graph', '-o', 'json')
if (-not $argExt) {
    Write-Host '  Installing the Azure CLI resource-graph extension (one time)...' -ForegroundColor Yellow
    & az extension add --name resource-graph --only-show-errors 2>$null | Out-Null
    $argExt = Invoke-Az @('extension', 'show', '--name', 'resource-graph', '-o', 'json')
    if ($argExt) {
        Add-Result 'Prereq' 'resource-graph extension' 'PASS' "Installed v$($argExt.version)."
    } else {
        Add-Result 'Prereq' 'resource-graph extension' 'WARN' 'Could not install it. The script still works via direct REST and per-resource reads, but cross-subscription discovery will be slower and narrower.'
    }
} else {
    Add-Result 'Prereq' 'resource-graph extension' 'PASS' "v$($argExt.version)"
}

# --- authentication -----------------------------------------------------------
if ($SubscriptionId) {
    & az account set --subscription $SubscriptionId 2>$null | Out-Null
}
$ctx = Invoke-Az @('account', 'show', '-o', 'json')
if (-not $ctx) {
    Write-Host ''
    Write-Host '  Not signed in to Azure. Starting device code sign-in...' -ForegroundColor Yellow
    Write-Host '  Open the URL shown below and enter the code to continue.' -ForegroundColor Yellow
    Write-Host ''
    # Device code works over SSH, in containers, and on hosts with no browser -
    # exactly where a private-network diagnostic tends to be run.
    & az login --use-device-code --only-show-errors | Out-Null
    Write-Host ''
    if ($SubscriptionId) {
        & az account set --subscription $SubscriptionId 2>$null | Out-Null
    }
    $ctx = Invoke-Az @('account', 'show', '-o', 'json')
    if (-not $ctx) {
        Write-Host '  FATAL: sign-in did not complete. Run "az login --use-device-code" manually, then re-run.' -ForegroundColor Red
        Write-Host ''
        exit 2
    }
    Add-Result 'Prereq' 'Sign-in' 'PASS' "Signed in interactively as $($ctx.user.name)."
}
$SubscriptionId = $ctx.id
$idLabel = if ($ctx.user.type -eq 'servicePrincipal') {
    "service principal $($ctx.user.name)"
} else {
    $ctx.user.name
}
Add-Result 'Context' 'Azure CLI session' 'INFO' "$($ctx.name) [$($ctx.id)] as $idLabel"

# Fail fast if the token cannot be minted - every read below depends on it.
if (-not (Get-ArmToken)) {
    Write-Host ''
    Write-Host '  FATAL: could not acquire an ARM access token. Try: az login --use-device-code' -ForegroundColor Red
    Write-Host ''
    exit 2
}

# Pin the subscription set used for cross-subscription lookups. Private DNS zones
# routinely live in a hub subscription, and the ambient CLI context can be changed
# by another process mid-run - which silently turns "zone not found" into a false
# finding. Resolve the list once and pass it explicitly on every search.
$subsRaw = Invoke-Az @('account', 'list', '--query', "[?state=='Enabled'].id", '-o', 'json')
$script:SubScope = @(ConvertTo-Array $subsRaw)
if ($script:SubScope -notcontains $SubscriptionId) { $script:SubScope += $SubscriptionId }
Add-Result 'Context' 'Search scope' 'INFO' "$($script:SubScope.Count) enabled subscription(s) searched for private DNS zones."

#endregion

#region ------------------------------------------------- 1. account + topology

Write-Phase '1. Foundry account and deployment topology'

$acctId  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.CognitiveServices/accounts/$AccountName"
$account = Invoke-Arm -Id $acctId -ApiVersion $script:ApiCS

if (-not $account) {
    Add-Result 'Account' 'Resolve account' 'FAIL' "Not found or no access: $acctId"
    Write-Host ''
    Write-Host '  FATAL: cannot read the Foundry account. Check name, RG, subscription and RBAC.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

$props    = $account.properties
$location = $account.location
Add-Result 'Account' 'Resolve account' 'PASS' "kind=$($account.kind) sku=$($account.sku.name) region=$location"

if ($props.provisioningState -eq 'Succeeded') {
    Add-Result 'Account' 'Provisioning state' 'PASS' $props.provisioningState
} else {
    Add-Result 'Account' 'Provisioning state' 'FAIL' "$($props.provisioningState) - resource is not healthy; fix this before chasing network issues"
}

# --- topology classification -------------------------------------------------
$injections     = ConvertTo-Array $props.networkInjections
$agentInjection = $injections | Where-Object { $_.scenario -and $_.scenario -ne 'none' } | Select-Object -First 1
$injectedSubnetId = $null
$injectedVNetId   = $null
$topology         = 'none'

if ($agentInjection) {
    if ($agentInjection.useMicrosoftManagedNetwork -eq $true) {
        $topology = 'managed-network'
        Add-Result 'Topology' 'Deployment type' 'INFO' "Microsoft-managed network (scenario=$($agentInjection.scenario)). Outbound is Microsoft-managed; there is no customer subnet to inspect."
    } elseif ($agentInjection.subnetArmId) {
        $topology         = 'delegated-subnet'
        $injectedSubnetId = $agentInjection.subnetArmId
        $injectedVNetId   = Get-VNetIdFromSubnetId $injectedSubnetId
        Add-Result 'Topology' 'Deployment type' 'PASS' "Delegated subnet injection (scenario=$($agentInjection.scenario)) -> $(Get-IdSegment $injectedSubnetId 'virtualNetworks')/$(Get-IdSegment $injectedSubnetId 'subnets')"
    } else {
        $topology = 'injection-incomplete'
        Add-Result 'Topology' 'Deployment type' 'FAIL' "networkInjections present with scenario=$($agentInjection.scenario) but neither subnetArmId nor useMicrosoftManagedNetwork is set."
    }
} else {
    Add-Result 'Topology' 'Deployment type' 'INFO' 'No VNet injection configured. Inbound private endpoints may still apply; agent outbound traffic is not injected into a customer VNet.'
}

#endregion

#region -------------------------------------------- 2. control-plane exposure

Write-Phase '2. Control-plane network configuration'

$pna = $props.publicNetworkAccess
switch ($pna) {
    'Disabled' {
        $script:PublicDisabled[$AccountName] = $true
        Add-Result 'Control plane' 'publicNetworkAccess' 'PASS' 'Disabled - private-only, as expected for a private deployment.'
    }
    'Enabled'  { Add-Result 'Control plane' 'publicNetworkAccess' 'WARN' 'Enabled - the public endpoint still answers. Traffic may silently be flowing over the internet instead of your private endpoint.' }
    default    { Add-Result 'Control plane' 'publicNetworkAccess' 'INFO' "Value: $pna" }
}

$acls = $props.networkAcls
if ($acls) {
    $ipRules     = ConvertTo-Array $acls.ipRules
    $vnetRules   = ConvertTo-Array $acls.virtualNetworkRules
    Add-Result 'Control plane' 'Network ACLs' 'INFO' "defaultAction=$($acls.defaultAction) ipRules=$($ipRules.Count) vnetRules=$($vnetRules.Count)"
    if ($acls.defaultAction -eq 'Allow' -and $pna -eq 'Enabled') {
        Add-Result 'Control plane' 'ACL default action' 'WARN' 'defaultAction=Allow with public access enabled - the account is effectively open.'
    }
} else {
    Add-Result 'Control plane' 'Network ACLs' 'INFO' 'No networkAcls object set.'
}

if ($props.customSubDomainName) {
    Add-Result 'Control plane' 'Custom subdomain' 'PASS' $props.customSubDomainName
} else {
    Add-Result 'Control plane' 'Custom subdomain' 'FAIL' 'No custom subdomain. Private endpoints and Entra ID token auth both require one; the regional shared endpoint cannot be reached privately.'
}

$endpoints = @()
if ($props.endpoint) { $endpoints += $props.endpoint }
if ($props.endpoints) {
    foreach ($p in $props.endpoints.PSObject.Properties) {
        if ($p.Value -and $p.Value -notin $endpoints) { $endpoints += $p.Value }
    }
}
$fqdns = @()
foreach ($e in $endpoints) {
    try { $u = [uri]$e; if ($u.Host) { $fqdns += $u.Host } } catch { }
}
$fqdns = $fqdns | Sort-Object -Unique
Add-Result 'Control plane' 'Data-plane FQDNs' 'INFO' ($fqdns -join ', ')

#endregion

#region --------------------------------- 3. build the resource inventory

Write-Phase '3. Dependency discovery (project connections)'

# Each target: Name / Type / ResourceId / Zones (required private DNS zones)
$targets = New-Object System.Collections.Generic.List[object]
$targets.Add([pscustomobject]@{
    Name  = $AccountName
    Type  = 'Foundry account'
    Id    = $acctId
    # DNS label the private endpoint A records are registered under
    Label = if ($props.customSubDomainName) { $props.customSubDomainName } else { $AccountName }
    Zones = @('privatelink.services.ai.azure.com', 'privatelink.openai.azure.com', 'privatelink.cognitiveservices.azure.com')
    Area  = "Foundry: $AccountName"
}) | Out-Null

$zoneMap = @{
    'Microsoft.Storage/storageAccounts'      = @('privatelink.blob.core.windows.net', 'privatelink.file.core.windows.net')
    'Microsoft.DocumentDB/databaseAccounts'  = @('privatelink.documents.azure.com')
    'Microsoft.Search/searchServices'        = @('privatelink.search.windows.net')
    'Microsoft.KeyVault/vaults'              = @('privatelink.vaultcore.azure.net')
}
# Human-readable service names so each report section says what the resource is,
# not just what it is called.
$friendlyType = @{
    'Foundry account'                        = 'Foundry'
    'Microsoft.Storage/storageAccounts'      = 'Storage'
    'Microsoft.DocumentDB/databaseAccounts'  = 'Cosmos DB'
    'Microsoft.Search/searchServices'        = 'AI Search'
    'Microsoft.KeyVault/vaults'              = 'Key Vault'
}
$typeApi = @{
    'Microsoft.Storage/storageAccounts'      = '2023-05-01'
    'Microsoft.DocumentDB/databaseAccounts'  = '2024-11-15'
    'Microsoft.Search/searchServices'        = '2023-11-01'
    'Microsoft.KeyVault/vaults'              = '2023-07-01'
}
# A resource only needs the zone matching the sub-resource its private endpoint
# actually targets. Checking every theoretically-possible zone produces false
# failures (e.g. flagging a missing file-share record on a blob-only account).
$groupIdZone = @{
    'blob'          = 'privatelink.blob.core.windows.net'
    'file'          = 'privatelink.file.core.windows.net'
    'table'         = 'privatelink.table.core.windows.net'
    'queue'         = 'privatelink.queue.core.windows.net'
    'dfs'           = 'privatelink.dfs.core.windows.net'
    'web'           = 'privatelink.web.core.windows.net'
    'sql'           = 'privatelink.documents.azure.com'
    'mongodb'       = 'privatelink.mongo.cosmos.azure.com'
    'cassandra'     = 'privatelink.cassandra.cosmos.azure.com'
    'gremlin'       = 'privatelink.gremlin.cosmos.azure.com'
    'searchservice' = 'privatelink.search.windows.net'
    'vault'         = 'privatelink.vaultcore.azure.net'
}

$projects = Invoke-ArmNegotiated -Id "$acctId/projects" -CacheKey 'projects'
if ($null -eq $projects) {
    Add-Result 'Dependencies' 'Enumerate projects' 'FAIL' "Could not list projects under the account on any of: $($script:ApiCandidates -join ', '). Dependency checks below are incomplete - do not read the absence of findings as a clean bill of health."
}
$projList = ConvertTo-Array $projects.value
Add-Result 'Dependencies' 'Projects found' 'INFO' (($projList | ForEach-Object { ($_.name -split '/')[-1] }) -join ', ')

$seen        = New-Object System.Collections.Generic.HashSet[string]
$otherConns  = New-Object System.Collections.Generic.List[string]
$connReadOk  = $false
# One dependency resource can back several projects, and EACH project's managed
# identity needs its own role assignments. The target list is deduped so the
# network checks do not run twice, so the project mapping is kept alongside it
# rather than being lost with the duplicate.
$script:ResourceProjects = @{}
$script:ResourceConns    = @{}

foreach ($proj in $projList) {
    # $proj.name is returned fully qualified ("account/project"), so build the
    # connections URL from the project's own resource id rather than its name.
    $projLeaf = ($proj.name -split '/')[-1]
    $projId   = if ($proj.id) { $proj.id } else { "$acctId/projects/$projLeaf" }

    $conns = Invoke-ArmNegotiated -Id "$projId/connections" -CacheKey 'connections'
    if ($null -eq $conns) {
        Add-Result 'Dependencies' "Read connections [$projLeaf]" 'FAIL' "Could not list project connections on any of: $($script:ApiCandidates -join ', '). Private dependencies cannot be enumerated."
        continue
    }
    $connReadOk = $true

    foreach ($c in (ConvertTo-Array $conns.value)) {
        $resId = $null
        if ($c.properties.metadata) {
            foreach ($mp in $c.properties.metadata.PSObject.Properties) {
                if ($mp.Name -match '^resourceid$' -and $mp.Value -match '^/subscriptions/') {
                    $resId = $mp.Value; break
                }
            }
        }
        if (-not $resId -and $c.properties.target -match '^/subscriptions/') { $resId = $c.properties.target }
        if (-not $resId) {
            if ($c.properties.category) { $otherConns.Add("$($c.name) [$($c.properties.category)]") | Out-Null }
            continue
        }

        $provider = $null
        if ($resId -match '/providers/(?<p>[^/]+/[^/]+)/') { $provider = $Matches['p'] }
        if (-not $provider -or -not $zoneMap.ContainsKey($provider)) {
            $otherConns.Add("$($c.name) [$($c.properties.category)]") | Out-Null
            continue
        }
        $rk = $resId.ToLower()
        if (-not $script:ResourceProjects.ContainsKey($rk)) {
            $script:ResourceProjects[$rk] = New-Object System.Collections.Generic.List[string]
            $script:ResourceConns[$rk]    = New-Object System.Collections.Generic.List[object]
        }
        if (-not $script:ResourceProjects[$rk].Contains($projLeaf)) {
            $script:ResourceProjects[$rk].Add($projLeaf) | Out-Null
        }
        $script:ResourceConns[$rk].Add([pscustomobject]@{
            Project = $projLeaf; Conn = $c.name; AuthType = $c.properties.authType
        }) | Out-Null

        if (-not $seen.Add($rk)) { continue }

        $targets.Add([pscustomobject]@{
            Name  = ($resId -split '/')[-1]
            Type  = $provider
            Id    = $resId
            Label = ($resId -split '/')[-1]
            Zones = $zoneMap[$provider]
            Area  = "$($friendlyType[$provider]): $(($resId -split '/')[-1])"
            # Captured for the authorization phase. Foundry creates its own
            # connections with authType=AAD; a key-based connection changes
            # which failure mode applies and is worth surfacing.
            AuthType = $c.properties.authType
            ConnName = $c.name
            Project  = $projLeaf
        }) | Out-Null
    }
}

if ($script:ApiUsed['connections']) {
    Add-Result 'Dependencies' 'Connections API version' 'INFO' $script:ApiUsed['connections']
}

$depCount = $targets.Count - 1
if ($depCount -gt 0) {
    Add-Result 'Dependencies' 'Private dependencies discovered' 'PASS' (($targets | Select-Object -Skip 1 | ForEach-Object { "$($_.Name) ($(($_.Type -split '/')[-1]))" }) -join ', ')
} elseif ($connReadOk) {
    Add-Result 'Dependencies' 'Private dependencies discovered' 'WARN' 'Connections were readable but none resolved to Storage / Cosmos DB / AI Search / Key Vault. This account appears to use Microsoft-managed dependencies rather than BYO resources.'
}

if ($otherConns.Count -gt 0) {
    Add-Result 'Dependencies' 'Other connections (not checked)' 'INFO' "$($otherConns -join ', '). These are not standard private-link dependency types; App Insights/Log Analytics private access requires an Azure Monitor Private Link Scope (AMPLS), which this script does not evaluate."
}

#endregion

#region ------------------------------------------ 4. identity and authorization

Write-Phase '4. Identity and authorization (RBAC)'

<#
  Why this phase exists.

  Phases 1-3 and 5-7 answer "can packets reach the service". They cannot answer
  "is the caller allowed once they arrive". For the Agent Service those are not
  interchangeable questions: the service does not accept API keys at all, so a
  missing role assignment is not a degraded path, it is a hard stop - and it
  surfaces as a 403 that reads like a network problem.

  Three traps this phase is built around, each of which makes a naive check
  worse than no check:

    1. The grants belong to each PROJECT's managed identity, not the account's.
    2. Storage Blob Data Owner is assigned at account scope but carries an ABAC
       condition restricting it to the project's own agent containers. Matching
       on role GUID alone reports PASS on a grant that does not apply.
    3. The Cosmos data-plane grant is not an Azure RBAC assignment at all. It
       lives on the DocumentDB resource provider and is scoped to a child
       database, so Microsoft.Authorization never returns it.

  Read failures are reported as WARN, not FAIL, matching the convention used
  for private DNS zones: from the outside, "no assignment exists" and "you may
  not read assignments" look identical, and calling the second a failure
  invents findings on a healthy deployment.
#>

# --- who is running this ------------------------------------------------------
$callerOid = Get-TokenClaim -Token (Get-ArmToken) -Claim 'oid'
if ($callerOid) {
    Add-Result 'Identity' 'Calling principal' 'INFO' "objectId $callerOid ($idLabel). Role checks below marked 'caller' are about THIS principal."
} else {
    Add-Result 'Identity' 'Calling principal' 'WARN' 'Could not read the oid claim from the ARM token. Caller-side role checks are skipped; managed identity checks are unaffected.'
}

# --- account identity ---------------------------------------------------------
$acctIdentityType = if ($account.identity.type) { $account.identity.type } else { 'None' }
$acctOid = $account.identity.principalId
if ($acctOid) {
    Add-Result 'Identity' 'Account managed identity' 'INFO' "$acctIdentityType, principalId $acctOid. Note that BYO dependency grants belong to the PROJECT identities below, not to this one."
} else {
    Add-Result 'Identity' 'Account managed identity' 'INFO' "type=$acctIdentityType. No account-level principal; this is normal - BYO dependency access is granted to project identities."
}

# --- project identities -------------------------------------------------------
# The project list response does not always carry the identity block, so any
# project missing one is re-read individually before it is called absent.
$projIdentities = New-Object System.Collections.Generic.List[object]
foreach ($proj in $projList) {
    $projLeaf = ($proj.name -split '/')[-1]
    $projId   = if ($proj.id) { $proj.id } else { "$acctId/projects/$projLeaf" }
    $oid      = $proj.identity.principalId
    $itype    = $proj.identity.type

    if (-not $oid) {
        $full  = Invoke-ArmNegotiated -Id $projId -CacheKey 'projects'
        $oid   = $full.identity.principalId
        $itype = $full.identity.type
    }

    $projIdentities.Add([pscustomobject]@{
        Name = $projLeaf; Id = $projId; Oid = $oid; Type = $itype
    }) | Out-Null

    if ($oid) {
        Add-Result 'Identity' "Project identity [$projLeaf]" 'PASS' "$itype, principalId $oid"
    } else {
        Add-Result 'Identity' "Project identity [$projLeaf]" 'FAIL' "Project has no managed identity (type=$(if($itype){$itype}else{'None'})). A standard agent setup with BYO Storage, Cosmos DB or AI Search requires a system-assigned identity on the project - without it there is no principal to grant data access to and every dependency call will fail authorization."
    }
}

# --- capability host ----------------------------------------------------------
# Two of the required grants are only applied AFTER the capability host exists.
# If the caphost never provisioned, their absence is a symptom, not the disease,
# and reporting them as forgotten role assignments sends the reader the wrong way.
$caphostKnown   = $false
$caphostPresent = $false
foreach ($pi in $projIdentities) {
    $ch = Invoke-ArmNegotiated -Id "$($pi.Id)/capabilityHosts" -CacheKey 'capabilityHosts'
    if ($null -ne $ch) {
        $caphostKnown = $true
        $chList = ConvertTo-Array $ch.value
        if ($chList.Count -gt 0) {
            $caphostPresent = $true
            $states = ($chList | ForEach-Object { "$(($_.name -split '/')[-1])=$($_.properties.provisioningState)" }) -join ', '
            $bad = $chList | Where-Object { $_.properties.provisioningState -and $_.properties.provisioningState -ne 'Succeeded' }
            if ($bad) {
                Add-Result 'Identity' "Capability host [$($pi.Name)]" 'FAIL' "$states. The capability host is what creates the agent containers and the enterprise_memory database. While it is not in Succeeded state the post-provisioning role assignments (Storage Blob Data Owner, Cosmos Built-in Data Contributor) cannot be applied and agents will not run."
            } else {
                Add-Result 'Identity' "Capability host [$($pi.Name)]" 'PASS' $states
            }
        } else {
            Add-Result 'Identity' "Capability host [$($pi.Name)]" 'WARN' 'No capability host on this project. If this project is meant to run agents with BYO resources, the post-provisioning role assignments below will legitimately be missing and the capability host is the thing to fix first.'
        }
    }
}
if (-not $caphostKnown) {
    Add-Result 'Identity' 'Capability host' 'INFO' "Could not enumerate capability hosts on any of: $($script:ApiCandidates -join ', '). Post-provisioning role findings below are reported without that context."
}

# --- helper: evaluate one principal against one resource ----------------------
function Test-ResourceRbac {
    <#
      Compare the role assignments a principal actually holds over a resource
      against the roles the Foundry standard agent setup requires, and report
      the difference. Everything interesting is in the edge cases:
        * inherited grants (scope is an ancestor) still work, but are worth
          calling out because they are usually broader than intended
        * an ABAC condition can make a present assignment inapplicable
        * a read failure is not an absence
    #>
    param(
        [Parameter(Mandatory)][string] $Area,
        [Parameter(Mandatory)][string] $ResourceId,
        [Parameter(Mandatory)][string] $Provider,
        [Parameter(Mandatory)][string] $PrincipalId,
        [Parameter(Mandatory)][string] $PrincipalLabel,
        [bool] $CaphostPresent = $false,
        [bool] $CaphostKnown = $false
    )

    $req = $script:RequiredRoles[$Provider]
    if (-not $req) { return }

    $res = Get-RoleAssignment -Scope $ResourceId -PrincipalId $PrincipalId
    if (-not $res.Ok) {
        $hint = if ($res.Code -in 401, 403) {
            'The signed-in principal is not permitted to read role assignments here (needs Microsoft.Authorization/roleAssignments/read, included in Reader).'
        } else {
            "ARM returned $($res.Code)."
        }
        Add-Result $Area "RBAC read [$PrincipalLabel]" 'WARN' "Could not list role assignments on this resource. $hint Authorization cannot be confirmed either way - do not read the absence of failures below as a pass."
        return
    }

    $held = @($res.Value)
    foreach ($r in $req) {
        $guid  = $r.Guid
        $rname = Resolve-RoleName $guid
        $match = @($held | Where-Object { (Get-RoleGuid $_.properties.roleDefinitionId) -ieq $guid })

        if ($match.Count -eq 0) {
            # A missing post-caphost grant on a project with no capability host
            # is expected fallout, not an independent fault.
            if ($r.Phase -eq 'post' -and $CaphostKnown -and -not $CaphostPresent) {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'WARN' "Not assigned. This grant is applied after the capability host is created, and this project has no capability host - fix the capability host first and this should follow."
            } else {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'FAIL' "Not assigned to $PrincipalLabel on this resource. The Agent Service authenticates with Microsoft Entra ID only - there is no API key fallback - so this gap stops agent operations against this dependency outright. Both a direct and a group-resolved lookup were performed; if this identity is granted the role some other way, confirm before acting."
            }
            continue
        }

        foreach ($m in $match) {
            $mScope = $m.properties.scope
            $cond   = $m.properties.condition

            # An assignment can sit at the resource, ABOVE it (inherited, and
            # therefore broader than intended) or BELOW it (narrowed to a child
            # such as a single Search index, and therefore possibly too narrow
            # to cover what Foundry touches). Those are opposite problems and
            # must not share a message.
            $sLower = if ($mScope) { $mScope.ToLower() } else { '' }
            $rLower = $ResourceId.ToLower()
            $rel = if (-not $sLower)              { 'unknown' }
                   elseif ($sLower -eq $rLower)   { 'exact' }
                   elseif ($rLower.StartsWith($sLower.TrimEnd('/') + '/')) { 'ancestor' }
                   elseif ($sLower.StartsWith($rLower.TrimEnd('/') + '/')) { 'descendant' }
                   else                           { 'unrelated' }

            $where = switch ($rel) {
                'ancestor'   { " (inherited from $mScope)" }
                'descendant' { " (narrowed to $mScope)" }
                'unrelated'  { " (scoped to $mScope)" }
                default      { '' }
            }

            if ($cond) {
                # Expected on Storage Blob Data Owner: the condition narrows the
                # grant to the project's own '<workspaceId>*-azureml-agent'
                # containers. Present but wrongly-scoped reads as PASS to any
                # check that stops at the role GUID.
                if ($r.Condition) {
                    $looksRight = $cond -match '(?i)azureml-agent'
                    if ($looksRight) {
                        Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'PASS' "Assigned$where with the expected ABAC condition (conditionVersion $($m.properties.conditionVersion)) restricting it to the project's agent containers."
                    } else {
                        Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'WARN' "Assigned$where but the ABAC condition does not reference the expected '*-azureml-agent' container pattern. Condition: $cond. If it does not admit the project's own agent containers the assignment will not grant what the Agent Service needs, despite appearing present."
                    }
                } else {
                    Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'WARN' "Assigned$where but carries an ABAC condition that the standard setup does not apply to this role. Condition: $cond. Verify it does not exclude the operations Foundry performs."
                }
            } elseif ($rel -eq 'descendant') {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'WARN' "Assigned, but narrowed to the child scope $mScope rather than granted on the resource itself. That is narrower than the reference deployment. It only works if every object the Agent Service touches lives under that child scope - verify before treating this as satisfied."
            } elseif ($rel -eq 'unrelated') {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'WARN' "An assignment for this role exists at $mScope, which is neither this resource nor an ancestor or child of it. It does not grant access here."
            } elseif ($r.Condition) {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'PASS-NOTE' "Assigned$where with no ABAC condition. Functionally sufficient, and broader than the reference deployment, which conditions this role down to the project's agent containers only."
            } elseif ($rel -eq 'ancestor') {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'PASS-NOTE' "Assigned, inherited from $mScope rather than granted on this resource. This works, but it grants the same access over every resource under that scope."
            } else {
                Add-Result $Area "RBAC: $rname [$PrincipalLabel]" 'PASS' 'Assigned directly on this resource.'
            }
        }
    }

    # Surface roles that look like they should help but do not, so a reader
    # holding one of them stops assuming it covers the requirement.
    foreach ($h in $held) {
        $g = Get-RoleGuid $h.properties.roleDefinitionId
        if ($script:RoleNotApplicable.ContainsKey($g)) {
            Add-Result $Area "RBAC: non-applicable role [$PrincipalLabel]" 'INFO' "$($script:RoleNotApplicable[$g]) is assigned here. Microsoft Learn directs Foundry projects away from the Cognitive Services * and Azure AI Developer roles - they target AI Services accounts and Azure ML / Foundry hub workspaces. It does not satisfy any requirement above."
        }
    }
}

# --- per-dependency authorization ---------------------------------------------
$byoTargets = @($targets | Select-Object -Skip 1)

if ($byoTargets.Count -eq 0) {
    Add-Result 'Identity' 'Dependency authorization' 'SKIP' 'No BYO Storage / Cosmos DB / AI Search dependencies were discovered, so there are no dependency role assignments to verify. Microsoft-managed dependencies are authorized by the platform.'
} elseif (-not ($projIdentities | Where-Object { $_.Oid })) {
    Add-Result 'Identity' 'Dependency authorization' 'SKIP' 'No project managed identity was resolved, so there is no principal to evaluate dependency role assignments against.'
} else {
    foreach ($t in $byoTargets) {
        $rk = $t.Id.ToLower()
        $owners = if ($script:ResourceProjects.ContainsKey($rk)) { @($script:ResourceProjects[$rk]) } else { @() }
        $subjects = @($projIdentities | Where-Object { $_.Oid -and ($owners.Count -eq 0 -or $owners -contains $_.Name) })

        if ($subjects.Count -eq 0) { continue }

        foreach ($pi in $subjects) {
            Test-ResourceRbac -Area $t.Area -ResourceId $t.Id -Provider $t.Type `
                -PrincipalId $pi.Oid -PrincipalLabel "project $($pi.Name)" `
                -CaphostPresent $caphostPresent -CaphostKnown $caphostKnown
        }

        # --- connection auth type -------------------------------------------
        if ($script:ResourceConns.ContainsKey($rk)) {
            foreach ($cn in $script:ResourceConns[$rk]) {
                $at = if ($cn.AuthType) { $cn.AuthType } else { 'unspecified' }
                if ($at -imatch '^(aad|entra)') {
                    Add-Result $t.Area "Connection auth [$($cn.Project)/$($cn.Conn)]" 'PASS' "authType=$at. Entra ID token auth, which is what the standard agent setup uses and what the role assignments above serve."
                } elseif ($at -imatch 'key|sas|connectionstring') {
                    Add-Result $t.Area "Connection auth [$($cn.Project)/$($cn.Conn)]" 'WARN' "authType=$at. The connection authenticates with a key or SAS rather than Entra ID. That bypasses the role assignments above, and it breaks outright if the resource has local/shared-key auth disabled. The reference deployment uses authType=AAD for all three BYO dependencies."
                } else {
                    Add-Result $t.Area "Connection auth [$($cn.Project)/$($cn.Conn)]" 'INFO' "authType=$at"
                }
            }
        }

        # --- local-auth posture: decides how fatal an RBAC gap is ------------
        switch ($t.Type) {

            'Microsoft.Storage/storageAccounts' {
                $sa = Invoke-Arm -Id $t.Id -ApiVersion '2023-05-01'
                if ($sa) {
                    # Tri-state: the property is absent until explicitly set, and
                    # both null and true mean shared key is permitted.
                    $ask = $sa.properties.allowSharedKeyAccess
                    if ($ask -eq $false) {
                        Add-Result $t.Area 'Shared key access' 'PASS' 'allowSharedKeyAccess=false. Entra ID is the only authentication path, which matches the reference deployment - and makes every blob role assignment above mandatory rather than advisory.'
                    } elseif ($null -eq $ask) {
                        Add-Result $t.Area 'Shared key access' 'INFO' 'allowSharedKeyAccess is not set. Azure treats unset as allowed, so shared-key auth is still available to other consumers. Foundry itself uses Entra ID regardless.'
                    } else {
                        Add-Result $t.Area 'Shared key access' 'INFO' 'allowSharedKeyAccess=true. Shared-key auth remains available to other consumers; Foundry still authenticates with Entra ID, so the role assignments above are what govern it.'
                    }
                }
            }

            'Microsoft.Search/searchServices' {
                $ss = Invoke-Arm -Id $t.Id -ApiVersion $script:ApiSearch
                if ($ss) {
                    $localAuthDisabled = $ss.properties.disableLocalAuth -eq $true
                    $aadOptionPresent  = $null -ne $ss.properties.authOptions.aadOrApiKey
                    if (-not $localAuthDisabled -and -not $aadOptionPresent) {
                        Add-Result $t.Area 'Entra ID data-plane auth' 'FAIL' "The service is in apiKeyOnly mode (disableLocalAuth=false and authOptions has no aadOrApiKey block), which is the default for a new search service. In that mode the service REJECTS Entra ID tokens, so Foundry's AAD-typed connection fails with a 403 that reads like a missing permission no matter how the roles above are assigned. Fix: az search service update --name $($t.Name) --resource-group $(Get-IdSegment $t.Id 'resourceGroups') --auth-options aadOrApiKey --aad-auth-failure-mode http401WithBearerChallenge"
                    } elseif ($localAuthDisabled) {
                        Add-Result $t.Area 'Entra ID data-plane auth' 'PASS' 'disableLocalAuth=true. API keys are off and Entra ID tokens are accepted, so the role assignments above are the sole access control.'
                    } else {
                        Add-Result $t.Area 'Entra ID data-plane auth' 'PASS' "authOptions.aadOrApiKey present (aadAuthFailureMode=$($ss.properties.authOptions.aadOrApiKey.aadAuthFailureMode)). Entra ID tokens are accepted alongside API keys, which is the configuration the reference deployment creates."
                    }
                }
            }

            'Microsoft.DocumentDB/databaseAccounts' {
                $cdb = Invoke-Arm -Id $t.Id -ApiVersion '2024-11-15'
                if ($cdb) {
                    if ($cdb.properties.disableLocalAuth -eq $true) {
                        Add-Result $t.Area 'Local auth' 'PASS' 'disableLocalAuth=true. Account keys are off, matching the reference deployment; data-plane role assignments are the only access path.'
                    } else {
                        Add-Result $t.Area 'Local auth' 'INFO' 'disableLocalAuth is not enabled, so account keys still work. The reference deployment disables them. Foundry uses Entra ID either way.'
                    }
                }

                # Cosmos data-plane RBAC is a separate resource provider. These
                # assignments are invisible to Microsoft.Authorization, so a
                # check that stops at Azure RBAC misses them entirely.
                $sqlRes = $null
                foreach ($v in $script:ApiCosmosSqlCandidates) {
                    $sqlRes = Invoke-ArmUrl -Url "https://management.azure.com$($t.Id)/sqlRoleAssignments?api-version=$v"
                    if ($sqlRes.Ok) { break }
                }

                if (-not $sqlRes -or -not $sqlRes.Ok) {
                    Add-Result $t.Area 'Cosmos data-plane RBAC' 'WARN' "Could not list sqlRoleAssignments on any of: $($script:ApiCosmosSqlCandidates -join ', '). This is a separate resource provider from Azure RBAC, so the role findings above say nothing about data-plane access. Verify manually before concluding this account is correctly authorized."
                } else {
                    $sqlAll = @($sqlRes.Value)
                    foreach ($pi in $subjects) {
                        $dataRole = '00000000-0000-0000-0000-000000000002'
                        $mine = @($sqlAll | Where-Object {
                            $_.properties.principalId -ieq $pi.Oid -and
                            (Get-RoleGuid $_.properties.roleDefinitionId) -ieq $dataRole
                        })

                        if ($mine.Count -eq 0) {
                            $anyRole = @($sqlAll | Where-Object { $_.properties.principalId -ieq $pi.Oid })
                            if ($anyRole.Count -gt 0) {
                                $names = ($anyRole | ForEach-Object { Resolve-RoleName (Get-RoleGuid $_.properties.roleDefinitionId) }) -join ', '
                                Add-Result $t.Area "Cosmos data-plane RBAC [project $($pi.Name)]" 'FAIL' "Cosmos DB Built-in Data Contributor is not assigned. The identity does hold: $names. Read-only or narrower data roles are not sufficient - the Agent Service writes thread state to the enterprise_memory database."
                            } else {
                                $note = if ($caphostKnown -and -not $caphostPresent) {
                                    ' This grant is applied after the capability host is created, and this project has no capability host - fix that first.'
                                } else { '' }
                                Add-Result $t.Area "Cosmos data-plane RBAC [project $($pi.Name)]" 'FAIL' "No Cosmos data-plane role assignment exists for this project identity. Azure RBAC roles such as Cosmos DB Operator do NOT grant data access - Cosmos keeps a separate assignment system under Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments, and agent thread storage needs Cosmos DB Built-in Data Contributor there.$note"
                            }
                        } else {
                            foreach ($m in $mine) {
                                # The reference deployment scopes this to
                                # /dbs/enterprise_memory, not the account root.
                                # Requiring account scope would false-negative on
                                # every correctly deployed environment.
                                $sc = $m.properties.scope
                                $acctScope = $t.Id
                                if ($sc -and ($sc.ToLower() -eq $acctScope.ToLower())) {
                                    Add-Result $t.Area "Cosmos data-plane RBAC [project $($pi.Name)]" 'PASS-NOTE' 'Cosmos DB Built-in Data Contributor assigned at account scope. Sufficient, and broader than the reference deployment, which scopes it to the enterprise_memory database.'
                                } elseif ($sc -imatch '/dbs/enterprise_memory') {
                                    Add-Result $t.Area "Cosmos data-plane RBAC [project $($pi.Name)]" 'PASS' "Cosmos DB Built-in Data Contributor assigned at $sc, matching the reference deployment."
                                } else {
                                    Add-Result $t.Area "Cosmos data-plane RBAC [project $($pi.Name)]" 'WARN' "Cosmos DB Built-in Data Contributor is assigned, but scoped to $sc. The Agent Service stores thread state under the enterprise_memory database; if that scope is not an ancestor of it, the grant does not apply where it is needed."
                                }
                            }
                        }
                    }
                }
            }

            'Microsoft.KeyVault/vaults' {
                # Key Vault is not part of the project-based standard agent
                # setup. It only appears here because a connection references
                # one, so the checks are about that connection, not about a
                # required dependency.
                $kv = Invoke-Arm -Id $t.Id -ApiVersion '2023-07-01'
                if ($kv) {
                    if ($kv.properties.enableRbacAuthorization -eq $true) {
                        Add-Result $t.Area 'Access model' 'INFO' 'enableRbacAuthorization=true. Azure RBAC governs this vault, so the role findings above are the relevant control.'
                    } else {
                        $pols = ConvertTo-Array $kv.properties.accessPolicies
                        $hit = @()
                        foreach ($pi in $subjects) {
                            if ($pi.Oid) { $hit += @($pols | Where-Object { $_.objectId -ieq $pi.Oid }) }
                        }
                        if ($hit.Count -gt 0) {
                            Add-Result $t.Area 'Access model' 'PASS' "Legacy access-policy model, and the project identity has a policy entry. Key Vault data-plane RBAC roles are ignored on this vault, so any role findings above are not what governs access here."
                        } else {
                            Add-Result $t.Area 'Access model' 'FAIL' "Legacy access-policy model (enableRbacAuthorization=false) with no access policy for the project identity. On a vault in this mode the Key Vault RBAC roles have no effect at all, so granting Key Vault Secrets User will not help - add an access policy, or switch the vault to the RBAC permission model."
                        }
                    }
                }
                Add-Result $t.Area 'Key Vault scope note' 'INFO' 'Key Vault is not a required BYO dependency of the project-based Foundry standard agent setup (those are Storage, Cosmos DB and AI Search). It is checked here because a project connection references it.'
            }
        }
    }
}

# --- caller access to the Foundry account and projects ------------------------
if ($callerOid) {
    $foundryRoles = @(
        '53ca6127-db72-4b80-b1b0-d745d6d5456d'   # Foundry User
        'c883944f-8b7b-4483-af10-35834be79c4a'   # Foundry Owner
        'e47c6f54-e4a2-4754-9501-8e0985b135e1'   # Foundry Account Owner
        'eadc314b-1a2d-4efa-be10-5d325db5065e'   # Foundry Project Manager
        'eed3b665-ab3a-47b6-8f48-c9382fb1dad6'   # Foundry Agent Consumer
    )

    $callerRes = Get-RoleAssignment -Scope $acctId -PrincipalId $callerOid
    if (-not $callerRes.Ok) {
        Add-Result 'Identity' 'Caller access to Foundry account' 'WARN' "Could not list role assignments on the account$(if($callerRes.Code){" (HTTP $($callerRes.Code))"}). Reading role assignments needs Microsoft.Authorization/roleAssignments/read, which Reader includes."
    } else {
        $callerHeld = @($callerRes.Value)
        $heldGuids  = @($callerHeld | ForEach-Object { Get-RoleGuid $_.properties.roleDefinitionId })
        $foundryHit = @($heldGuids | Where-Object { $foundryRoles -contains $_.ToLower() })

        if ($foundryHit.Count -gt 0) {
            $names = ($foundryHit | ForEach-Object { Resolve-RoleName $_ } | Select-Object -Unique) -join ', '
            Add-Result 'Identity' 'Caller access to Foundry account' 'PASS' "$names. Sufficient to work with projects on this account."
        } else {
            $naHit = @($heldGuids | Where-Object { $script:RoleNotApplicable.ContainsKey($_.ToLower()) })
            if ($naHit.Count -gt 0) {
                $names = ($naHit | ForEach-Object { $script:RoleNotApplicable[$_.ToLower()] } | Select-Object -Unique) -join ', '
                Add-Result 'Identity' 'Caller access to Foundry account' 'WARN' "No Foundry role is assigned to the calling principal. It does hold: $names - and these do NOT grant Foundry project access. Microsoft Learn is explicit that the Cognitive Services * roles target AI Services accounts and that Azure AI Developer is scoped to Azure ML workspaces and Foundry hubs. Assign Foundry User (53ca6127-db72-4b80-b1b0-d745d6d5456d) instead."
            } else {
                $other = ($heldGuids | ForEach-Object { Resolve-RoleName $_ } | Select-Object -Unique) -join ', '
                $detail = if ($other) { " The principal holds: $other." } else { ' Neither a direct nor a group-resolved lookup returned any role assignment for this principal.' }
                Add-Result 'Identity' 'Caller access to Foundry account' 'WARN' "No Foundry role (User / Owner / Account Owner / Project Manager / Agent Consumer) is assigned to the calling principal.$detail Control-plane reads can still succeed via Reader or Contributor, so this does not affect the checks in this report - but the Agent Service accepts Entra ID only, with no API key fallback, so data-plane calls will fail until a Foundry role is assigned."
            }
        }
    }

    # The project identity also needs Foundry User on the account. Portal-created
    # projects get this automatically; projects deployed from IaC, CLI or SDK do
    # not, which is exactly the shape of deployment this script is aimed at.
    foreach ($pi in $projIdentities) {
        if (-not $pi.Oid) { continue }
        $miRes = Get-RoleAssignment -Scope $acctId -PrincipalId $pi.Oid
        if (-not $miRes.Ok) { continue }
        $miGuids = @($miRes.Value | ForEach-Object { (Get-RoleGuid $_.properties.roleDefinitionId).ToLower() })
        $hit = @($miGuids | Where-Object { $foundryRoles -contains $_ })
        if ($hit.Count -gt 0) {
            $names = ($hit | ForEach-Object { Resolve-RoleName $_ } | Select-Object -Unique) -join ', '
            Add-Result 'Identity' "Project identity on account [$($pi.Name)]" 'PASS' $names
        } else {
                Add-Result 'Identity' "Project identity on account [$($pi.Name)]" 'WARN' "The project's managed identity holds no Foundry role on the parent account. Microsoft documents Foundry User here as a minimum alongside the dependency grants. This assignment is created automatically only when a project is made in the portal by a principal that can assign roles - deployments from Bicep, Terraform, CLI or SDK routinely omit it. Raised as a warning rather than a failure because a grant made through an Entra group at a scope above this account may not be visible here."
        }
    }
}

#endregion

#region --------------------- 5. private endpoints + DNS per resource

Write-Phase '5. Private endpoints and private DNS'

# Cache of zone name -> zone objects found anywhere we can see
$zoneCache = @{}

function Find-PrivateDnsZone {
    param([string] $ZoneName)
    if ($zoneCache.ContainsKey($ZoneName)) { return $zoneCache[$ZoneName] }

    $rows = Invoke-Graph -Query @"
Resources
| where type =~ 'microsoft.network/privatednszones' and name =~ '$ZoneName'
| project id, name, subscriptionId, resourceGroup
"@ -First 50

    # Resource Graph can lag or be throttled; fall back to a direct list so an empty
    # ARG result never masquerades as "the zone does not exist". Bounded to the
    # account's own subscription plus an explicit hub, since a serial sweep of every
    # accessible subscription would be pathologically slow in large tenants.
    if (-not $rows -or $rows.Count -eq 0) {
        $fallbackSubs = @($SubscriptionId)
        if ($HubVNetId -and $HubVNetId -match '^/subscriptions/(?<s>[^/]+)/') {
            if ($Matches['s'] -ne $SubscriptionId) { $fallbackSubs += $Matches['s'] }
        }
        foreach ($s in $fallbackSubs) {
            $local = Invoke-Az @('network', 'private-dns', 'zone', 'list', '--subscription', $s,
                                 '--query', "[?name=='$ZoneName'].{id:id,name:name,resourceGroup:resourceGroup}", '-o', 'json')
            $rows += ConvertTo-Array $local
        }
    }
    $zoneCache[$ZoneName] = $rows
    return $rows
}

function Get-ZoneLinks {
    <#
      VNet links for a specific set of zone ids, as a hashtable
      zoneId(lower) -> array of { linkName, vnetId, registration }, or $null when
      the links could not be read at all.

      One Resource Graph query filtered to just the zones in question covers
      everything not already cached, so the result set stays small and the
      1000-row page limit cannot silently truncate a zone's links. A zone ARG
      returns nothing for gets a direct read: ARG can lag a freshly created link,
      and an empty answer must never masquerade as "no links".
    #>
    param([string[]] $ZoneIds)
    if ($null -eq $script:ZoneLinkCache) { $script:ZoneLinkCache = @{} }
    $want = @($ZoneIds | Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Sort-Object -Unique |
              Where-Object { -not $script:ZoneLinkCache.ContainsKey($_) })

    if ($want.Count -gt 0) {
        $found  = @{}
        $inList = ($want | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
        $rows = Invoke-Graph -Query @"
Resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| extend zoneId = tolower(strcat_array(array_slice(split(id, '/'), 0, 8), '/'))
| where zoneId in ($inList)
| project linkName = name, zoneId,
          vnetId = tostring(properties.virtualNetwork.id),
          registration = tobool(properties.registrationEnabled)
"@ -First 1000
        foreach ($r in $rows) {
            if (-not $r.zoneId) { continue }
            $k = $r.zoneId.ToLower()
            if (-not $found.ContainsKey($k)) { $found[$k] = New-Object System.Collections.Generic.List[object] }
            $found[$k].Add([pscustomobject]@{
                linkName = $r.linkName; vnetId = $r.vnetId; registration = [bool]$r.registration
            }) | Out-Null
        }
        foreach ($k in $want) {
            if ($found.ContainsKey($k)) { $script:ZoneLinkCache[$k] = $found[$k].ToArray(); continue }
            $links = Invoke-Arm -Id "$k/virtualNetworkLinks" -ApiVersion '2020-06-01'
            if ($null -eq $links) { $script:ZoneLinkCache[$k] = $null; continue }
            $script:ZoneLinkCache[$k] = @(ConvertTo-Array $links.value | ForEach-Object {
                [pscustomobject]@{
                    linkName = $_.name; vnetId = $_.properties.virtualNetwork.id
                    registration = [bool]$_.properties.registrationEnabled
                }
            })
        }
    }

    $out = @{}
    foreach ($z in $ZoneIds) { if ($z) { $out[$z.ToLower()] = $script:ZoneLinkCache[$z.ToLower()] } }
    return $out
}

function Get-ZoneRoles {
    <#
      Why (if at all) a zone instance is on this deployment's resolution path.
      Empty result = bystander: same zone name, but nothing here resolves through it.
    #>
    param([string] $ZoneId, $Links, [string[]] $WiredZoneIds, [string[]] $PeVNetIds)
    $roles = New-Object System.Collections.Generic.List[string]
    if ($WiredZoneIds | Where-Object { $_ -ieq $ZoneId }) { $roles.Add('wired to PE') | Out-Null }
    $vnets = @($Links | ForEach-Object { $_.vnetId } | Where-Object { $_ })
    if ($injectedVNetId -and ($vnets | Where-Object { $_ -ieq $injectedVNetId })) { $roles.Add('linked to injected VNet') | Out-Null }
    if ($HubVNetId      -and ($vnets | Where-Object { $_ -ieq $HubVNetId }))      { $roles.Add('linked to hub VNet') | Out-Null }
    foreach ($pv in $PeVNetIds) {
        if ($vnets | Where-Object { $_ -ieq $pv }) { $roles.Add('linked to PE VNet') | Out-Null; break }
    }
    return ,@($roles)
}

function Get-ZoneLinkNames {
    param($Links)
    if ($null -eq $Links) { return '(links unreadable)' }
    $l = @($Links)
    if ($l.Count -eq 0) { return '(no VNet links)' }
    return ($l | ForEach-Object { Get-IdSegment $_.vnetId 'virtualNetworks' } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
}

function Get-RecordChecks {
    <# Which A-record label(s) and expected IPs to look for in a zone with this suffix. #>
    param([string] $Suffix, [hashtable] $FqdnIpMap, [string] $Label, [string[]] $AllIps)
    $checks = @()
    foreach ($kv in $FqdnIpMap.GetEnumerator()) {
        if ($kv.Key -like "*.$Suffix") {
            $checks += [pscustomobject]@{ Label = ($kv.Key -split '\.')[0]; Want = @($kv.Value) }
        }
    }
    if ($checks.Count -eq 0 -and $AllIps.Count -gt 0) {
        # no published FQDN map - fall back to the resource's DNS label
        $checks += [pscustomobject]@{ Label = $Label; Want = @($AllIps) }
    }
    return ,$checks
}

function Get-ZoneARecordState {
    <#
      Read a zone's A records and score each check against them.
      Returns $null when the record sets cannot be read.
      Item State: ok | missing | wrong
    #>
    param([string] $ZoneId, [object[]] $Checks)
    $recs = Invoke-Arm -Id "$ZoneId/A" -ApiVersion '2020-06-01'
    if ($null -eq $recs) { return $null }
    $recList = @(ConvertTo-Array $recs.value)
    $present = ($recList | ForEach-Object { $_.name }) -join ', '
    $items = foreach ($chk in $Checks) {
        $rec = $recList | Where-Object { $_.name -ieq $chk.Label } | Select-Object -First 1
        if (-not $rec) {
            [pscustomobject]@{ Label = $chk.Label; State = 'missing'; Ips = @(); Want = $chk.Want }
            continue
        }
        $recIps = @((ConvertTo-Array $rec.properties.aRecords) | ForEach-Object { $_.ipv4Address })
        $state  = if ($recIps | Where-Object { $chk.Want -contains $_ }) { 'ok' } else { 'wrong' }
        [pscustomobject]@{ Label = $chk.Label; State = $state; Ips = $recIps; Want = $chk.Want }
    }
    return [pscustomobject]@{ RecordCount = $recList.Count; Present = $present; Items = @($items) }
}

function Test-ZoneVNetLinks {
    <#
      VNet-link verdict for an on-path zone instance:
        injected VNet                      = PASS
        PE VNet (no injected VNet exists)  = PASS
        hub / PE VNet / other VNet         = PASS-NOTE
        no links                           = FAIL
    #>
    param([string] $ZoneName, [string] $Area, $Links, [string[]] $PeVNetIds, [string] $Tag = '')
    $short = $ZoneName -replace '^privatelink\.', ''
    $check = "Zone links: $short$Tag"

    if ($null -eq $Links) {
        Add-Result $Area $check 'WARN' 'VNet links not readable (cross-subscription or missing Private DNS Zone Reader).'
        return
    }
    $linkList      = @($Links)
    $linkedVNetIds = @($linkList | ForEach-Object { $_.vnetId } | Where-Object { $_ })
    if ($linkedVNetIds.Count -eq 0) {
        Add-Result $Area $check 'FAIL' 'Zone has no virtual network links at all. Nothing can resolve it.'
        return
    }
    $names      = ($linkList | ForEach-Object { "$($_.linkName)->$(Get-IdSegment $_.vnetId 'virtualNetworks')" }) -join ', '
    $regEnabled = @($linkList | Where-Object { $_.registration -eq $true } | ForEach-Object { $_.linkName })

    $matchInjected = $injectedVNetId -and [bool]($linkedVNetIds | Where-Object { $_ -ieq $injectedVNetId })
    $matchHub      = $HubVNetId      -and [bool]($linkedVNetIds | Where-Object { $_ -ieq $HubVNetId })
    $matchPe       = $null
    foreach ($pv in $PeVNetIds) { if ($linkedVNetIds | Where-Object { $_ -ieq $pv }) { $matchPe = $pv; break } }

    if ($matchInjected) {
        Add-Result $Area $check 'PASS' "Linked to the injected VNet ($(Get-IdSegment $injectedVNetId 'virtualNetworks')). Links: $names"
    } elseif ($matchHub) {
        Add-Result $Area $check 'PASS-NOTE' "Linked to the supplied hub VNet ($(Get-IdSegment $HubVNetId 'virtualNetworks')) but NOT to the injected VNet. Valid only if the injected VNet peers to the hub AND uses the hub resolver / DNS servers. Links: $names"
    } elseif ($matchPe -and -not $injectedVNetId) {
        Add-Result $Area $check 'PASS' "Linked to the private endpoint's VNet ($(Get-IdSegment $matchPe 'virtualNetworks')). Links: $names"
    } elseif ($matchPe) {
        Add-Result $Area $check 'PASS-NOTE' "Linked to the private endpoint's VNet ($(Get-IdSegment $matchPe 'virtualNetworks')) but NOT to the injected VNet. Zone links do not follow VNet peering - the injected VNet resolves this only if its DNS servers forward to a resolver in a linked VNet. Links: $names"
    } elseif ($injectedVNetId -or $HubVNetId) {
        Add-Result $Area $check 'PASS-NOTE' "Linked to a centralized/other VNet, not the injected VNet. Confirm that VNet is your hub resolver and that the injected VNet forwards to it. Links: $names"
    } else {
        Add-Result $Area $check 'INFO' "No injected VNet to compare against. Links: $names"
    }

    if ($regEnabled.Count -gt 0) {
        Add-Result $Area "Zone auto-registration: $short$Tag" 'WARN' "registrationEnabled=true on: $($regEnabled -join ', '). Private-link zones should have auto-registration off; it can overwrite private endpoint A records."
    }
}

function Test-ResourcePrivateLink {
    param([pscustomobject] $Target)

    $area  = if ($Target.Area) { $Target.Area } else { $Target.Name }
    $short = ($Target.Type -split '/')[-1]

    $res = Invoke-Arm -Id $Target.Id -ApiVersion ($typeApi[$Target.Type] ?? $script:ApiCS)
    if (-not $res) {
        Add-Result $area "Read $short" 'WARN' "Cannot read $($Target.Id) - likely cross-subscription or missing Reader. Skipping its checks."
        return
    }

    # public exposure on the dependency
    $depPna = $res.properties.publicNetworkAccess
    if ($depPna) {
        if ($depPna -match 'Disabled|Deny|SecuredByPerimeter') {
            $script:PublicDisabled[$Target.Name] = $true
            Add-Result $area 'publicNetworkAccess' 'PASS' $depPna
        } else {
            Add-Result $area 'publicNetworkAccess' 'WARN' "$depPna - dependency still reachable publicly; a working app here does not prove private connectivity works."
        }
    }

    # private endpoint connections on the resource
    $pecs = ConvertTo-Array $res.properties.privateEndpointConnections
    if ($pecs.Count -eq 0) {
        Add-Result $area 'Private endpoints' 'FAIL' "No private endpoint connections on this $short. With public access locked down, Foundry cannot reach it."
        return
    }

    $approved = @()
    foreach ($pec in $pecs) {
        $state = $pec.properties.privateLinkServiceConnectionState.status
        $peId  = $pec.properties.privateEndpoint.id
        $peNm  = if ($peId) { ($peId -split '/')[-1] } else { $pec.name }
        $sfx   = if ($pecs.Count -gt 1) { " [$peNm]" } else { '' }
        if ($state -ieq 'Approved') {
            $approved += $pec
        } else {
            Add-Result $area "PE connection$sfx" 'FAIL' "State=$state - $($pec.properties.privateLinkServiceConnectionState.description). Traffic will be rejected until approved."
        }
    }
    if ($approved.Count -gt 0) {
        Add-Result $area 'Private endpoints' 'PASS' "$($approved.Count) approved connection(s)."
    }

    # Which sub-resources are actually private-linked? Only their zones matter.
    # groupIds are carried on the private endpoint's own connection objects; the
    # resource-side privateEndpointConnections usually omit them, so seed from the
    # PEC here and let the private endpoint walk below fill in the rest.
    $groupIds = @()
    foreach ($pec in $pecs) { $groupIds += (ConvertTo-Array $pec.properties.groupIds) }

    # ---- walk each approved PE: placement, NIC IPs, zone group -------------
    $allExpectedIps = New-Object System.Collections.Generic.List[string]
    $fqdnIpMap      = @{}
    $wiredZoneIds   = New-Object System.Collections.Generic.List[string]
    $peVNetIds      = New-Object System.Collections.Generic.List[string]

    foreach ($pec in $approved) {
        $peId = $pec.properties.privateEndpoint.id
        if (-not $peId) { continue }
        $peNm = ($peId -split '/')[-1]
        # Only disambiguate labels with the endpoint name when there is more than
        # one; otherwise it is redundant and eats column width.
        $peSfx = if ($approved.Count -gt 1) { " [$peNm]" } else { '' }
        $pe   = Invoke-Arm -Id $peId -ApiVersion $script:ApiNet
        if (-not $pe) {
            Add-Result $area "PE detail$peSfx" 'WARN' 'Private endpoint object not readable (different subscription?).'
            continue
        }

        # where does the PE live
        $peSubnet = $pe.properties.subnet.id
        $peVNet   = Get-VNetIdFromSubnetId $peSubnet
        if ($peVNet -and -not ($peVNetIds | Where-Object { $_ -ieq $peVNet })) { $peVNetIds.Add($peVNet) | Out-Null }
        Add-Result $area "PE placement$peSfx" 'INFO' "$(Get-IdSegment $peSubnet 'virtualNetworks')/$(Get-IdSegment $peSubnet 'subnets')"

        # exact FQDN -> IP mapping, when the platform published one
        foreach ($cfg in (ConvertTo-Array $pe.properties.customDnsConfigs)) {
            foreach ($ip in (ConvertTo-Array $cfg.ipAddresses)) {
                if ($cfg.fqdn) { $fqdnIpMap[$cfg.fqdn] = $ip }
                if ($ip -and -not $allExpectedIps.Contains($ip)) { $allExpectedIps.Add($ip) | Out-Null }
            }
        }
        # the authoritative groupIds live here
        foreach ($plsc in (ConvertTo-Array $pe.properties.privateLinkServiceConnections)) {
            $groupIds += (ConvertTo-Array $plsc.properties.groupIds)
        }
        foreach ($plsc in (ConvertTo-Array $pe.properties.manualPrivateLinkServiceConnections)) {
            $groupIds += (ConvertTo-Array $plsc.properties.groupIds)
        }
        # always read the NICs too - customDnsConfigs is frequently empty
        foreach ($nicRef in (ConvertTo-Array $pe.properties.networkInterfaces)) {
            $nic = Invoke-Arm -Id $nicRef.id -ApiVersion $script:ApiNet
            foreach ($ipc in (ConvertTo-Array $nic.properties.ipConfigurations)) {
                $ip = $ipc.properties.privateIPAddress
                if ($ip -and -not $allExpectedIps.Contains($ip)) { $allExpectedIps.Add($ip) | Out-Null }
            }
        }

        if ($allExpectedIps.Count -eq 0) {
            Add-Result $area "PE NIC addresses$peSfx" 'FAIL' 'Private endpoint has no private IP addresses. The endpoint is not functional.'
        } else {
            $nonPriv = $allExpectedIps | Where-Object { -not (Test-PrivateIPv4 $_) }
            $status  = if ($nonPriv) { 'WARN' } else { 'PASS' }
            Add-Result $area "PE NIC addresses$peSfx" $status ($allExpectedIps -join ', ')
            # Publish for the client phase so it can tell a real private endpoint
            # address apart from a proxy/load-balancer VIP that merely looks private.
            foreach ($eip in $allExpectedIps) {
                if (-not $script:KnownPeIps.Contains($eip)) { $script:KnownPeIps.Add($eip) | Out-Null }
            }
        }

        # Read the DNS zone group purely to learn which zones this endpoint is
        # wired to - those get their A records validated below. The presence or
        # absence of a zone group is not itself reported: hand-managed and
        # IaC-managed records resolve exactly as well, so it is not a finding.
        $zgs = Invoke-Arm -Id "$peId/privateDnsZoneGroups" -ApiVersion $script:ApiNet
        foreach ($zg in (ConvertTo-Array $zgs.value)) {
            foreach ($cfg in (ConvertTo-Array $zg.properties.privateDnsZoneConfigs)) {
                if ($cfg.privateDnsZoneId -and -not $wiredZoneIds.Contains($cfg.privateDnsZoneId)) {
                    $wiredZoneIds.Add($cfg.privateDnsZoneId) | Out-Null
                }
            }
        }
    }

    # ---- narrow the required zones to the sub-resources actually linked ----
    $groupIds = $groupIds | Where-Object { $_ } | Sort-Object -Unique
    $effectiveZones = @()
    foreach ($g in $groupIds) {
        $k = $g.ToLower()
        if ($groupIdZone.ContainsKey($k)) { $effectiveZones += $groupIdZone[$k] }
    }
    $effectiveZones = $effectiveZones | Sort-Object -Unique
    if ($effectiveZones.Count -eq 0) {
        $effectiveZones = $Target.Zones
    } else {
        Add-Result $area 'Private endpoint sub-resources' 'INFO' "groupIds: $($groupIds -join ', ') -> zones required: $($effectiveZones -join ', ')"
    }

    # ---- locate every instance of each relevant zone name -----------------
    # The same privatelink zone name commonly exists many times across a tenant
    # (one per spoke, per dev subscription, abandoned landing zones). A client
    # only ever resolves through the instance linked to the VNet whose DNS it
    # uses, so only on-path instances get an A-record verdict. Every other
    # instance is a bystander: summarised once, never failed. Wired zones are
    # always included - a PE with no zone group still has its expected zones
    # searched, so the zone group alone never decides what gets checked.
    $instances = [ordered]@{}   # zoneName(lower) -> List[zoneId]
    function Add-ZoneInstance([string] $Name, [string] $Id) {
        $n = $Name.ToLower()
        if (-not $instances.Contains($n)) { $instances[$n] = New-Object System.Collections.Generic.List[string] }
        if ($Id -and -not ($instances[$n] | Where-Object { $_ -ieq $Id })) { $instances[$n].Add($Id) | Out-Null }
    }
    foreach ($zid in $wiredZoneIds) { Add-ZoneInstance -Name (($zid -split '/')[-1]) -Id $zid }
    foreach ($expected in $effectiveZones) {
        Add-ZoneInstance -Name $expected -Id $null
        foreach ($zf in (ConvertTo-Array (Find-PrivateDnsZone -ZoneName $expected))) { Add-ZoneInstance -Name $expected -Id $zf.id }
    }

    $allZoneIds = @($instances.Values | ForEach-Object { $_ } | Where-Object { $_ })
    $linkMap    = if ($allZoneIds.Count -gt 0) { Get-ZoneLinks -ZoneIds $allZoneIds } else { @{} }
    $peVNetArr  = @($peVNetIds)
    $bystanderReadCap = 25

    foreach ($zn in @($instances.Keys)) {
        $suffix = $zn -replace '^privatelink\.', ''
        $ids    = @($instances[$zn])

        if ($ids.Count -eq 0) {
            Add-Result $area "Zone: $suffix" 'WARN' "No private DNS zone named $zn is visible to you. Required only if that endpoint surface is in use, or the zone may live in a subscription you cannot read."
            continue
        }

        $checks = Get-RecordChecks -Suffix $suffix -FqdnIpMap $fqdnIpMap -Label $Target.Label -AllIps @($allExpectedIps)

        # ---- classify each instance: on path vs bystander -------------------
        $onPath = @(); $bystanders = @()
        foreach ($zid in $ids) {
            $links = $linkMap[$zid.ToLower()]
            $roles = Get-ZoneRoles -ZoneId $zid -Links $links -WiredZoneIds @($wiredZoneIds) -PeVNetIds $peVNetArr
            $z = [pscustomobject]@{
                Id    = $zid
                Sub   = Get-IdSegment $zid 'subscriptions'
                Rg    = Get-IdSegment $zid 'resourceGroups'
                Links = $links
                Roles = $roles
            }
            if ($roles.Count -gt 0) { $onPath += $z } else { $bystanders += $z }
        }
        $unreadable = @($bystanders | Where-Object { $null -eq $_.Links })
        $byNote = ''
        if ($bystanders.Count -gt 0) {
            $byNote = " $($bystanders.Count) other instance(s) of this zone are not on the resolution path and were not scored"
            if ($unreadable.Count -gt 0) { $byNote += " ($($unreadable.Count) with unreadable VNet links)" }
            $byNote += if ($ShowAllZones) { '.' } else { ' (use -ShowAllZones to list them).' }
        }

        if ($onPath.Count -gt 0) {
            $where = ($onPath | ForEach-Object { "rg $($_.Rg) [$($_.Roles -join ', ')]" }) -join '; '
            Add-Result $area "Zone: $suffix" 'PASS' "On resolution path: $where.$byNote"

            $multi   = $onPath.Count -gt 1
            $answers = @{}   # label -> list of IP-set strings seen across on-path instances
            foreach ($z in $onPath) {
                $tag = if ($multi) { " [$($z.Rg)]" } else { '' }
                $why = "rg $($z.Rg), sub $($z.Sub) ($($z.Roles -join ', '))"
                $st  = Get-ZoneARecordState -ZoneId $z.Id -Checks $checks

                if ($null -eq $st) {
                    Add-Result $area "A records: $suffix$tag" 'WARN' "Zone record sets not readable from this context (cross-subscription or missing Private DNS Zone Reader). Zone: $why."
                } elseif ($checks.Count -eq 0) {
                    Add-Result $area "A records: $suffix$tag" 'INFO' "$($st.RecordCount) A record(s); no private endpoint IP available to compare against. Zone: $why."
                } else {
                    foreach ($it in $st.Items) {
                        $chk = "A record: $($it.Label).$suffix$tag"
                        switch ($it.State) {
                            'ok' {
                                Add-Result $area $chk 'PASS' "$($it.Label) -> $($it.Ips -join ',') (matches private endpoint NIC). Zone: $why."
                            }
                            'missing' {
                                $present = if ($st.Present) { $st.Present } else { '(none)' }
                                Add-Result $area $chk 'FAIL' "No A record named '$($it.Label)' in the on-path $zn ($why). Clients resolving through this zone fall through to the public CNAME. Records present: $present."
                            }
                            'wrong' {
                                Add-Result $area $chk 'FAIL' "$($it.Label) -> $($it.Ips -join ',') but the private endpoint NIC is $($it.Want -join ','). Stale/incorrect record in the on-path zone ($why) - traffic is sent to the wrong address."
                            }
                        }
                        if ($it.Ips.Count -gt 0) {
                            if (-not $answers.ContainsKey($it.Label)) { $answers[$it.Label] = New-Object System.Collections.Generic.List[string] }
                            $answers[$it.Label].Add("$(($it.Ips | Sort-Object) -join ',') (rg $($z.Rg))") | Out-Null
                        }
                    }
                }
                Test-ZoneVNetLinks -ZoneName $zn -Area $area -Links $z.Links -PeVNetIds $peVNetArr -Tag $tag
            }

            # Two on-path instances giving different answers means clients get a
            # different address depending on which VNet's DNS they use.
            foreach ($kv in $answers.GetEnumerator()) {
                $ipSets = @($kv.Value | ForEach-Object { ($_ -split ' \(rg ')[0] } | Sort-Object -Unique)
                if ($ipSets.Count -gt 1) {
                    Add-Result $area "Split-brain: $($kv.Key).$suffix" 'WARN' "On-path zone instances disagree: $($kv.Value -join ' vs '). Which address a client gets depends on which VNet's DNS it uses."
                }
            }
        } else {
            # Nothing wired to the PE and nothing linked to a VNet we know about.
            # Before calling it, find out whether a correct record exists anywhere.
            $holders = New-Object System.Collections.Generic.List[string]
            $scanned = 0
            if ($checks.Count -gt 0) {
                foreach ($z in $bystanders) {
                    if ($scanned -ge $bystanderReadCap) { break }
                    $scanned++
                    $st = Get-ZoneARecordState -ZoneId $z.Id -Checks $checks
                    if ($null -eq $st) { continue }
                    foreach ($it in ($st.Items | Where-Object { $_.State -eq 'ok' })) {
                        $holders.Add("$($it.Label) in rg $($z.Rg) (sub $($z.Sub), linked to: $(Get-ZoneLinkNames $z.Links))") | Out-Null
                    }
                }
            }
            $capNote = if ($bystanders.Count -gt $scanned -and $checks.Count -gt 0) { " Only the first $scanned of $($bystanders.Count) instances were searched for the record." } else { '' }
            $anchor  = 'but none is wired to this private endpoint or linked to the injected VNet, the -HubVNetId, or the private endpoint''s VNet'

            if ($holders.Count -gt 0) {
                Add-Result $area "Zone: $suffix" 'WARN' "$($bystanders.Count) instance(s) of $zn visible $anchor - so the resolution path cannot be confirmed. A correct record exists in: $($holders -join '; '). If that zone is linked to your DNS hub, re-run with -HubVNetId to score it.$capNote"
            } elseif ($checks.Count -gt 0) {
                $labels = ($checks | ForEach-Object { $_.Label }) -join ', '
                Add-Result $area "Zone: $suffix" 'FAIL' "$($bystanders.Count) instance(s) of $zn visible $anchor, and none hold a correct record for '$labels'. Clients will fall through to the public endpoint unless a zone you cannot read serves it.$capNote"
            } else {
                Add-Result $area "Zone: $suffix" 'WARN' "$($bystanders.Count) instance(s) of $zn visible $anchor. No private endpoint IP available to compare records against."
            }
        }

        if ($ShowAllZones) {
            foreach ($z in $bystanders) {
                Add-Result $area "Bystander zone: $suffix [$($z.Rg)]" 'INFO' "sub $($z.Sub); linked to: $(Get-ZoneLinkNames $z.Links). Not on this deployment's resolution path - not scored."
            }
        }
    }
}

foreach ($t in $targets) {
    Write-Host ''
    Write-Host "    --- $(if ($t.Area) { $t.Area } else { $t.Name }) ---" -ForegroundColor Cyan
    Test-ResourcePrivateLink -Target $t
}

#endregion

#region ------------------------------------------- 6. injected subnet health

Write-Phase '6. Injected subnet health'

if ($topology -ne 'delegated-subnet') {
    Add-Result 'Subnet' 'Subnet checks' 'SKIP' "Topology is '$topology' - no customer delegated subnet to inspect."
} else {
    $subnet = Invoke-Arm -Id $injectedSubnetId -ApiVersion $script:ApiNet
    if (-not $subnet) {
        Add-Result 'Subnet' 'Read subnet' 'FAIL' "Cannot read $injectedSubnetId - it may have been deleted or lives in another subscription."
    } else {
        $sp = $subnet.properties

        $delegations = ConvertTo-Array $sp.delegations
        $delNames = $delegations | ForEach-Object { $_.properties.serviceName }
        if ($delNames -contains 'Microsoft.App/environments') {
            Add-Result 'Subnet' 'Delegation' 'PASS' 'Microsoft.App/environments'
        } elseif ($delNames.Count -eq 0) {
            Add-Result 'Subnet' 'Delegation' 'FAIL' 'Subnet has no delegation. Foundry agent injection requires delegation to Microsoft.App/environments.'
        } else {
            Add-Result 'Subnet' 'Delegation' 'FAIL' "Delegated to '$($delNames -join ',')' instead of Microsoft.App/environments."
        }

        $prefixes = @()
        if ($sp.addressPrefix) { $prefixes += $sp.addressPrefix }
        $prefixes += (ConvertTo-Array $sp.addressPrefixes)
        $sizes = $prefixes | ForEach-Object { Get-PrefixSize $_ } | Where-Object { $_ }
        $smallest = ($sizes | Measure-Object -Maximum).Maximum
        if ($null -eq $smallest) {
            Add-Result 'Subnet' 'Address space' 'WARN' 'Could not determine prefix size.'
        } elseif ($smallest -le 27) {
            Add-Result 'Subnet' 'Address space' 'PASS' "$($prefixes -join ',') (/$smallest meets the /27 minimum)."
        } else {
            Add-Result 'Subnet' 'Address space' 'FAIL' "$($prefixes -join ',') is /$smallest. Injection requires /27 or larger; the deployment will fail or be unable to scale."
        }

        if ($sp.networkSecurityGroup) {
            $nsgId = $sp.networkSecurityGroup.id
            $nsg = Invoke-Arm -Id $nsgId -ApiVersion $script:ApiNet
            $rules = ConvertTo-Array $nsg.properties.securityRules
            $denyOut = $rules | Where-Object { $_.properties.access -eq 'Deny' -and $_.properties.direction -eq 'Outbound' }
            $denyIn  = $rules | Where-Object { $_.properties.access -eq 'Deny' -and $_.properties.direction -eq 'Inbound' }
            Add-Result 'Subnet' 'NSG attached' 'INFO' "$(($nsgId -split '/')[-1]) - $($rules.Count) custom rule(s)"
            if ($denyOut) {
                Add-Result 'Subnet' 'NSG outbound denies' 'WARN' "Deny rules present: $(($denyOut | ForEach-Object { "$($_.name)[p$($_.properties.priority)] $($_.properties.destinationAddressPrefix):$($_.properties.destinationPortRange)" }) -join '; '). Confirm 443 to AzureCloud, Storage, and your dependency PE IPs is still permitted."
            }
            if ($denyIn) {
                Add-Result 'Subnet' 'NSG inbound denies' 'INFO' (($denyIn | ForEach-Object { "$($_.name)[p$($_.properties.priority)]" }) -join '; ')
            }
        } else {
            Add-Result 'Subnet' 'NSG attached' 'INFO' 'No NSG on the injected subnet.'
        }

        if ($sp.routeTable) {
            $rtId = $sp.routeTable.id
            $rt = Invoke-Arm -Id $rtId -ApiVersion $script:ApiNet
            $routes = ConvertTo-Array $rt.properties.routes
            $default = $routes | Where-Object { $_.properties.addressPrefix -eq '0.0.0.0/0' }
            if ($default) {
                $nh = ($default | ForEach-Object { "$($_.properties.nextHopType) $($_.properties.nextHopIpAddress)" }) -join '; '
                Add-Result 'Subnet' 'UDR default route' 'WARN' "0.0.0.0/0 -> $nh. Forced tunneling: if the appliance cannot reach Azure control-plane endpoints or drops return traffic, Foundry will time out even with perfect DNS."
            } else {
                Add-Result 'Subnet' 'UDR' 'INFO' "$(($rtId -split '/')[-1]) - $($routes.Count) route(s), no default route override."
            }
        } else {
            Add-Result 'Subnet' 'UDR' 'PASS' 'No route table - system routing.'
        }

        $svcEps = ConvertTo-Array $sp.serviceEndpoints
        if ($svcEps.Count -gt 0) {
            Add-Result 'Subnet' 'Service endpoints' 'WARN' "$(($svcEps | ForEach-Object { $_.service }) -join ', ') enabled. Service endpoints take precedence over private endpoint routing for those services and will bypass your private path."
        }

        $ipCfgs = ConvertTo-Array $sp.ipConfigurations
        Add-Result 'Subnet' 'IP consumption' 'INFO' "$($ipCfgs.Count) IP configuration(s) in use."
    }

    # is the injected VNet peered to the hub, if a hub was supplied?
    if ($HubVNetId -and $injectedVNetId) {
        $peers = Invoke-Arm -Id "$injectedVNetId/virtualNetworkPeerings" -ApiVersion $script:ApiNet
        $peerList = ConvertTo-Array $peers.value
        $hit = $peerList | Where-Object { $_.properties.remoteVirtualNetwork.id -ieq $HubVNetId }
        if ($hit) {
            $st = $hit.properties.peeringState
            if ($st -eq 'Connected') {
                Add-Result 'Subnet' 'Peering to hub' 'PASS' "$($hit.name) is Connected."
            } else {
                Add-Result 'Subnet' 'Peering to hub' 'FAIL' "$($hit.name) state=$st. Hub-linked DNS zones will not resolve from the injected VNet."
            }
        } else {
            Add-Result 'Subnet' 'Peering to hub' 'FAIL' 'Injected VNet is not peered to the supplied hub VNet. Hub-linked private DNS zones cannot be used from here.'
        }
    }

    # DNS servers configured on the injected VNet
    if ($injectedVNetId) {
        $vnet = Invoke-Arm -Id $injectedVNetId -ApiVersion $script:ApiNet
        $dns = ConvertTo-Array $vnet.properties.dhcpOptions.dnsServers
        if ($dns.Count -eq 0) {
            Add-Result 'Subnet' 'VNet DNS servers' 'INFO' 'Azure-provided DNS (168.63.129.16). Private DNS zones must be linked directly to this VNet.'
        } else {
            Add-Result 'Subnet' 'VNet DNS servers' 'INFO' "Custom DNS: $($dns -join ', '). Zone links on this VNet are irrelevant unless these servers forward to 168.63.129.16 or a Private Resolver inbound endpoint."
        }
    }
}

#endregion

#region ------------------------------------------- 7. client-side data plane

Write-Phase '7. Client-side resolution and reachability (this machine)'

if ($SkipClientTests) {
    Add-Result 'Client' 'DNS/TCP tests' 'SKIP' '-SkipClientTests was specified.'
} else {
    # which resolver is this machine using
    $resolverAddrs = @()
    try {
        $svrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses.Count -gt 0 }
        $servers = $svrs | ForEach-Object { "$($_.InterfaceAlias)=$($_.ServerAddresses -join ',')" }
        $resolverAddrs = $svrs | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique
        Add-Result 'Client' 'Configured resolvers' 'INFO' ($servers -join ' | ')
    } catch {
        Add-Result 'Client' 'Configured resolvers' 'WARN' 'Could not enumerate DNS client settings.'
    }

    $publicResolvers = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '208.67.222.222')
    $usingPublicDns  = [bool]($resolverAddrs | Where-Object { $publicResolvers -contains $_ })

    # Build the FQDN test list, tagged by whether the endpoint is private-linkable.
    # Regional shared endpoints (speech, translator, regional api.cognitive.*) are
    # multi-tenant and have no per-account private endpoint - they must never be
    # reported as private-connectivity failures.
    $subLabel  = if ($props.customSubDomainName) { $props.customSubDomainName } else { $AccountName }
    $testItems = New-Object System.Collections.Generic.List[object]

    foreach ($f in $fqdns) {
        $isAccount = $f -like "$subLabel.*"
        $testItems.Add([pscustomobject]@{ Fqdn = $f; Private = $isAccount; Source = $AccountName }) | Out-Null
    }
    foreach ($t in ($targets | Select-Object -Skip 1)) {
        $res = Invoke-Arm -Id $t.Id -ApiVersion ($typeApi[$t.Type] ?? $script:ApiCS)
        foreach ($pec in (ConvertTo-Array $res.properties.privateEndpointConnections)) {
            $peId = $pec.properties.privateEndpoint.id
            if (-not $peId) { continue }
            $pe = Invoke-Arm -Id $peId -ApiVersion $script:ApiNet
            foreach ($cfg in (ConvertTo-Array $pe.properties.customDnsConfigs)) {
                if ($cfg.fqdn -and -not ($testItems.Fqdn -contains $cfg.fqdn)) {
                    $testItems.Add([pscustomobject]@{ Fqdn = $cfg.fqdn; Private = $true; Source = $t.Name }) | Out-Null
                }
            }
        }
    }

    $privateItems = @($testItems | Where-Object { $_.Private })
    $sharedItems  = @($testItems | Where-Object { -not $_.Private })

    if ($sharedItems.Count -gt 0) {
        Add-Result 'Client' 'Regional shared endpoints' 'INFO' "Not private-linkable, excluded from pass/fail: $(($sharedItems.Fqdn) -join ', '). These are multi-tenant regional endpoints; they resolve publicly by design. If your workload calls them from a locked-down VNet, they need firewall/UDR allowances rather than a private endpoint."
    }
    if ($privateItems.Count -eq 0) {
        Add-Result 'Client' 'DNS/TCP tests' 'WARN' 'No private-linkable FQDNs resolved from the control plane to test.'
    }

    $privateResolveCount = 0
    $publicBlockedCount  = 0
    $indirectFqdns       = New-Object System.Collections.Generic.List[string]

    # Probe every endpoint concurrently, then report serially so live output
    # stays ordered and severity logic keeps access to script state.
    $probes = @(Test-EndpointReachability -Items $privateItems -Throttle 8)
    $probeMap = @{}
    foreach ($pr in $probes) { $probeMap[$pr.Fqdn] = $pr }

    foreach ($item in $privateItems) {
        $fqdn  = $item.Fqdn
        $probe = $probeMap[$fqdn]
        if (-not $probe) { continue }

        if ($probe.ResolveError) {
            Add-Result 'Client' "Resolve $fqdn" 'FAIL' "NXDOMAIN / no answer: $($probe.ResolveError). This machine cannot resolve the endpoint at all."
            continue
        }

        $addrs = @($probe.Addrs)
        if ($addrs.Count -eq 0) {
            Add-Result 'Client' "Resolve $fqdn" 'FAIL' 'CNAME resolved but no A record returned. The privatelink zone is not answering for this client.'
            continue
        }

        $priv = $addrs | Where-Object { Test-PrivateIPv4 $_ }
        $pub  = $addrs | Where-Object { -not (Test-PrivateIPv4 $_) }

        if ($priv -and -not $pub) {
            $privateResolveCount++
            $known = $priv | Where-Object { $script:KnownPeIps -contains $_ }
            if ($known) {
                Add-Result 'Client' "Resolve $fqdn" 'PASS' "PRIVATE (direct) -> $($known -join ', ') - matches a discovered private endpoint NIC."
            } elseif ($script:KnownPeIps.Count -gt 0) {
                # Private address space, but not one of this deployment's endpoint
                # NICs. Typical of a NetScaler/F5/proxy VIP, a DNS forwarder that
                # rewrites answers, or a stale record. Not provably wrong - traffic
                # may well be forwarded correctly - so this is a WARN plus a
                # certificate check below, not a failure.
                $indirectFqdns.Add($fqdn) | Out-Null
                Add-Result 'Client' "Resolve $fqdn" 'WARN' "PRIVATE (indirect) -> $($priv -join ', '). This is private address space but NOT one of this deployment's private endpoint NICs ($($script:KnownPeIps -join ', ')). Something in the path is answering on the service's behalf - an ADC/proxy VIP (NetScaler, F5), a DNS forwarder that rewrites answers, or a stale record. Check the TLS identity below to see whether it still reaches the right backend."
            } else {
                Add-Result 'Client' "Resolve $fqdn" 'PASS' "PRIVATE -> $($priv -join ', ')"
            }
        } elseif ($priv -and $pub) {
            $privateResolveCount++
            Add-Result 'Client' "Resolve $fqdn" 'WARN' "SPLIT-BRAIN -> private $($priv -join ',') AND public $($pub -join ','). Some clients will take the public path."
        } else {
            # Severity is driven by the service's own config, not by this machine's
            # vantage point: if the service refuses public traffic, resolving to the
            # public frontend means the client provably cannot reach it.
            $blocked = $script:PublicDisabled[$item.Source] -eq $true
            $why = if ($usingPublicDns) {
                "This machine is using a public DNS resolver ($($resolverAddrs -join ', ')) and is off the private network."
            } else {
                "Resolver(s) $($resolverAddrs -join ', ') are not answering from the private DNS zone."
            }
            if ($blocked) {
                Add-Result 'Client' "Resolve $fqdn" 'FAIL' "PUBLIC ENDPOINT -> $($pub -join ', '). NOT reaching the private endpoint. $($item.Source) has publicNetworkAccess Disabled, so this address WILL refuse the connection - from this machine the service is unreachable. $why"
                $publicBlockedCount++
            } else {
                Add-Result 'Client' "Resolve $fqdn" 'WARN' "PUBLIC ENDPOINT -> $($pub -join ', '). NOT reaching the private endpoint; traffic from here egresses over the internet to the public frontend. $($item.Source) still allows public access, so calls may succeed while bypassing your private path entirely. $why"
            }
            # Still report who answered on the public path - it distinguishes
            # "reached Azure's public frontend" from "a proxy intercepted this".
            if ($probe.HttpIdValue) {
                Add-Result 'Client' "Service identity $fqdn" 'INFO' "Public path answered HTTP $($probe.HttpStatus) with $($probe.HttpIdHeader)=$($probe.HttpIdValue), i.e. the genuine Azure frontend - not an intercepting proxy. This says nothing about the private path."
            } elseif ($probe.HttpStatus) {
                Add-Result 'Client' "Service identity $fqdn" 'WARN' "Public path answered HTTP $($probe.HttpStatus) with no Azure per-request id header - something other than the real service replied (proxy, captive portal, or error page)."
            }
            continue
        }

        # --- TCP reachability (only meaningful once we have a private answer) ---
        if ($probe.Tcp) {
            Add-Result 'Client' "TCP 443 $fqdn" 'PASS' "$($probe.TcpTarget):443 open."
        } else {
            Add-Result 'Client' "TCP 443 $fqdn" 'FAIL' "$($probe.TcpTarget):443 unreachable. Check the NSG on the private endpoint subnet, UDR/firewall on the path, and that this machine is on-network (VPN/ExpressRoute)."
        }

        # --- TLS identity (through a proxy this is the real proof of backend) ---
        if ($probe.Tcp) {
            if ($probe.TlsIssuer) {
                $nameOk = Test-CertNameMatch -Fqdn $fqdn -SanText $probe.TlsSan -Subject $probe.TlsSubject
                $trusted = $probe.TlsIssuer -match 'Microsoft|DigiCert|Baltimore|Entrust'

                if ($nameOk -eq $false) {
                    Add-Result 'Client' "TLS identity $fqdn" 'FAIL' "The certificate presented does not cover $fqdn. Issuer: $($probe.TlsIssuer). Whatever answered on this address is NOT the intended service - a proxy or VIP is terminating the connection and forwarding to the wrong backend (or not forwarding at all)."
                } elseif ($nameOk -eq $true -and $trusted) {
                    Add-Result 'Client' "TLS identity $fqdn" 'PASS' "Certificate covers $fqdn and is issued by $($probe.TlsIssuer). Traffic is reaching the genuine service even if the address is a proxy VIP."
                } elseif ($nameOk -eq $true) {
                    Add-Result 'Client' "TLS identity $fqdn" 'WARN' "Certificate covers $fqdn but the issuer '$($probe.TlsIssuer)' is not a known Microsoft/public CA - a TLS-intercepting proxy is re-signing the connection. SDKs that pin or validate strictly will fail."
                } elseif (-not $trusted) {
                    Add-Result 'Client' "TLS identity $fqdn" 'WARN' "Issuer '$($probe.TlsIssuer)' is not a known Microsoft/public CA. A TLS-intercepting proxy is in the path and will break SDK calls that pin or validate strictly."
                } else {
                    Add-Result 'Client' "TLS identity $fqdn" 'INFO' "Issuer: $($probe.TlsIssuer)"
                }
                if ($Detailed -and $probe.TlsSan) { Add-Result 'Client' "TLS SAN $fqdn" 'INFO' $probe.TlsSan }
            } elseif ($probe.TlsError) {
                Add-Result 'Client' "TLS identity $fqdn" 'WARN' "TLS handshake failed: $($probe.TlsError)"
            }

            # --- service identity: did the REAL service answer? -------------
            # Scope note: this proves WHO answered, not whether network policy
            # allowed it. No credentials are sent, so a 401/403 cannot be
            # attributed to the network ACL rather than to missing auth.
            if ($probe.HttpStatus -or $probe.HttpError) {
                $svcName = $item.Source
                if ($probe.HttpIdValue) {
                    Add-Result 'Client' "Service identity $fqdn" 'PASS' "HTTP $($probe.HttpStatus) carrying $($probe.HttpIdHeader)=$($probe.HttpIdValue). Only the genuine Azure service stamps that header, so the request reached $svcName itself rather than being absorbed or answered by an intermediary. (401/403 is expected - the probe is unauthenticated.)"
                } elseif ($probe.HttpStatus) {
                    Add-Result 'Client' "Service identity $fqdn" 'WARN' "HTTP $($probe.HttpStatus) but the response carries none of the Azure per-request id headers (apim-request-id / x-ms-request-id / x-ms-activity-id / request-id). Something answered on the service's behalf - a proxy, captive portal, or error page - rather than the request reaching $svcName. Body: $($probe.HttpBody)"
                } else {
                    Add-Result 'Client' "Service identity $fqdn" 'WARN' "TLS succeeded but the HTTP probe failed: $($probe.HttpError). The listener is not behaving like $svcName."
                }
            }
        }
    }

    # A single address answering for many distinct services is the signature of a
    # shared VIP (ADC/proxy) rather than per-service private endpoints.
    $ipToFqdns = @{}
    foreach ($item in $privateItems) {
        $pr = $probeMap[$item.Fqdn]
        if (-not $pr) { continue }
        foreach ($a in @($pr.Addrs)) {
            if (-not $ipToFqdns.ContainsKey($a)) { $ipToFqdns[$a] = New-Object System.Collections.Generic.List[string] }
            $ipToFqdns[$a].Add($item.Fqdn) | Out-Null
        }
    }
    foreach ($kv in $ipToFqdns.GetEnumerator()) {
        if ($kv.Value.Count -gt 1 -and (Test-PrivateIPv4 $kv.Key) -and ($script:KnownPeIps -notcontains $kv.Key)) {
            Add-Result 'Client' 'Shared VIP detected' 'WARN' "$($kv.Value.Count) different service FQDNs all resolve to $($kv.Key): $($kv.Value -join ', '). Distinct private endpoints have distinct NIC addresses, so this is one appliance (NetScaler/F5/proxy) fronting them all. Client-side checks can only confirm the certificate identity per FQDN; which backend that appliance actually selects must be verified on the appliance itself."
        }
    }

    # Single, clear verdict on where this client sits relative to the private network.
    if ($privateItems.Count -gt 0) {
        if ($privateResolveCount -eq 0 -and $publicBlockedCount -gt 0) {
            Add-Result 'Client' 'Vantage point' 'FAIL' "NOT ON THE PRIVATE NETWORK, AND THE SERVICES REFUSE PUBLIC TRAFFIC. All $($privateItems.Count) endpoint(s) resolved to the PUBLIC frontend, and $publicBlockedCount of them belong to resources with publicNetworkAccess Disabled - so from this machine those services are unreachable, full stop. Resolver(s) in use: $($resolverAddrs -join ', '). This is expected if you are running from a laptop rather than the private network; the control-plane and DNS-zone findings above remain authoritative. To test the private path, re-run from a VM in the injected VNet or a host on VPN/ExpressRoute using the corporate resolver."
        } elseif ($privateResolveCount -eq 0 -and $usingPublicDns) {
            Add-Result 'Client' 'Vantage point' 'WARN' "NOT ON THE PRIVATE NETWORK. All $($privateItems.Count) endpoint(s) resolved to the PUBLIC frontend, not the private endpoint, because this machine uses a public DNS resolver ($($resolverAddrs -join ', ')). The client-side results above therefore prove nothing about the private path - the control-plane and DNS-zone findings are the authoritative ones. Re-run from a VM in the injected VNet, or a host on VPN/ExpressRoute using the corporate resolver."
        } elseif ($privateResolveCount -eq 0) {
            Add-Result 'Client' 'Vantage point' 'FAIL' "This machine uses resolver(s) $($resolverAddrs -join ', ') yet resolved 0 of $($privateItems.Count) private endpoints privately. If this host is meant to be on-network, the resolver is not forwarding to Azure DNS (168.63.129.16) or the Private Resolver inbound endpoint, or the zone is not linked to the VNet this host sits in."
        } elseif ($privateResolveCount -lt $privateItems.Count) {
            Add-Result 'Client' 'Vantage point' 'WARN' "$privateResolveCount of $($privateItems.Count) private endpoints resolved privately from this machine. Partial resolution usually means one zone is missing a VNet link or an A record."
        } else {
            Add-Result 'Client' 'Vantage point' 'PASS' "All $($privateItems.Count) private endpoints resolved to private addresses from this machine."
        }
    }
}

#endregion

#region ------------------------------------------------------- 8. verdict table

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor White
Write-Host '   VERDICT (consolidated)' -ForegroundColor White
Write-Host '  ============================================================' -ForegroundColor White
Write-Host ''

$maxDetail = if ($Detailed) { 4000 } else { 150 }

# Group in the order findings were produced, not alphabetically - the report
# should read top-down the way the sweep ran (Prereq, Context, Account, ...,
# then each service), instead of putting "AI Search" above "Foundry".
$areaOrder = New-Object System.Collections.Generic.List[string]
foreach ($r in $script:Results) {
    if (-not $areaOrder.Contains($r.Area)) { $areaOrder.Add($r.Area) | Out-Null }
}

foreach ($areaName in $areaOrder) {
    Write-Host ("  {0}" -f $areaName) -ForegroundColor White
    foreach ($r in ($script:Results | Where-Object { $_.Area -eq $areaName })) {
        Write-ResultLine -Row $r -MaxDetail $maxDetail
    }
    Write-Host ''
}

# Deployment scope decides the verdict and the exit code. Client-side results
# describe the machine this ran from - a laptop off the private network cannot
# make a correctly configured deployment "failed".
$depResults = @($script:Results | Where-Object { $_.Scope -eq 'Deployment' })
$cliResults = @($script:Results | Where-Object { $_.Scope -eq 'Client' })

$fails = @($depResults | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($depResults | Where-Object { $_.Status -eq 'WARN' })
$notes = @($depResults | Where-Object { $_.Status -eq 'PASS-NOTE' })
$passes = @($depResults | Where-Object { $_.Status -eq 'PASS' })

$cliFails = @($cliResults | Where-Object { $_.Status -eq 'FAIL' })
$cliWarns = @($cliResults | Where-Object { $_.Status -eq 'WARN' })

$deployVerdict = if ($fails.Count -gt 0) { 'FAIL' } elseif ($warns.Count -gt 0) { 'WARN' } else { 'PASS' }
$verdictColor  = @{ 'PASS' = 'Green'; 'WARN' = 'Yellow'; 'FAIL' = 'Red' }[$deployVerdict]

Write-Host '  ------------------------------------------------------------' -ForegroundColor White
Write-Host '   DEPLOYMENT CONFIGURATION' -ForegroundColor White -NoNewline
Write-Host "   $deployVerdict" -ForegroundColor $verdictColor
Write-Host ("   {0} FAIL   {1} WARN   {2} PASS-NOTE   {3} PASS" -f `
    $fails.Count, $warns.Count, $notes.Count, $passes.Count) -ForegroundColor DarkGray

if ($cliResults.Count -gt 0) {
    $cliSummary = if ($cliFails.Count -gt 0 -or $cliWarns.Count -gt 0) {
        "$($cliFails.Count) FAIL   $($cliWarns.Count) WARN   (reflects THIS machine's network position, not the deployment)"
    } else {
        'no issues from this machine'
    }
    $cliColor = if ($cliFails.Count -gt 0) { 'Red' } elseif ($cliWarns.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host '   CLIENT CONNECTIVITY (this host)' -ForegroundColor White
    Write-Host "   $cliSummary" -ForegroundColor $cliColor
}
Write-Host '  ------------------------------------------------------------' -ForegroundColor White

if ($fails.Count -gt 0) {
    Write-Host ''
    Write-Host '   Fix these first (deployment):' -ForegroundColor Red
    foreach ($f in $fails) {
        Write-Host "    * [$($f.Area)] $($f.Check)" -ForegroundColor Red
        Write-Host "        $($f.Detail)" -ForegroundColor DarkGray
    }
}

if ($cliFails.Count -gt 0) {
    Write-Host ''
    if ($deployVerdict -eq 'PASS') {
        Write-Host '   The deployment configuration is healthy. The failures below are about THIS' -ForegroundColor Yellow
        Write-Host '   machine reaching it, not about the deployment being wrong:' -ForegroundColor Yellow
    } else {
        Write-Host '   Client-side (depends on where this ran from):' -ForegroundColor Yellow
    }
    foreach ($f in $cliFails) {
        Write-Host "    * $($f.Check)" -ForegroundColor Yellow
    }
    Write-Host '    Re-run from a host inside the private network to validate the data path.' -ForegroundColor DarkGray
}
Write-Host ''

#endregion

#region ------------------------------------------------------- 9. HTML export

function Export-HtmlReport {
    param([Parameter(Mandatory)][string] $Path)

    $enc = {
        param($s)
        if ($null -eq $s) { return '' }
        [System.Net.WebUtility]::HtmlEncode([string]$s)
    }

    $passCount = $passes.Count
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $overall   = $deployVerdict

    # Build the client banner separately - nesting $() inside a here-string
    # subexpression is fragile and hard to read.
    $clientBanner = ''
    if ($cliFails.Count -gt 0 -or $cliWarns.Count -gt 0) {
        $clientBanner = "<div class=""banner b-WARN"">Client connectivity from $(& $enc $env:COMPUTERNAME): $($cliFails.Count) fail, $($cliWarns.Count) warn &mdash; this reflects where the script ran, not whether the deployment is correct.</div>"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Foundry private connectivity - $(& $enc $AccountName)</title>
<style>
 :root{--bg:#0f1117;--card:#171a21;--line:#272b34;--txt:#e6e6e6;--mut:#9aa0aa;
       --pass:#3fb950;--note:#2ea043;--warn:#d29922;--fail:#f85149;--info:#8b949e;--skip:#6e7681;}
 @media(prefers-color-scheme:light){
  :root{--bg:#f6f8fa;--card:#fff;--line:#d8dee4;--txt:#1f2328;--mut:#59636e;--info:#59636e;--skip:#8c959f;}}
 *{box-sizing:border-box}
 body{margin:0;padding:32px;background:var(--bg);color:var(--txt);
      font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:28px 0 10px;color:var(--txt)}
 .sub{color:var(--mut);font-size:13px;margin-bottom:20px}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 26px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 18px;min-width:96px}
 .card .n{font-size:22px;font-weight:600} .card .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
 .banner{border-radius:8px;padding:12px 16px;margin-bottom:22px;font-weight:600;border:1px solid}
 .b-PASS{background:rgba(63,185,80,.12);border-color:var(--pass);color:var(--pass)}
 .b-WARN{background:rgba(210,153,34,.12);border-color:var(--warn);color:var(--warn)}
 .b-FAIL{background:rgba(248,81,73,.12);border-color:var(--fail);color:var(--fail)}
 table{width:100%;border-collapse:collapse;background:var(--card);
       border:1px solid var(--line);border-radius:8px;overflow:hidden}
 th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
    color:var(--mut);padding:9px 12px;border-bottom:1px solid var(--line);font-weight:600}
 td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
 tr:last-child td{border-bottom:none}
 .s{font-weight:700;font-size:11px;letter-spacing:.04em;white-space:nowrap}
 .s-PASS{color:var(--pass)} .s-PASSNOTE{color:var(--note)} .s-WARN{color:var(--warn)}
 .s-FAIL{color:var(--fail)} .s-INFO{color:var(--info)} .s-SKIP{color:var(--skip)}
 td.chk{white-space:nowrap;font-weight:500} td.det{color:var(--mut)}
 .fixlist{background:var(--card);border:1px solid var(--fail);border-radius:8px;padding:14px 18px;margin-bottom:26px}
 .fixlist li{margin-bottom:10px} .fixlist .d{color:var(--mut);font-size:13px}
 footer{color:var(--mut);font-size:12px;margin-top:32px;border-top:1px solid var(--line);padding-top:14px}
 code{background:rgba(127,127,127,.14);padding:1px 5px;border-radius:4px;font-size:12px}
</style></head><body>
<h1>Microsoft Foundry &mdash; private connectivity diagnostics</h1>
<div class="sub">
  <strong>$(& $enc $AccountName)</strong> in <code>$(& $enc $ResourceGroup)</code>
  &middot; subscription <code>$(& $enc $SubscriptionId)</code>
  &middot; generated $generated
</div>
<div class="banner b-$overall">Deployment configuration: $overall</div>
$clientBanner
<div class="cards">
  <div class="card"><div class="n s-FAIL">$($fails.Count)</div><div class="l">Fail</div></div>
  <div class="card"><div class="n s-WARN">$($warns.Count)</div><div class="l">Warn</div></div>
  <div class="card"><div class="n s-PASSNOTE">$($notes.Count)</div><div class="l">Pass-note</div></div>
  <div class="card"><div class="n s-PASS">$passCount</div><div class="l">Pass</div></div>
</div>
<div class="sub">Counts above cover the deployment configuration. Client-side checks are listed separately below.</div>
"@)

    if ($fails.Count -gt 0) {
        [void]$sb.Append('<h2>Fix these first (deployment)</h2><div class="fixlist"><ol>')
        foreach ($f in $fails) {
            [void]$sb.Append("<li><strong>[$(& $enc $f.Area)] $(& $enc $f.Check)</strong><div class='d'>$(& $enc $f.Detail)</div></li>")
        }
        [void]$sb.Append('</ol></div>')
    }

    if ($cliFails.Count -gt 0) {
        $lead = if ($deployVerdict -eq 'PASS') {
            'The deployment configuration is healthy. These relate to this machine reaching it, not to the deployment being wrong. Re-run from a host inside the private network to validate the data path.'
        } else {
            'Client-side observations. These depend on where the script ran from.'
        }
        [void]$sb.Append("<h2>Client connectivity from this host</h2><div class='fixlist' style='border-color:var(--warn)'><p class='d'>$(& $enc $lead)</p><ol>")
        foreach ($f in $cliFails) {
            [void]$sb.Append("<li><strong>$(& $enc $f.Check)</strong><div class='d'>$(& $enc $f.Detail)</div></li>")
        }
        [void]$sb.Append('</ol></div>')
    }

    # Preserve discovery order rather than sorting alphabetically.
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($r in $script:Results) { if (-not $order.Contains($r.Area)) { $order.Add($r.Area) | Out-Null } }

    foreach ($areaName in $order) {
        [void]$sb.Append("<h2>$(& $enc $areaName)</h2>")
        [void]$sb.Append('<table><thead><tr><th style="width:88px">Status</th><th style="width:280px">Check</th><th>Detail</th></tr></thead><tbody>')
        foreach ($r in ($script:Results | Where-Object { $_.Area -eq $areaName })) {
            $cls = 's-' + ($r.Status -replace '-', '')
            [void]$sb.Append("<tr><td class='s $cls'>$(& $enc $r.Status)</td><td class='chk'>$(& $enc $r.Check)</td><td class='det'>$(& $enc $r.Detail)</td></tr>")
        }
        [void]$sb.Append('</tbody></table>')
    }

    [void]$sb.Append(@"
<footer>
  Read-only diagnostic. Control-plane and DNS findings are authoritative from anywhere;
  client-side results reflect the host this ran on
  ($(& $enc $env:COMPUTERNAME)$(if ($SkipClientTests) { ', client tests skipped' })).
</footer></body></html>
"@)

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

# Non-interactive export when asked for explicitly; otherwise offer it, unless
# the host cannot prompt (CI, scheduled task, redirected stdin) - the script must
# never block waiting on input that will not arrive.
$defaultHtml = Join-Path (Get-Location) "FoundryConnectivity-$AccountName-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

if ($ExportHtml -or $HtmlPath) {
    $target = if ($HtmlPath) { $HtmlPath } else { $defaultHtml }
    if ($target -notmatch '\.html?$') { $target += '.html' }
    try {
        Export-HtmlReport -Path $target
        Write-Host "  Report written: $((Resolve-Path $target).Path)" -ForegroundColor Green
    } catch {
        Write-Host "  Could not write the report: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ''
} elseif (-not [System.Console]::IsInputRedirected) {
    $answer = $null
    try { $answer = Read-Host '  Export an HTML report? [y/N]' } catch { $answer = 'n' }
    if ($answer -match '^\s*(y|yes)\s*$') {
        $custom = Read-Host "  Path [$defaultHtml]"
        $target = if ([string]::IsNullOrWhiteSpace($custom)) { $defaultHtml } else { $custom.Trim() }
        if ($target -notmatch '\.html?$') { $target += '.html' }
        try {
            Export-HtmlReport -Path $target
            $full = (Resolve-Path $target).Path
            Write-Host "  Report written: $full" -ForegroundColor Green
            $open = Read-Host '  Open it now? [y/N]'
            if ($open -match '^\s*(y|yes)\s*$') { Start-Process $full }
        } catch {
            Write-Host "  Could not write the report: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ''
}

# Exit code reflects the DEPLOYMENT only. A correctly configured deployment
# should not report failure just because the operator ran the script from a
# laptop that is not on the private network.
if ($fails.Count -gt 0) { exit 1 } else { exit 0 }

#endregion
