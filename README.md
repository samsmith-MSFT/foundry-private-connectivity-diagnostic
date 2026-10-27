# Foundry Private Connectivity Diagnostic

A read-only PowerShell diagnostic for privately deployed **Microsoft Foundry** (Azure AI Foundry) accounts and their private dependencies (Storage, Cosmos DB, AI Search, Key Vault).

It checks both:

- **Network** – is the topology right (delegated subnet vs. managed network), is public network access disabled, are the private endpoints approved, do the private DNS A records match the endpoints' NIC IPs, which VNets are the zones linked to, and is the subnet healthy (NSG, UDR, service endpoints)? It also runs DNS and TCP tests from the machine you run it on.
- **Authorization** – does each project's managed identity have the role assignments it needs on each dependency? It also checks ABAC conditions, Cosmos DB data-plane RBAC, local-auth settings, and the caller's Foundry roles.

It never changes anything in Azure, and it never reads keys or secrets.

## Quick start

Requires PowerShell 7+ and the Azure CLI. The caller needs **Reader** on the relevant scopes.

```powershell
.\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry

# With a hub VNet (recommended when private DNS is centralized)
.\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
    -HubVNetId "/subscriptions/<sub>/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub"

# Control-plane only, HTML report
.\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai -AccountName my-foundry `
    -SkipClientTests -HtmlPath .\foundry-report.html
```

| Parameter | Purpose |
|---|---|
| `-ResourceGroup`, `-AccountName` | The Foundry account to check (required) |
| `-SubscriptionId` | Defaults to the current `az` subscription |
| `-HubVNetId` | Your DNS hub VNet. Zones linked to it count as being on the resolution path |
| `-SkipClientTests` | Skip the DNS and TCP tests from this machine |
| `-ShowAllZones` | List bystander private DNS zones (see below) |
| `-Detailed` | Show full detail text without truncation |
| `-ExportHtml` / `-HtmlPath` | Write a self-contained HTML report |

The exit code is `1` if any deployment-level check fails, otherwise `0`.

## Private DNS zone selection (v3)

The same `privatelink.*` zone name often exists many times across a tenant. A client only resolves through the zone linked to the VNet whose DNS it uses. The script therefore sorts every zone into one of two groups before checking it:

- **On path:** the private endpoint's DNS zone group points to it, or it is linked to the injected VNet, the `-HubVNetId` VNet, or the private endpoint's own VNet. These zones get A-record PASS/FAIL results.
- **Bystander:** same name, but not linked to any of those. These are not scored; they're counted in one line, and `-ShowAllZones` lists them.

If no zone is on the path, the script reports where a correct record does exist (WARN) or that none exists (FAIL). Two on-path zones that return different IPs are flagged as **split-brain**.

See [`Test-FoundryPrivateConnectivity-README.txt`](Test-FoundryPrivateConnectivity-README.txt) for full documentation, including least-privilege permissions, what each check means, and common findings.

## Disclaimer

This is a community sample. It is not an official Microsoft product and is not supported by Microsoft. Provided as-is under the [MIT License](LICENSE).
