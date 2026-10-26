function Connect-M365BecAudit {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph (read-only scopes) and Exchange Online.
    .DESCRIPTION
        Requests only the delegated scopes returned by Get-M365BecAuditPermission,
        all of which are read-only. The Graph session is scoped to this PowerShell
        process. Exchange Online has no scope model; the signed-in account's
        Exchange role decides what it can read, and the audit only calls Get-*
        cmdlets.
    .EXAMPLE
        Connect-M365BecAudit -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Connect-M365BecAudit -SkipExchange -UseDeviceCode
    #>
    [CmdletBinding()]
    param(
        [string] $TenantId,
        [switch] $SkipExchange,
        [switch] $UseDeviceCode
    )

    if (-not (Get-Command -Name 'Connect-MgGraph' -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    $scopes = @(Get-M365BecAuditPermission)
    $graphParams = @{ Scopes = $scopes; ContextScope = 'Process'; NoWelcome = $true }
    if ($TenantId) { $graphParams['TenantId'] = $TenantId }
    if ($UseDeviceCode) { $graphParams['UseDeviceCode'] = $true }
    Connect-MgGraph @graphParams

    $context = Get-MgContext
    $missing = @($scopes | Where-Object { @($context.Scopes) -notcontains $_ })
    if ($missing.Count) {
        Write-Warning "Signed in, but these scopes were not granted: $($missing -join ', '). Checks that depend on them will be reported as not assessed."
    }

    if (-not $SkipExchange) {
        if (-not (Get-Command -Name 'Connect-ExchangeOnline' -ErrorAction SilentlyContinue)) {
            throw 'ExchangeOnlineManagement is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser (or use -SkipExchange).'
        }
        $exoParams = @{ ShowBanner = $false }
        if ($context.Account) { $exoParams['UserPrincipalName'] = $context.Account }
        if ($UseDeviceCode) { $exoParams['Device'] = $true }
        Connect-ExchangeOnline @exoParams
    }

    [pscustomobject]@{
        Account       = $context.Account
        TenantId      = $context.TenantId
        GraphScopes   = @($context.Scopes)
        ExchangeOnline = -not $SkipExchange
    }
}
