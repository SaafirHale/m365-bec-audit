function Get-M365BecAuditPermission {
    <#
    .SYNOPSIS
        Lists the data the audit reads and the permissions each dataset needs.
    .DESCRIPTION
        Without -Detailed, returns the unique Microsoft Graph delegated scopes the
        audit requests (all read-only). With -Detailed, returns one row per
        dataset: source, request, the least-privileged permission Microsoft
        documents for it, and the scope this tool requests to cover it.
    .EXAMPLE
        Get-M365BecAuditPermission
    .EXAMPLE
        Get-M365BecAuditPermission -Detailed | Format-Table
    #>
    [CmdletBinding()]
    param([switch] $Detailed)

    $catalog = Get-AuditDatasetCatalog
    if ($Detailed) {
        return $catalog | ForEach-Object {
            [pscustomobject]@{
                Dataset         = $_.Name
                Source          = $_.Source
                Request         = $_.Request
                LeastPrivileged = $_.LeastPrivileged
                Requested       = $_.Permission
            }
        }
    }
    $catalog | Where-Object { $_.Permission } |
        ForEach-Object { $_.Permission -split ',\s*' } |
        Sort-Object -Unique
}
