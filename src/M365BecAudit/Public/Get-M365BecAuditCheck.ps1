function Get-M365BecAuditCheck {
    <#
    .SYNOPSIS
        Lists the checks the audit runs.
    .EXAMPLE
        Get-M365BecAuditCheck | Format-Table Id, Severity, Title
    #>
    [CmdletBinding()]
    param([string[]] $Id)

    Get-AuditCheckDefinition | Where-Object { -not $Id -or $Id -contains $_.Id } | ForEach-Object {
        [pscustomobject]@{
            Id         = $_.Id
            Category   = $_.Category
            Severity   = $_.Severity
            Title      = $_.Title
            Requires   = $_.Requires
            References = @($_.References | ForEach-Object { $_.Url })
        }
    }
}
