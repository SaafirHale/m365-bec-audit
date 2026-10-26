function Invoke-M365BecAuditAnalysis {
    <#
    .SYNOPSIS
        Runs the checks against a snapshot and returns one finding per check.
    .DESCRIPTION
        Pure analysis: no network calls. Each finding has Id, Title, Category,
        Status (Pass, Fail, Warn, NotAssessed, Error), Severity, Summary,
        Evidence, Remediation and References (Microsoft documentation).
    .PARAMETER Option
        Overrides for thresholds: StaleGuestDays, PendingInvitationDays,
        MaxGlobalAdmins, MinGlobalAdmins, BreakGlassAccounts, BreakGlassPattern.
    .EXAMPLE
        Get-M365BecAuditSnapshot -FixturePath .\fixtures\contoso-weak | Invoke-M365BecAuditAnalysis
    .EXAMPLE
        Invoke-M365BecAuditAnalysis -Snapshot $s -CheckId BEC-EXO-02
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Snapshot,
        [string[]] $CheckId,
        [hashtable] $Option
    )

    process {
        $merged = Merge-AuditOption -Option $Option
        $definitions = @(Get-AuditCheckDefinition | Where-Object { -not $CheckId -or $CheckId -contains $_.Id })
        if ($CheckId -and -not $definitions.Count) { throw "Unknown check id: $($CheckId -join ', ')" }
        foreach ($definition in $definitions) {
            Invoke-AuditCheck -Definition $definition -Snapshot $Snapshot -Option $merged
        }
    }
}
