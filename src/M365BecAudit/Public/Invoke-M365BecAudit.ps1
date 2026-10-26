function Invoke-M365BecAudit {
    <#
    .SYNOPSIS
        Collects, analyses and reports in one step.
    .DESCRIPTION
        Builds a snapshot (from a recorded fixture or the connected tenant), runs
        every check, prints a console summary, and writes m365-bec-audit.html and
        m365-bec-audit.json to -OutputPath.
    .EXAMPLE
        Invoke-M365BecAudit -FixturePath .\fixtures\contoso-weak -OutputPath .\out
    .EXAMPLE
        Connect-M365BecAudit
        Invoke-M365BecAudit -Live -BreakGlassAccount bg1@contoso.onmicrosoft.com -OutputPath .\out
    #>
    [CmdletBinding(DefaultParameterSetName = 'Fixture', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Fixture')] [string] $FixturePath,
        [Parameter(Mandatory, ParameterSetName = 'Live')] [switch] $Live,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipExchange,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipInboxRules,
        [Parameter(ParameterSetName = 'Live')] [string] $SaveSnapshotPath,
        [Parameter(Mandatory, ParameterSetName = 'Snapshot')] $Snapshot,
        [string] $OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'm365-bec-audit-output'),
        [string[]] $BreakGlassAccount,
        [ValidateRange(1, 3650)] [int] $StaleGuestDays = 90,
        [ValidateRange(1, 100)] [int] $MaxGlobalAdmins = 4,
        [switch] $NoReport,
        [switch] $Quiet,
        [switch] $PassThru
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Fixture' { $Snapshot = Get-M365BecAuditSnapshot -FixturePath $FixturePath }
        'Live' {
            $Snapshot = Get-M365BecAuditSnapshot -Live -SkipExchange:$SkipExchange -SkipInboxRules:$SkipInboxRules
            if ($SaveSnapshotPath) { $null = Save-M365BecAuditSnapshot -Snapshot $Snapshot -Path $SaveSnapshotPath }
        }
    }

    $option = @{ StaleGuestDays = $StaleGuestDays; MaxGlobalAdmins = $MaxGlobalAdmins }
    if ($BreakGlassAccount) { $option['BreakGlassAccounts'] = $BreakGlassAccount }
    $findings = @(Invoke-M365BecAuditAnalysis -Snapshot $Snapshot -Option $option)

    if (-not $Quiet) { Show-M365BecAuditSummary -Finding $findings -TenantName $Snapshot.Meta.tenantName }

    $report = $null
    if (-not $NoReport -and $PSCmdlet.ShouldProcess($OutputPath, 'Write HTML and JSON report')) {
        $report = Export-M365BecAuditReport -Finding $findings -Snapshot $Snapshot -OutputPath $OutputPath -Confirm:$false
        if (-not $Quiet) {
            Write-Information "HTML report: $($report.Html)" -InformationAction Continue
            Write-Information "JSON report: $($report.Json)" -InformationAction Continue
        }
    }

    if ($PassThru) {
        [pscustomobject]@{
            Snapshot = $Snapshot
            Findings = $findings
            Report   = $report
        }
    }
}
