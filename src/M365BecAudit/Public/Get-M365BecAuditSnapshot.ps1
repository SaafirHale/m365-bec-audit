function Get-M365BecAuditSnapshot {
    <#
    .SYNOPSIS
        Collects the tenant data the audit needs, live or from a recorded snapshot.
    .DESCRIPTION
        -FixturePath reads a snapshot directory (one <dataset>.json file per
        dataset, Graph-style {"value": [...]} for collections). -Live reads the
        connected tenant through Microsoft Graph GET requests and Exchange Online
        Get-* cmdlets. -Collector accepts any object that implements the collector
        contract described in Private/Collectors.ps1.

        Datasets that cannot be collected (missing licence, missing permission,
        skipped) are recorded in the snapshot's Errors table, and the checks that
        need them report NotAssessed.
    .EXAMPLE
        $snapshot = Get-M365BecAuditSnapshot -FixturePath .\fixtures\contoso-weak
    .EXAMPLE
        Connect-M365BecAudit; $snapshot = Get-M365BecAuditSnapshot -Live
    #>
    [CmdletBinding(DefaultParameterSetName = 'Fixture')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Fixture')] [string] $FixturePath,
        [Parameter(Mandatory, ParameterSetName = 'Live')] [switch] $Live,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipExchange,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipInboxRules,
        [Parameter(Mandatory, ParameterSetName = 'Collector')] $Collector
    )

    if ($PSCmdlet.ParameterSetName -eq 'Fixture') {
        $Collector = Get-AuditCollector -FixturePath $FixturePath
    }
    elseif ($Live) {
        if (-not (Get-Command -Name 'Get-MgContext' -ErrorAction SilentlyContinue) -or -not (Get-MgContext)) {
            throw 'Not connected to Microsoft Graph. Run Connect-M365BecAudit first.'
        }
        $Collector = Get-AuditCollector -Live -SkipExchange:$SkipExchange -SkipInboxRules:$SkipInboxRules
    }
    Get-TenantSnapshot -Collector $Collector
}
