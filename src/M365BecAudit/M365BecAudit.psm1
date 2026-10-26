#Requires -Version 5.1
# Module loader. Private files are dot-sourced in a fixed order so shared
# helpers exist before the checks that use them.

$privateFiles = @(
    'Private\Common.ps1'
    'Private\DatasetCatalog.ps1'
    'Private\Collectors.ps1'
    'Private\Checks\Identity.ps1'
    'Private\Checks\ConditionalAccess.ps1'
    'Private\Checks\Exchange.ps1'
    'Private\Checks\Applications.ps1'
    'Private\Checks\Roles.ps1'
    'Private\Checks\Guests.ps1'
    'Private\Checks\BreakGlass.ps1'
    'Private\CheckRegistry.ps1'
    'Private\Report.ps1'
)

foreach ($file in $privateFiles) {
    . (Join-Path -Path $PSScriptRoot -ChildPath $file)
}

foreach ($file in Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1') {
    . $file.FullName
}

Export-ModuleMember -Function @(
    'Connect-M365BecAudit'
    'Get-M365BecAuditCheck'
    'Get-M365BecAuditPermission'
    'Get-M365BecAuditSnapshot'
    'Save-M365BecAuditSnapshot'
    'Invoke-M365BecAuditAnalysis'
    'Invoke-M365BecAudit'
    'Export-M365BecAuditReport'
    'Show-M365BecAuditSummary'
)
