@{
    RootModule        = 'M365BecAudit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '6f0d3c52-8a4e-4f3b-9d55-2b7f6c1e9a40'
    Author            = 'Saafir Hale'
    Copyright         = '(c) Saafir Hale. MIT License.'
    Description       = 'Read-only audit of a Microsoft 365 / Entra ID tenant for the weaknesses behind business email compromise. Runs live against Microsoft Graph and Exchange Online, or offline against recorded JSON snapshots.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Microsoft365', 'EntraID', 'Security', 'BEC', 'Audit', 'MicrosoftGraph', 'ExchangeOnline')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
