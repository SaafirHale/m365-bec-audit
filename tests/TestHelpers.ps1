# Dot-sourced by every test file from BeforeAll.

$script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent
$script:FixtureRoot = Join-Path -Path $script:RepoRoot -ChildPath 'fixtures'
Import-Module (Join-Path -Path $script:RepoRoot -ChildPath 'src\M365BecAudit\M365BecAudit.psd1') -Force

function Get-TestSnapshot {
    # A fresh snapshot per call, so tests can mutate it freely.
    param([ValidateSet('weak', 'hardened', 'basic')] [string] $Tenant)
    Get-M365BecAuditSnapshot -FixturePath (Join-Path -Path $script:FixtureRoot -ChildPath "contoso-$Tenant")
}

function Invoke-TestCheck {
    param($Snapshot, [string] $Id, [hashtable] $Option)
    Invoke-M365BecAuditAnalysis -Snapshot $Snapshot -CheckId $Id -Option $Option
}

function Remove-TestDataset {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Edits an in-memory test snapshot.')]
    param($Snapshot, [string] $Name, [string] $Reason = 'Removed by test.')
    $Snapshot.Datasets.Remove($Name)
    $Snapshot.Errors[$Name] = $Reason
}

function New-TestPolicy {
    # A minimal Conditional Access policy in Graph's shape.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory test object.')]
    param(
        [string] $Name = 'Test policy',
        [string] $State = 'enabled',
        [string[]] $ClientApps = @('all'),
        [string[]] $IncludeUsers = @('All'),
        [string[]] $ExcludeUsers = @(),
        [string[]] $ExcludeGroups = @(),
        [string[]] $IncludeRoles = @(),
        [string[]] $Controls = @('mfa'),
        [string[]] $SignInRisk = @(),
        [string[]] $UserRisk = @(),
        [string] $AuthStrengthId
    )
    $json = @{
        id            = [guid]::NewGuid().ToString()
        displayName   = $Name
        state         = $State
        conditions    = @{
            clientAppTypes   = $ClientApps
            applications     = @{ includeApplications = @('All'); excludeApplications = @() }
            users            = @{ includeUsers = $IncludeUsers; excludeUsers = $ExcludeUsers; includeGroups = @(); excludeGroups = $ExcludeGroups; includeRoles = $IncludeRoles; excludeRoles = @() }
            signInRiskLevels = $SignInRisk
            userRiskLevels   = $UserRisk
            platforms        = $null
            locations        = $null
        }
        grantControls = @{
            operator               = 'OR'
            builtInControls        = $Controls
            authenticationStrength = if ($AuthStrengthId) { @{ id = $AuthStrengthId; displayName = 'strength' } } else { $null }
        }
    } | ConvertTo-Json -Depth 10
    $json | ConvertFrom-Json
}
