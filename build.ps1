#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Pester suite, PSScriptAnalyzer, and renders the sample reports.
.EXAMPLE
    .\build.ps1                # Test + Analyze
.EXAMPLE
    .\build.ps1 -Task Report   # write sample reports for every fixture to .\out
#>
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Analyze', 'Report', 'All')]
    [string[]] $Task = @('Test', 'Analyze')
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if ($Task -contains 'All') { $Task = @('Test', 'Analyze', 'Report') }
$failed = $false

if ($Task -contains 'Test') {
    Import-Module Pester -MinimumVersion 5.5.0
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path -Path $root -ChildPath 'tests'
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path -Path $root -ChildPath 'out\test-results.xml'
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'out') -Force
    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') { $failed = $true }
}

if ($Task -contains 'Analyze') {
    Import-Module PSScriptAnalyzer
    $settings = Join-Path -Path $root -ChildPath 'PSScriptAnalyzerSettings.psd1'
    $issues = @(
        Invoke-ScriptAnalyzer -Path (Join-Path $root 'src') -Recurse -Settings $settings
        Invoke-ScriptAnalyzer -Path (Join-Path $root 'tests') -Recurse -Settings $settings
        Invoke-ScriptAnalyzer -Path (Join-Path $root 'build.ps1') -Settings $settings
    )
    if ($issues.Count) {
        $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Output
        $failed = $true
    }
    else {
        Write-Output 'PSScriptAnalyzer: no findings.'
    }
}

if ($Task -contains 'Report') {
    Import-Module (Join-Path -Path $root -ChildPath 'src\M365BecAudit\M365BecAudit.psd1') -Force
    foreach ($fixture in Get-ChildItem -Path (Join-Path $root 'fixtures') -Directory) {
        Invoke-M365BecAudit -FixturePath $fixture.FullName -OutputPath (Join-Path $root "out\$($fixture.Name)")
    }
}

if ($failed) { exit 1 }
