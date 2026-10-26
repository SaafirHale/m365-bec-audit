[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables between BeforeAll and It blocks.')]
param()

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
    $legacyApps = @('exchangeActiveSync', 'other')
}

Describe 'BEC-CA-01 Legacy authentication not blocked' {
    It 'fails when the only block policy is disabled and security defaults are off' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-CA-01'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'disabled'
        $f.Evidence[0].Policy | Should -Be 'Block legacy authentication'
    }

    It 'fails when no policy targets legacy clients at all' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @()
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-01'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'No Conditional Access policy blocks legacy authentication'
    }

    It 'passes with an enforced all-users block policy' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-CA-01'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match 'CA001 Block legacy authentication'
    }

    It 'passes when security defaults are enabled' {
        $s = Get-TestSnapshot weak
        $s.Datasets['securityDefaults'].isEnabled = $true
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-01').Status | Should -Be 'Pass'
    }

    It 'warns when the block policy is report-only' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @(New-TestPolicy -State 'enabledForReportingButNotEnforced' -ClientApps $legacyApps -Controls 'block')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-01'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'report-only'
    }

    It 'warns when the block policy covers only some users' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @(New-TestPolicy -IncludeUsers 'a0000000-0000-4000-8000-000000000007' -ClientApps $legacyApps -Controls 'block')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-01'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'only for some users'
    }
}

Describe 'BEC-CA-02 Security defaults vs Conditional Access coverage' {
    It 'fails when only group-scoped and report-only MFA policies exist' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'High'
        $f.Summary | Should -Match 'No enabled policy requires MFA for all users'
    }

    It 'fails as Critical with neither security defaults nor any enabled policy' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies'] | Where-Object state -NE 'enabled')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'Critical'
    }

    It 'fails when the all-users MFA policy is report-only' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies']) + (New-TestPolicy -Name 'MFA all (report)' -State 'enabledForReportingButNotEnforced')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'report-only'
    }

    It 'does not treat a location-scoped MFA policy as baseline coverage' {
        $s = Get-TestSnapshot weak
        $p = New-TestPolicy -Name 'MFA off-network'
        $p.conditions.locations = [pscustomobject]@{ includeLocations = @('All'); excludeLocations = @('AllTrusted') }
        $s.Datasets['conditionalAccessPolicies'] = @($p)
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-02').Status | Should -Be 'Fail'
    }

    It 'passes with an enforced all-users MFA policy that excludes only break-glass accounts' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match 'CA002 Require MFA for all users'
    }

    It 'warns when the baseline policy excludes accounts other than break-glass' {
        $s = Get-TestSnapshot hardened
        $p = $s.Datasets['conditionalAccessPolicies'] | Where-Object displayName -Like 'CA002*'
        $p.conditions.users.excludeUsers = @($p.conditions.users.excludeUsers) + 'a1000000-0000-4000-8000-000000000005'
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match '1 user or group exclusion'
    }

    It 'passes with Info severity when security defaults are enabled' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-CA-02'
        $f.Status | Should -Be 'Pass'
        $f.Severity | Should -Be 'Info'
    }
}

Describe 'BEC-CA-03 Sign-in risk and user risk policies' {
    It 'fails when no policy uses risk conditions' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-CA-03').Status | Should -Be 'Fail'
    }

    It 'notes that security defaults do not replace risk policies' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-CA-03').Summary | Should -Match 'Security defaults are on'
    }

    It 'passes with enforced sign-in risk and user risk policies' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-CA-03'
        $f.Status | Should -Be 'Pass'
        @($f.Evidence).Count | Should -Be 2
    }

    It 'warns when only sign-in risk is covered' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies'] | Where-Object displayName -NotLike 'CA005*')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-03'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'user risk'
        $f.Summary | Should -Not -Match 'sign-in risk or'
    }

    It 'warns when risk policies are report-only' {
        $s = Get-TestSnapshot weak
        $s.Datasets['conditionalAccessPolicies'] = @(
            New-TestPolicy -State 'enabledForReportingButNotEnforced' -SignInRisk 'high'
            New-TestPolicy -State 'enabledForReportingButNotEnforced' -UserRisk 'high' -Controls 'mfa', 'passwordChange'
        )
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-03'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'sign-in risk or user risk'
    }
}
