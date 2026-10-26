BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'BEC-ROLE-01 Standing Global Administrator count' {
    It 'fails with five permanent Global Administrators' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-ROLE-01'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match '^5 principals hold Global Administrator permanently'
        @($f.Evidence | Where-Object Assignment -EQ 'Eligible (PIM)').Principal | Should -Be 'emergency.admin@contoso.example.com'
    }

    It 'honours the MaxGlobalAdmins threshold' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-ROLE-01' -Option @{ MaxGlobalAdmins = 5 }).Status | Should -Be 'Pass'
    }

    It 'does not count PIM-activated assignments as standing' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-ROLE-01'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match '^2 standing Global Administrator\(s\), 3 active'
        ($f.Evidence | Where-Object Principal -EQ 'avery.stone@contoso.example.org' | Where-Object Assignment -NE 'Eligible (PIM)').Assignment | Should -Be 'Activated (PIM)'
        @($f.Evidence | Where-Object BreakGlass -EQ 'yes').Count | Should -Be 2
    }

    It 'warns when there is only one Global Administrator' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-ROLE-01'
        $f.Status | Should -Be 'Warn'
        $f.Severity | Should -Be 'Medium'
    }

    It 'treats every active assignment as standing when PIM data is unavailable' {
        $s = Get-TestSnapshot hardened
        Remove-TestDataset -Snapshot $s -Name 'roleAssignmentScheduleInstances'
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-ROLE-01'
        $f.Summary | Should -Match '^3 standing'
    }

    It 'notes group-based assignments' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['roleAssignments'] = @($s.Datasets['roleAssignments']) + ([pscustomobject]@{
                id = 'ra-group'; principalId = 'g1'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'
                principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Tier 0 Admins' }
            })
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-ROLE-01'
        $f.Summary | Should -Match 'assignment\(s\) are to groups'
        ($f.Evidence | Where-Object Principal -EQ 'Tier 0 Admins').Type | Should -Be 'group'
    }
}

Describe 'BEC-ROLE-02 Privileged roles held without PIM' {
    It 'fails on permanent privileged assignments' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-ROLE-02'
        $f.Status | Should -Be 'Fail'
        @($f.Evidence).Count | Should -Be 6
        ($f.Evidence | Where-Object Principal -EQ 'dana.price@contoso.example.com').Role | Should -Be 'Exchange Administrator'
    }

    It 'passes when only break-glass accounts hold Global Administrator permanently' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-ROLE-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match '2 eligible assignment'
    }

    It 'still flags a break-glass account holding another privileged role permanently' {
        $s = Get-TestSnapshot hardened
        $exchangeAdmin = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        $s.Datasets['roleAssignments'] = @($s.Datasets['roleAssignments']) + [pscustomobject]@{ id = 'x'; principalId = 'a1000000-0000-4000-8000-000000000001'; roleDefinitionId = $exchangeAdmin; directoryScopeId = '/'; principal = $null }
        $s.Datasets['roleAssignmentScheduleInstances'] = @($s.Datasets['roleAssignmentScheduleInstances']) + [pscustomobject]@{ principalId = 'a1000000-0000-4000-8000-000000000001'; roleDefinitionId = $exchangeAdmin; assignmentType = 'Assigned'; endDateTime = $null }
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-ROLE-02'
        $f.Status | Should -Be 'Fail'
        $f.Evidence[0].Principal | Should -Be 'bg.one@contosohardened.onmicrosoft.com'
    }

    It 'ignores assignments scoped to an administrative unit' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['roleAssignments'] = @($s.Datasets['roleAssignments']) + [pscustomobject]@{ id = 'au'; principalId = 'a1000000-0000-4000-8000-000000000005'; roleDefinitionId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; directoryScopeId = '/administrativeUnits/au1'; principal = $null }
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-ROLE-02').Status | Should -Be 'Pass'
    }

    It 'is not assessed without PIM data' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-ROLE-02'
        $f.Status | Should -Be 'NotAssessed'
        $f.Summary | Should -Match 'P2'
    }
}

Describe 'BEC-BG-01 Emergency access (break-glass) accounts' {
    It 'fails on a synced, eligible-only emergency account' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-BG-01'
        $f.Status | Should -Be 'Fail'
        $issues = @($f.Evidence.Issue)
        $issues | Should -Contain 'synchronised from on-premises AD; it should be cloud-only'
        ($issues | Where-Object { $_ -match 'Eligible \(PIM\) rather than permanently active' }) | Should -Not -BeNullOrEmpty
        ($issues | Where-Object { $_ -match '^only one emergency access account' }) | Should -Not -BeNullOrEmpty
        ($issues | Where-Object { $_ -match 'onmicrosoft' }) | Should -Not -BeNullOrEmpty
        ($issues | Where-Object { $_ -match 'no phishing-resistant method' }) | Should -Not -BeNullOrEmpty
    }

    It 'fails when no emergency account can be identified' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-BG-01'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'pass -BreakGlassAccount'
    }

    It 'passes for two well-configured accounts' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-BG-01').Status | Should -Be 'Pass'
    }

    It 'uses explicitly named accounts instead of the name pattern' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-BG-01' -Option @{ BreakGlassAccounts = @('BG.ONE@contosohardened.onmicrosoft.com') }
        $f.Status | Should -Be 'Warn'
        $f.Evidence[0].Issue | Should -Match '^only one emergency access account'
    }

    It 'reports a missing named account' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-BG-01' -Option @{ BreakGlassAccounts = @('nobody@contosohardened.onmicrosoft.com') }
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'nobody@contosohardened.onmicrosoft.com'
    }

    It 'fails when an enforced policy applies to the account without excluding it' {
        $s = Get-TestSnapshot hardened
        $p = $s.Datasets['conditionalAccessPolicies'] | Where-Object displayName -Like 'CA002*'
        $p.conditions.users.excludeUsers = @('a1000000-0000-4000-8000-000000000002')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-BG-01'
        $f.Status | Should -Be 'Fail'
        ($f.Evidence | Where-Object Account -EQ 'bg.one@contosohardened.onmicrosoft.com').Issue | Should -Match "CA002 Require MFA for all users"
    }

    It 'ignores report-only policies, which do not block sign-in' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies']) + (New-TestPolicy -Name 'Report only' -State 'enabledForReportingButNotEnforced')
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-BG-01').Status | Should -Be 'Pass'
    }

    It 'asks for confirmation when exclusion is by group' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies']) + (New-TestPolicy -Name 'Group excluded' -ExcludeGroups 'grp-emergency')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-BG-01'
        $f.Status | Should -Be 'Warn'
        ($f.Evidence | Where-Object Severity -EQ 'Low').Issue | Should -Match 'excludes groups'
    }
}
