[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables between BeforeAll and It blocks.')]
param()

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'BEC-APP-01 Apps with high-risk permissions' {
    BeforeAll {
        $weak = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-APP-01'
    }

    It 'fails as Critical when a third-party app holds full_access_as_app' {
        $weak.Status | Should -Be 'Fail'
        $weak.Severity | Should -Be 'Critical'
        $row = $weak.Evidence | Where-Object Application -EQ 'Invoice Automation Connector'
        $row.Grant | Should -Be 'Application'
        $row.Permissions | Should -Be 'full_access_as_app, Mail.ReadWrite'
        $row.Risk | Should -Be 'Critical'
        $row.Publisher | Should -Be 'unverified'
    }

    It 'aggregates user-consented delegated grants per app' {
        $row = $weak.Evidence | Where-Object Application -EQ 'MailSync Pro'
        $row.Grant | Should -Be 'Delegated (user consent, 2 user(s))'
        $row.Permissions | Should -Be 'Mail.Read, Mail.Send'
        $row.Risk | Should -Be 'High'
        $row.Publisher | Should -Be 'MailSync Labs (unverified)'
    }

    It 'ignores Microsoft first-party apps and low-risk permissions' {
        $weak.Evidence.Application | Should -Not -Contain 'Graph Explorer'
        $weak.Evidence.Application | Should -Not -Contain 'HR Directory Sync'
    }

    It 'caps delegated grants at High because they act as the consenting user' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['oauth2PermissionGrants'] = @([pscustomobject]@{
                id = 'g'; clientId = 'e1000000-0000-4000-8000-000000000012'; consentType = 'AllPrincipals'; principalId = $null
                resourceId = 'e1000000-0000-4000-8000-000000000001'; scope = 'Directory.ReadWrite.All'
            })
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-APP-01'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'High'
        $f.Evidence[0].Grant | Should -Be 'Delegated (admin consent, all users)'
        $f.Evidence[0].Publisher | Should -Be 'Example HR Software Inc. (verified)'
    }

    It 'passes when no third-party app holds a high-risk permission' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-APP-01'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match '4 service principals reviewed'
    }
}

Describe 'BEC-APP-02 User consent settings' {
    It 'fails when users can consent to any app' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-APP-02'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'admin consent workflow is off'
    }

    It 'passes when consent is limited to the low-impact built-in policy' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-APP-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match 'microsoft-user-default-low'
        $f.Summary | Should -Not -Match 'workflow is off'
    }

    It 'passes when user consent is disabled' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-APP-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match 'Users cannot consent'
    }

    It 'warns on a custom app consent policy' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['authorizationPolicy'].defaultUserRolePermissions.permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.contoso-custom')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-APP-02'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'contoso-custom'
    }
}
