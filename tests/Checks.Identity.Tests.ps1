BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'BEC-MFA-01 Users without MFA registered' {
    It 'fails on the weak tenant and lists only enabled members without MFA' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-MFA-01'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'High'
        @($f.Evidence.User) | Sort-Object | Should -Be @(
            'jordan.pike@contoso.example.com', 'sam.okafor@contoso.example.com', 'taylor.brooks@contoso.example.com')
        $f.Summary | Should -Match '^3 of 12 enabled member accounts'
    }

    It 'ignores disabled accounts and guests' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-MFA-01'
        $f.Evidence.User | Should -Not -Contain 'lee.marsh@contoso.example.com'
        $f.Evidence.User | Should -Not -Match '#EXT#'
    }

    It 'passes when every enabled member has a method registered' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-MFA-01'
        $f.Status | Should -Be 'Pass'
        @($f.Evidence).Count | Should -Be 0
    }

    It 'is not assessed when the registration report could not be collected' {
        $s = Get-TestSnapshot weak
        Remove-TestDataset -Snapshot $s -Name 'userRegistrationDetails' -Reason '403 Forbidden'
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-MFA-01'
        $f.Status | Should -Be 'NotAssessed'
        $f.Summary | Should -Match 'userRegistrationDetails \(403 Forbidden\)'
    }
}

Describe 'BEC-MFA-02 Admins without phishing-resistant MFA' {
    It 'fails as Critical when an admin has no MFA at all' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-MFA-02'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'Critical'
        ($f.Evidence | Where-Object Admin -EQ 'jordan.pike@contoso.example.com').Methods | Should -Be 'none'
    }

    It 'counts eligible (PIM) admins and excludes admins with FIDO2' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-MFA-02'
        $f.Evidence.Admin | Should -Contain 'emergency.admin@contoso.example.com'
        $f.Evidence.Admin | Should -Not -Contain 'casey.nguyen@contoso.example.com'
        @($f.Evidence).Count | Should -Be 6
    }

    It 'fails as High when every admin has some MFA but not phishing-resistant MFA' {
        $s = Get-TestSnapshot weak
        $jordan = $s.Datasets['userRegistrationDetails'] | Where-Object userPrincipalName -EQ 'jordan.pike@contoso.example.com'
        $jordan.isMfaRegistered = $true
        $jordan.methodsRegistered = @('microsoftAuthenticatorPush')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-MFA-02'
        $f.Status | Should -Be 'Fail'
        $f.Severity | Should -Be 'High'
    }

    It 'skips disabled admin accounts' {
        $s = Get-TestSnapshot weak
        ($s.Datasets['users'] | Where-Object userPrincipalName -EQ 'jordan.pike@contoso.example.com').accountEnabled = $false
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-MFA-02'
        $f.Evidence.Admin | Should -Not -Contain 'jordan.pike@contoso.example.com'
        $f.Severity | Should -Be 'High'
    }

    It 'passes when every admin has a phishing-resistant method and CA enforces it' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-MFA-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match 'CA003 Phishing-resistant MFA for admins'
        @($f.Evidence | Where-Object { -not $_.PhishingResistant }).Count | Should -Be 0
    }

    It 'warns when methods are registered but no policy enforces the strength' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['conditionalAccessPolicies'] = @($s.Datasets['conditionalAccessPolicies'] | Where-Object displayName -NotLike 'CA003*')
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-MFA-02'
        $f.Status | Should -Be 'Warn'
    }

    It 'recognises passkey and Windows Hello method names as phishing-resistant' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-MFA-02'
        ($f.Evidence | Where-Object Admin -EQ 'avery.stone@contoso.example.org').PhishingResistant | Should -BeTrue
        ($f.Evidence | Where-Object Admin -EQ 'dana.price@contoso.example.org').PhishingResistant | Should -BeTrue
    }
}

Describe 'BEC-GUEST-01 Stale guest accounts' {
    It 'flags inactive, never-used and unaccepted guests' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-GUEST-01'
        $f.Status | Should -Be 'Fail'
        @($f.Evidence.Guest) | Sort-Object | Should -Be @(
            'consultant@northwind.example.org', 'former.contractor@mail.example.net', 'vendor.rep@fabrikam.example.org')
        ($f.Evidence | Where-Object Guest -EQ 'vendor.rep@fabrikam.example.org').Reason | Should -Be 'no sign-in for 333 days'
        ($f.Evidence | Where-Object Guest -EQ 'consultant@northwind.example.org').Reason | Should -Match 'invitation not accepted for 92 days'
        ($f.Evidence | Where-Object Guest -EQ 'former.contractor@mail.example.net').Reason | Should -Match '^never signed in'
    }

    It 'does not flag a guest who signed in recently' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-GUEST-01'
        $f.Evidence.Guest | Should -Not -Contain 'auditor@tailspin.example.org'
    }

    It 'respects the StaleGuestDays threshold' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-GUEST-01' -Option @{ StaleGuestDays = 400 }
        $f.Evidence.Guest | Should -Not -Contain 'vendor.rep@fabrikam.example.org'
    }

    It 'ignores disabled guests' {
        $s = Get-TestSnapshot weak
        ($s.Datasets['users'] | Where-Object mail -EQ 'vendor.rep@fabrikam.example.org').accountEnabled = $false
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-GUEST-01'
        $f.Evidence.Guest | Should -Not -Contain 'vendor.rep@fabrikam.example.org'
    }

    It 'passes when guests are active and invitations are recent' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-GUEST-01').Status | Should -Be 'Pass'
    }

    It 'falls back to creation dates and says so when sign-in activity is unavailable' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-GUEST-01'
        $f.Status | Should -Be 'Fail'
        $f.Evidence[0].Reason | Should -Match 'sign-in data unavailable'
        $f.Summary | Should -Match 'Sign-in activity was not available'
    }
}
