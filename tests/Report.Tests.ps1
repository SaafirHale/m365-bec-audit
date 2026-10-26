BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'Reports' {
    BeforeAll {
        $snapshot = Get-TestSnapshot weak
        # Inbox rule names and app names are attacker-controlled; plant markup in both.
        $snapshot.Datasets['exoInboxRules'][0].Name = '<script>alert(1)</script>'
        ($snapshot.Datasets['servicePrincipals'] | Where-Object displayName -EQ 'MailSync Pro').displayName = 'Mail<img src=x onerror=alert(2)>Sync'
        $findings = @(Invoke-M365BecAuditAnalysis -Snapshot $snapshot)
        $out = Join-Path -Path $TestDrive -ChildPath 'out'
        $paths = Export-M365BecAuditReport -Finding $findings -Snapshot $snapshot -OutputPath $out
        $html = Get-Content -LiteralPath $paths.Html -Raw
        $json = Get-Content -LiteralPath $paths.Json -Raw | ConvertFrom-Json
    }

    It 'writes HTML and JSON files' {
        Test-Path -LiteralPath $paths.Html | Should -BeTrue
        Test-Path -LiteralPath $paths.Json | Should -BeTrue
    }

    It 'HTML-encodes tenant-controlled strings' {
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Not -Match '<img src=x'
    }

    It 'is self-contained: no scripts and no external resources' {
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<link'
        $html | Should -Not -Match '<[^>]+\ssrc='
        foreach ($m in [regex]::Matches($html, 'href="([^"]+)"')) {
            $m.Groups[1].Value | Should -Match '^(#BEC-|https://learn\.microsoft\.com/)'
        }
    }

    It 'contains a section for every check' {
        foreach ($f in $findings) { $html | Should -Match "id=""$($f.Id)""" }
    }

    It 'supports dark mode' {
        $html | Should -Match 'prefers-color-scheme: dark'
    }

    It 'puts failing checks first, most severe first' {
        $order = @($json.findings.id)
        $order[0] | Should -BeIn @('BEC-MFA-02', 'BEC-APP-01')
        $json.findings[0].severity | Should -Be 'Critical'
    }

    It 'JSON carries the summary, tenant metadata and every finding' {
        $json.tool | Should -Be 'M365BecAudit'
        $json.tenant.tenantName | Should -Be 'Contoso Weak (synthetic)'
        @($json.findings).Count | Should -Be 15
        $json.summary.Fail | Should -Be 15
        $json.summary.Critical | Should -Be 2
        ($json.findings | Where-Object id -EQ 'BEC-EXO-02').evidence[0].Rule | Should -Not -BeNullOrEmpty
    }

    It 'counts not-assessed checks in the summary' {
        $basic = Get-TestSnapshot basic
        $doc = InModuleScope M365BecAudit -Parameters @{ s = $basic } {
            param($s)
            ConvertTo-AuditJson -Finding @(Invoke-M365BecAuditAnalysis -Snapshot $s) -Snapshot $s
        } | ConvertFrom-Json
        $doc.summary.NotAssessed | Should -Be 2
        $doc.collectionErrors.exoInboxRules | Should -Match 'Skipped'
    }
}

Describe 'Invoke-M365BecAudit' {
    It 'runs end to end from a fixture and returns findings with -PassThru' {
        $out = Join-Path -Path $TestDrive -ChildPath 'e2e'
        $result = Invoke-M365BecAudit -FixturePath (Join-Path $FixtureRoot 'contoso-hardened') -OutputPath $out -Quiet -PassThru
        @($result.Findings).Count | Should -Be 15
        Test-Path -LiteralPath $result.Report.Html | Should -BeTrue
    }

    It 'passes thresholds and break-glass names through to the checks' {
        $result = Invoke-M365BecAudit -FixturePath (Join-Path $FixtureRoot 'contoso-weak') -NoReport -Quiet -PassThru -MaxGlobalAdmins 5 -BreakGlassAccount 'casey.nguyen@contoso.example.com'
        ($result.Findings | Where-Object Id -EQ 'BEC-ROLE-01').Status | Should -Be 'Pass'
        ($result.Findings | Where-Object Id -EQ 'BEC-BG-01').Summary | Should -Match 'casey.nguyen'
    }

    It 'writes nothing with -NoReport' {
        $out = Join-Path -Path $TestDrive -ChildPath 'none'
        $null = Invoke-M365BecAudit -FixturePath (Join-Path $FixtureRoot 'contoso-weak') -OutputPath $out -NoReport -Quiet
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}
