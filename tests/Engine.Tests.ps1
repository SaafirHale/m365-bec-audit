BeforeDiscovery {
    # The per-check cases below are generated from the module at discovery time.
    Import-Module (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'src\M365BecAudit\M365BecAudit.psd1') -Force
}

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'Check registry' {
    BeforeAll { $checks = @(Get-M365BecAuditCheck) }

    It 'defines fifteen checks with unique ids' {
        $checks.Count | Should -Be 15
        @($checks.Id | Sort-Object -Unique).Count | Should -Be 15
    }

    It '<Id> links to Microsoft Learn and has an implementation' -ForEach @(Get-M365BecAuditCheck | ForEach-Object { @{ Id = $_.Id; References = $_.References } }) {
        $References.Count | Should -BeGreaterThan 0
        foreach ($url in $References) { $url | Should -Match '^https://learn\.microsoft\.com/en-us/' }
        $fn = InModuleScope M365BecAudit -Parameters @{ Id = $Id } { param($Id) (Get-AuditCheckDefinition | Where-Object Id -EQ $Id).Function }
        InModuleScope M365BecAudit -Parameters @{ fn = $fn } { param($fn) Get-Command -Name $fn -ErrorAction SilentlyContinue } | Should -Not -BeNullOrEmpty
    }

    It 'only requires datasets that exist in the catalog' {
        $names = InModuleScope M365BecAudit { @(Get-AuditDatasetCatalog | ForEach-Object { $_.Name }) }
        foreach ($c in $checks) { foreach ($r in $c.Requires) { $names | Should -Contain $r } }
    }
}

Describe 'Analysis engine' {
    It 'every check fails on the weak tenant and passes on the hardened tenant' {
        $weak = @(Invoke-M365BecAuditAnalysis -Snapshot (Get-TestSnapshot weak))
        $hardened = @(Invoke-M365BecAuditAnalysis -Snapshot (Get-TestSnapshot hardened))
        $weak.Count | Should -Be 15
        @($weak | Where-Object Status -NE 'Fail').Id | Should -BeNullOrEmpty
        @($hardened | Where-Object Status -NE 'Pass').Id | Should -BeNullOrEmpty
    }

    It 'gives every finding remediation text and references' {
        foreach ($f in Invoke-M365BecAuditAnalysis -Snapshot (Get-TestSnapshot weak)) {
            $f.Remediation | Should -Not -BeNullOrEmpty
            @($f.References).Count | Should -BeGreaterThan 0
            $f.Summary | Should -Not -BeNullOrEmpty
        }
    }

    It 'reports Error, not a crash, when a check throws' {
        Mock -ModuleName M365BecAudit Test-BecStaleGuest { throw 'boom' }
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-GUEST-01'
        $f.Status | Should -Be 'Error'
        $f.Summary | Should -Match 'boom'
    }

    It 'rejects an unknown check id' {
        { Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-NOPE-99' } | Should -Throw '*Unknown check id*'
    }

    It 'accepts a snapshot from the pipeline' {
        @(Get-TestSnapshot hardened | Invoke-M365BecAuditAnalysis -CheckId 'BEC-CA-01').Status | Should -Be 'Pass'
    }
}
