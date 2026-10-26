[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables between BeforeAll and It blocks.')]
param()

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
    $catalogNames = InModuleScope M365BecAudit { @(Get-AuditDatasetCatalog | ForEach-Object { $_.Name }) }
}

Describe 'Fixture collector' {
    It 'loads every catalog dataset from the <Tenant> fixture' -ForEach @(@{ Tenant = 'weak' }, @{ Tenant = 'hardened' }) {
        $s = Get-TestSnapshot $Tenant
        $s.Errors.Count | Should -Be 0
        foreach ($name in $catalogNames) { $s.Datasets.ContainsKey($name) | Should -BeTrue -Because $name }
    }

    It 'returns collections as arrays, including single-item and empty ones' {
        $s = Get-TestSnapshot weak
        , $s.Datasets['organization'] | Should -BeOfType [object[]]
        @($s.Datasets['organization']).Count | Should -Be 1
        , $s.Datasets['exoOutboundSpamRules'] | Should -BeOfType [object[]]
        @($s.Datasets['exoOutboundSpamRules']).Count | Should -Be 0
    }

    It 'reads tenant metadata from organization.json and _meta.json' {
        $s = Get-TestSnapshot weak
        $s.Meta.tenantName | Should -Be 'Contoso Weak (synthetic)'
        $s.Meta.defaultDomain | Should -Be 'contoso.example.com'
        $s.Meta.collector | Should -Be 'Fixture'
        (InModuleScope M365BecAudit -Parameters @{ v = $s.Meta.collectedAt } { param($v) ConvertTo-AuditDate $v }).Year | Should -Be 2026
    }

    It 'replays recorded collection errors from _errors.json' {
        $s = Get-TestSnapshot basic
        $s.Errors.Keys | Sort-Object | Should -Be @('exoInboxRules', 'roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances')
        $s.Errors['exoInboxRules'] | Should -Match 'Skipped by request'
    }

    It 'records a missing dataset file as an error instead of failing' {
        $copy = Join-Path -Path $TestDrive -ChildPath 'partial'
        Copy-Item -Path (Join-Path $FixtureRoot 'contoso-hardened') -Destination $copy -Recurse
        Remove-Item -LiteralPath (Join-Path $copy 'exoInboxRules.json')
        $s = Get-M365BecAuditSnapshot -FixturePath $copy
        $s.Errors['exoInboxRules'] | Should -Match 'not present in the snapshot'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-02').Status | Should -Be 'NotAssessed'
    }

    It 'round-trips through Save-M365BecAuditSnapshot with identical results' {
        $original = Get-TestSnapshot weak
        $path = Join-Path -Path $TestDrive -ChildPath 'recording'
        $null = Save-M365BecAuditSnapshot -Snapshot $original -Path $path
        $replayed = Get-M365BecAuditSnapshot -FixturePath $path
        $a = Invoke-M365BecAuditAnalysis -Snapshot $original | ForEach-Object { "$($_.Id)=$($_.Status)/$($_.Severity)/$(@($_.Evidence).Count)" }
        $b = Invoke-M365BecAuditAnalysis -Snapshot $replayed | ForEach-Object { "$($_.Id)=$($_.Status)/$($_.Severity)/$(@($_.Evidence).Count)" }
        $b | Should -Be $a
    }

    It 'round-trips recorded errors' {
        $path = Join-Path -Path $TestDrive -ChildPath 'recording-basic'
        $null = Save-M365BecAuditSnapshot -Snapshot (Get-TestSnapshot basic) -Path $path
        (Get-M365BecAuditSnapshot -FixturePath $path).Errors.Count | Should -Be 3
    }
}

Describe 'Collector contract' {
    It 'accepts any object that implements Kind, Skip, ReadMeta and ReadDataset' {
        $inMemory = [pscustomobject]@{
            Kind        = 'InMemory'
            Description = 'test double'
            Skip        = @('exoInboxRules')
            ReadMeta    = { param($Collector) $null = $Collector; @{ collectedAt = '2026-10-01T00:00:00Z' } }
            ReadDataset = {
                param($Collector, $Definition, $Collected)
                $null = $Collector, $Collected
                switch ($Definition.Name) {
                    'securityDefaults' { [pscustomobject]@{ isEnabled = $true } }
                    'conditionalAccessPolicies' { , @() }
                    default { throw 'not provided' }
                }
            }
        }
        $s = Get-M365BecAuditSnapshot -Collector $inMemory
        $s.Meta.collector | Should -Be 'InMemory'
        $s.Errors['exoInboxRules'] | Should -Be 'Skipped by request.'
        $s.Errors['users'] | Should -Be 'not provided'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-CA-01').Status | Should -Be 'Pass'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-MFA-01').Status | Should -Be 'NotAssessed'
    }
}

Describe 'Live collector (mocked Microsoft Graph)' {
    BeforeAll {
        Mock -ModuleName M365BecAudit Get-MgContext { [pscustomobject]@{ Account = 'auditor@contoso.example.com'; TenantId = 'tenant-id'; Scopes = @() } }
        Mock -ModuleName M365BecAudit Invoke-MgGraphRequest {
            switch -Wildcard ($Uri) {
                '*skiptoken=page2*' { return '{"value":[{"id":"u2","userPrincipalName":"two@contoso.example.com","userType":"Member"}]}' }
                '/v1.0/users?*signInActivity*' { return '{"value":[{"id":"u1","userPrincipalName":"one@contoso.example.com","userType":"Member"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/users?$skiptoken=page2"}' }
                '/v1.0/organization*' { return '{"value":[{"id":"t1","displayName":"Mocked Tenant","verifiedDomains":[{"name":"contoso.example.com","isDefault":true}]}]}' }
                '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' { return '{"isEnabled":true}' }
                '/v1.0/policies/*' { return '{"id":"policy"}' }
                "/v1.0/servicePrincipals?`$filter=appId*" { return '{"value":[{"id":"res1","appId":"00000003-0000-0000-c000-000000000000","appRoles":[]}]}' }
                default { return '{"value":[]}' }
            }
        }
        $s = Get-M365BecAuditSnapshot -Live -SkipExchange
    }

    It 'only ever issues GET requests' {
        Should -Invoke -ModuleName M365BecAudit Invoke-MgGraphRequest -ParameterFilter { $Method -ne 'GET' } -Times 0 -Exactly
        Should -Invoke -ModuleName M365BecAudit Invoke-MgGraphRequest -ParameterFilter { $Method -eq 'GET' } -Scope Describe
    }

    It 'follows @odata.nextLink paging' {
        @($s.Datasets['users']).Count | Should -Be 2
        @($s.Datasets['users'].userPrincipalName) | Should -Be @('one@contoso.example.com', 'two@contoso.example.com')
    }

    It 'queries role assignments once per privileged role' {
        $roleCount = InModuleScope M365BecAudit { $script:PrivilegedRoles.Count }
        Should -Invoke -ModuleName M365BecAudit Invoke-MgGraphRequest -ParameterFilter { "$Uri" -cmatch '/roleAssignments\?' } -Times $roleCount -Exactly -Scope Describe
    }

    It 'collects app role assignments for each resource service principal found' {
        Should -Invoke -ModuleName M365BecAudit Invoke-MgGraphRequest -ParameterFilter { $Uri -like '/v1.0/servicePrincipals/res1/appRoleAssignedTo*' } -Times 2 -Exactly -Scope Describe
    }

    It 'returns single-object datasets as objects' {
        $s.Datasets['securityDefaults'].isEnabled | Should -BeTrue
    }

    It 'marks Exchange datasets as skipped' {
        $s.Errors['exoMailboxes'] | Should -Be 'Skipped by request.'
        $s.Meta.tenantName | Should -Be 'Mocked Tenant'
        $s.Meta.account | Should -Be 'auditor@contoso.example.com'
    }

    It 'falls back to users without signInActivity when that request fails' {
        Mock -ModuleName M365BecAudit Invoke-MgGraphRequest { throw 'Forbidden: tenant has no premium license' } -ParameterFilter { $Uri -like '*signInActivity*' }
        Mock -ModuleName M365BecAudit Invoke-MgGraphRequest { '{"value":[{"id":"u3","userType":"Guest"}]}' } -ParameterFilter { $Uri -like '/v1.0/users?*' -and $Uri -notlike '*signInActivity*' }
        $fallback = Get-M365BecAuditSnapshot -Live -SkipExchange 3>$null
        @($fallback.Datasets['users']).id | Should -Be 'u3'
        $fallback.Errors.ContainsKey('users') | Should -BeFalse
    }

    It 'refuses to run live without a Graph connection' {
        Mock -ModuleName M365BecAudit Get-MgContext { $null }
        { Get-M365BecAuditSnapshot -Live -SkipExchange } | Should -Throw '*Connect-M365BecAudit*'
    }
}

Describe 'Live collector (stubbed Exchange Online)' {
    BeforeAll {
        # Exchange Online cmdlets only exist after Connect-ExchangeOnline, so the
        # test defines stand-ins with the same names in the global scope.
        $stubs = @{
            'Get-EXOMailbox'                    = { [pscustomobject]@{ DisplayName = 'Jamie'; UserPrincipalName = 'jamie@contoso.example.com'; PrimarySmtpAddress = 'jamie@contoso.example.com'; ExternalDirectoryObjectId = 'u1'; RecipientTypeDetails = 'UserMailbox'; ForwardingSmtpAddress = 'smtp:jamie@mail.example.net'; ForwardingAddress = $null; DeliverToMailboxAndForward = $false } }
            'Get-InboxRule'                     = { [pscustomobject]@{ Name = '..'; Enabled = $true; Priority = 1; From = $null; SubjectContainsWords = $null; SubjectOrBodyContainsWords = @('invoice'); BodyContainsWords = $null; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $true; SoftDeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $true; StopProcessingRules = $true } }
            'Get-AcceptedDomain'                = { [pscustomobject]@{ DomainName = 'contoso.example.com'; DomainType = 'Authoritative'; Default = $true } }
            'Get-HostedOutboundSpamFilterPolicy' = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Off' } }
            'Get-HostedOutboundSpamFilterRule'  = { }
            'Get-RemoteDomain'                  = { [pscustomobject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $false } }
            'Get-AdminAuditLogConfig'           = { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $true; Other = 'ignored' } }
            'Get-OrganizationConfig'            = { [pscustomobject]@{ AuditDisabled = $false } }
        }
        foreach ($name in $stubs.Keys) { Set-Item -Path "function:global:$name" -Value $stubs[$name] }

        Mock -ModuleName M365BecAudit Get-MgContext { [pscustomobject]@{ Account = 'auditor@contoso.example.com'; TenantId = 't'; Scopes = @() } }
        Mock -ModuleName M365BecAudit Invoke-MgGraphRequest { '{"value":[]}' }
        $s = Get-M365BecAuditSnapshot -Live
    }

    AfterAll {
        foreach ($name in $stubs.Keys) { Remove-Item -Path "function:global:$name" -ErrorAction SilentlyContinue }
    }

    It 'collects every Exchange dataset' {
        foreach ($name in @('exoAcceptedDomains', 'exoMailboxes', 'exoInboxRules', 'exoOutboundSpamPolicies', 'exoOutboundSpamRules', 'exoRemoteDomains', 'exoAdminAuditLogConfig', 'exoOrganizationConfig')) {
            $s.Errors.ContainsKey($name) | Should -BeFalse -Because $name
        }
    }

    It 'normalises live objects to the fixture shape' {
        $rule = @($s.Datasets['exoInboxRules'])[0]
        $rule.MailboxOwner | Should -Be 'jamie@contoso.example.com'
        , $rule.ForwardTo | Should -BeOfType [object[]]
        $s.Datasets['exoAdminAuditLogConfig'].PSObject.Properties.Name | Should -Be @('UnifiedAuditLogIngestionEnabled')
    }

    It 'feeds the same checks as a fixture does' {
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-01').Status | Should -Be 'Fail'
        # Deletes mail matching a finance keyword: High.
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-02').Status | Should -Be 'Fail'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-03').Status | Should -Be 'Pass'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-04').Status | Should -Be 'Pass'
    }

    It 'skips only inbox rules with -SkipInboxRules' {
        $partial = Get-M365BecAuditSnapshot -Live -SkipInboxRules
        $partial.Errors.Keys | Should -Be @('exoInboxRules')
    }
}
