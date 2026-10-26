BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')
}

Describe 'Least-privilege, read-only access' {
    It 'requests only read-only Graph scopes' {
        $scopes = @(Get-M365BecAuditPermission)
        $scopes | Should -Be @('AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')
        foreach ($scope in $scopes) { $scope | Should -Match '\.Read\.' -Because $scope; $scope | Should -Not -Match 'Write' }
    }

    It 'documents a least-privileged permission for every dataset' {
        foreach ($row in Get-M365BecAuditPermission -Detailed) {
            $row.LeastPrivileged | Should -Not -BeNullOrEmpty -Because $row.Dataset
            if ($row.Source -eq 'Graph') { $row.Requested | Should -Not -BeNullOrEmpty -Because $row.Dataset }
        }
    }

    It 'only calls Get-* cmdlets and GET helpers when collecting' {
        # Walk the AST of every Fetch scriptblock in the dataset catalog.
        $allowed = @('Invoke-AuditGraphGet', 'Select-Object', 'Where-Object', 'ForEach-Object', 'Write-Warning')
        $commands = InModuleScope M365BecAudit {
            Get-AuditDatasetCatalog | ForEach-Object {
                $_.Fetch.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() }
            } | Where-Object { $_ } | Sort-Object -Unique
        }
        foreach ($c in $commands) {
            ($c -like 'Get-*' -or $allowed -contains $c) | Should -BeTrue -Because "collection must stay read-only, but it calls $c"
        }
    }

    It 'uses Invoke-MgGraphRequest only with -Method GET anywhere in the module' {
        $calls = foreach ($file in Get-ChildItem -Path (Join-Path $RepoRoot 'src') -Recurse -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MgGraphRequest' }, $true)
        }
        @($calls).Count | Should -BeGreaterThan 0
        foreach ($call in $calls) { $call.Extent.Text | Should -Match '-Method GET\b' }
    }

    It 'connects with exactly the read-only scopes, scoped to the process' {
        Mock -ModuleName M365BecAudit Connect-MgGraph { }
        Mock -ModuleName M365BecAudit Get-MgContext { [pscustomobject]@{ Account = 'a@contoso.example.com'; TenantId = 't'; Scopes = @('AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory') } }
        $result = Connect-M365BecAudit -SkipExchange -TenantId 'contoso.example.com'
        Should -Invoke -ModuleName M365BecAudit Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            ($Scopes -join ',') -eq 'AuditLog.Read.All,Directory.Read.All,Policy.Read.All,RoleManagement.Read.Directory' -and
            $ContextScope -eq 'Process' -and $TenantId -eq 'contoso.example.com'
        }
        $result.ExchangeOnline | Should -BeFalse
    }

    It 'warns when a requested scope was not granted' {
        Mock -ModuleName M365BecAudit Connect-MgGraph { }
        Mock -ModuleName M365BecAudit Get-MgContext { [pscustomobject]@{ Account = 'a'; TenantId = 't'; Scopes = @('Directory.Read.All') } }
        $warnings = $null
        $null = Connect-M365BecAudit -SkipExchange -WarningVariable warnings 3>$null
        "$warnings" | Should -Match 'AuditLog.Read.All'
    }
}
