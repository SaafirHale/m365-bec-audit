[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables between BeforeAll and It blocks.')]
param()

BeforeAll {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers.ps1')

    function New-TestRule {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory test object.')]
        param([string]$Name = 'Rule', [hashtable]$Set = @{})
        $rule = [ordered]@{
            MailboxOwner = 'sam.okafor@contoso.example.com'; Name = $Name; Enabled = $true; Priority = 1
            From = @(); SubjectContainsWords = @(); SubjectOrBodyContainsWords = @(); BodyContainsWords = @()
            ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @()
            DeleteMessage = $false; SoftDeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $false; StopProcessingRules = $false
        }
        foreach ($k in $Set.Keys) { $rule[$k] = $Set[$k] }
        [pscustomobject]$rule
    }
}

Describe 'BEC-EXO-01 Mailbox external forwarding' {
    It 'fails on external SMTP forwarding and lists recipient-object forwards for review' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-EXO-01'
        $f.Status | Should -Be 'Fail'
        $external = $f.Evidence | Where-Object Assessment -EQ 'External SMTP forwarding'
        $external.Mailbox | Should -Be 'alex.ford@contoso.example.com'
        $external.ForwardsTo | Should -Be 'alex.ford.home@mail.example.net'
        $external.KeepsCopy | Should -BeTrue
        ($f.Evidence | Where-Object Mailbox -EQ 'accounts.payable@contoso.example.com').ForwardsTo | Should -Be 'Vendor Payments Contact'
    }

    It 'warns when the only forwarding targets a recipient object' {
        $s = Get-TestSnapshot weak
        ($s.Datasets['exoMailboxes'] | Where-Object UserPrincipalName -EQ 'alex.ford@contoso.example.com').ForwardingSmtpAddress = $null
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-01').Status | Should -Be 'Warn'
    }

    It 'treats forwarding to an accepted domain as internal' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoMailboxes'][0].ForwardingSmtpAddress = 'smtp:sam.okafor@contosohardened.onmicrosoft.com'
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-01').Status | Should -Be 'Pass'
    }

    It 'passes when no mailbox forwards' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-EXO-01').Status | Should -Be 'Pass'
    }
}

Describe 'BEC-EXO-02 Inbox rules that forward, delete or hide mail' {
    BeforeAll {
        $weak = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-EXO-02'
    }

    It 'fails on the weak tenant' {
        $weak.Status | Should -Be 'Fail'
        @($weak.Evidence).Count | Should -Be 3
    }

    It 'flags the classic hide-the-reply rule with every reason' {
        $rule = $weak.Evidence | Where-Object Mailbox -EQ 'jamie.rowe@contoso.example.com'
        $rule.Risk | Should -Be 'High'
        $rule.Reasons | Should -Match 'RSS Feeds'
        $rule.Reasons | Should -Match 'marks as read'
        $rule.Reasons | Should -Match 'finance keywords \(invoice, payment, wire transfer\)'
        $rule.Reasons | Should -Match "rule name '\.' is blank or punctuation only"
    }

    It 'flags a redirect to an external address' {
        $rule = $weak.Evidence | Where-Object Rule -EQ 'Sync'
        $rule.Risk | Should -Be 'High'
        $rule.Reasons | Should -Match 'quinn\.h\.archive@mail\.example\.net'
    }

    It 'rates a plain delete rule Medium' {
        ($weak.Evidence | Where-Object Mailbox -EQ 'avery.stone@contoso.example.com').Risk | Should -Be 'Medium'
    }

    It 'ignores internal forwards, ordinary folder moves and disabled rules' {
        $weak.Evidence.Rule | Should -Not -Contain 'Forward to manager'
        $weak.Evidence.Rule | Should -Not -Contain 'Newsletters'
        $weak.Evidence.Rule | Should -Not -Contain 'Old forward (disabled)'
    }

    It 'warns when only Medium-risk rules are present' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoInboxRules'] = @(New-TestRule -Name 'Junk the noise' -Set @{ MoveToFolder = 'sam:\Junk Email' })
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-02'
        $f.Status | Should -Be 'Warn'
        $f.Severity | Should -Be 'Medium'
    }

    It 'rates ForwardAsAttachmentTo an external address High' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoInboxRules'] = @(New-TestRule -Set @{ ForwardAsAttachmentTo = @('"x" [SMTP:x@mail.example.net]') })
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-02').Status | Should -Be 'Fail'
    }

    It 'passes when rules only organise mail internally' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-EXO-02'
        $f.Status | Should -Be 'Pass'
        $f.Summary | Should -Match '2 enabled inbox rules'
    }

    It 'is not assessed when inbox rules were skipped' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-EXO-02'
        $f.Status | Should -Be 'NotAssessed'
        $f.Summary | Should -Match 'Skipped by request'
    }
}

Describe 'SMTP address parsing' {
    It 'parses <Form>' -ForEach @(
        @{ Form = 'display name with SMTP tag'; In = '"Ext" [SMTP:Collector@Mail.Example.Net]'; Out = 'collector@mail.example.net' }
        @{ Form = 'lower-case smtp prefix'; In = 'smtp:a@mail.example.net'; Out = 'a@mail.example.net' }
        @{ Form = 'bare address'; In = 'b@mail.example.net'; Out = 'b@mail.example.net' }
    ) {
        InModuleScope M365BecAudit -Parameters @{ In = $In; Out = $Out } {
            param($In, $Out)
            Get-SmtpAddress -Value $In | Should -Be $Out
        }
    }

    It 'ignores legacy EX addresses' {
        InModuleScope M365BecAudit {
            @(Get-SmtpAddress -Value '"Jane" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group/cn=Recipients/cn=jane]').Count | Should -Be 0
        }
    }
}

Describe 'BEC-EXO-03 Outbound spam policy allows auto-forwarding' {
    It 'fails when the default policy is On' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-EXO-03'
        $f.Status | Should -Be 'Fail'
        ($f.Evidence | Where-Object Policy -EQ 'Default').Assessment | Should -Be 'Allows external auto-forwarding'
    }

    It 'warns when the default policy is Automatic' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot basic) -Id 'BEC-EXO-03'
        $f.Status | Should -Be 'Warn'
        $f.Summary | Should -Match 'Automatic'
    }

    It 'warns when a custom policy turns forwarding On for some senders' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoOutboundSpamPolicies'] = @($s.Datasets['exoOutboundSpamPolicies']) + [pscustomobject]@{ Name = 'Allow forwarding - Sales'; IsDefault = $false; AutoForwardingMode = 'On' }
        $s.Datasets['exoOutboundSpamRules'] = @([pscustomobject]@{ Name = 'Allow forwarding - Sales'; HostedOutboundSpamFilterPolicy = 'Allow forwarding - Sales'; State = 'Enabled'; Priority = 0; From = @(); FromMemberOf = @('sales@contoso.example.org'); SenderDomainIs = @() })
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-03'
        $f.Status | Should -Be 'Warn'
        ($f.Evidence | Where-Object Policy -EQ 'Allow forwarding - Sales').AppliesTo | Should -Be 'sales@contoso.example.org'
    }

    It 'ignores a custom On policy whose rule is disabled' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoOutboundSpamPolicies'] = @($s.Datasets['exoOutboundSpamPolicies']) + [pscustomobject]@{ Name = 'Old'; IsDefault = $false; AutoForwardingMode = 'On' }
        $s.Datasets['exoOutboundSpamRules'] = @([pscustomobject]@{ Name = 'Old'; HostedOutboundSpamFilterPolicy = 'Old'; State = 'Disabled'; Priority = 0; From = @('a@contoso.example.org'); FromMemberOf = @(); SenderDomainIs = @() })
        (Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-03').Status | Should -Be 'Pass'
    }

    It 'passes when the default policy is Off, and reports remote domains as context' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-EXO-03'
        $f.Status | Should -Be 'Pass'
        ($f.Evidence | Where-Object Policy -Like 'Remote domain*').AutoForwardingMode | Should -Be 'Blocked'
    }
}

Describe 'BEC-EXO-04 Audit logging enabled' {
    It 'fails when the unified audit log is off' {
        $f = Invoke-TestCheck -Snapshot (Get-TestSnapshot weak) -Id 'BEC-EXO-04'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'unified audit log is off'
    }

    It 'fails when mailbox auditing is disabled for the organisation' {
        $s = Get-TestSnapshot hardened
        $s.Datasets['exoOrganizationConfig'].AuditDisabled = $true
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-04'
        $f.Status | Should -Be 'Fail'
        $f.Summary | Should -Match 'mailbox auditing'
    }

    It 'still assesses the unified audit log when organisation config is missing' {
        $s = Get-TestSnapshot hardened
        Remove-TestDataset -Snapshot $s -Name 'exoOrganizationConfig'
        $f = Invoke-TestCheck -Snapshot $s -Id 'BEC-EXO-04'
        $f.Status | Should -Be 'Pass'
        @($f.Evidence).Count | Should -Be 1
    }

    It 'passes when both are on' {
        (Invoke-TestCheck -Snapshot (Get-TestSnapshot hardened) -Id 'BEC-EXO-04').Status | Should -Be 'Pass'
    }
}
