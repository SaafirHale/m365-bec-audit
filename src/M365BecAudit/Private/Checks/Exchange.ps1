# Exchange Online checks: mailbox forwarding, inbox rules, the outbound spam
# policy's auto-forwarding setting, and audit logging.

function Get-InternalDomain {
    [CmdletBinding()]
    [OutputType([string])]
    param($Snapshot)

    Get-SnapshotData -Snapshot $Snapshot -Name 'exoAcceptedDomains' | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() }
}

function Test-BecMailboxForwarding {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $internal = Get-InternalDomain -Snapshot $Snapshot
    $mailboxes = @(Get-SnapshotData -Snapshot $Snapshot -Name 'exoMailboxes')
    $external = @()
    $toObject = @()

    foreach ($m in $mailboxes) {
        $smtp = @(Get-SmtpAddress -Value $m.ForwardingSmtpAddress)
        foreach ($address in $smtp) {
            if (Test-ExternalAddress -Address $address -InternalDomain $internal) {
                $external += [pscustomobject]@{
                    Mailbox     = $m.UserPrincipalName
                    ForwardsTo  = $address
                    KeepsCopy   = [bool]$m.DeliverToMailboxAndForward
                    Assessment  = 'External SMTP forwarding'
                }
            }
        }
        if ($m.ForwardingAddress) {
            $toObject += [pscustomobject]@{
                Mailbox    = $m.UserPrincipalName
                ForwardsTo = $m.ForwardingAddress
                KeepsCopy  = [bool]$m.DeliverToMailboxAndForward
                Assessment = 'Forwards to a recipient object; confirm it is not a mail contact outside the organisation'
            }
        }
    }

    $evidence = @($external) + @($toObject)
    if ($external.Count) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "$($external.Count) mailbox(es) forward mail to an external address. Mailbox forwarding is a common way attackers keep reading a compromised mailbox after the password is reset."
    }
    if ($toObject.Count) {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $evidence `
            -Summary "$($toObject.Count) mailbox(es) forward to a recipient object. Confirm each target is internal."
    }
    New-CheckResult -Status Pass -Summary "None of the $($mailboxes.Count) mailboxes have forwarding configured."
}

function Get-InboxRuleFinding {
    # Returns the reasons (with a severity each) that make an inbox rule look
    # like the ones attackers create after taking over a mailbox.
    [CmdletBinding()]
    param($Rule, [string[]]$InternalDomain)

    $reasons = New-Object System.Collections.Generic.List[object]
    $add = { param($Severity, $Text) $reasons.Add([pscustomobject]@{ Severity = $Severity; Text = $Text }) }

    $targets = @(Get-SmtpAddress -Value (@($Rule.ForwardTo) + @($Rule.ForwardAsAttachmentTo) + @($Rule.RedirectTo)))
    $externalTargets = @($targets | Where-Object { Test-ExternalAddress -Address $_ -InternalDomain $InternalDomain })
    if ($externalTargets.Count) { & $add 'High' "forwards or redirects to external $($externalTargets -join ', ')" }

    $deletes = [bool]$Rule.DeleteMessage -or [bool]$Rule.SoftDeleteMessage
    if ($deletes) { & $add 'Medium' 'deletes matching messages' }

    $hidingFolder = $Rule.MoveToFolder -and ([string]$Rule.MoveToFolder -match '(?i)(RSS (Feeds|Subscriptions)|Conversation History|Archive|Junk Email|Deleted Items)\s*$')
    if ($hidingFolder -and $Rule.MarkAsRead) { & $add 'High' "moves to '$($Rule.MoveToFolder)' and marks as read" }
    elseif ($hidingFolder) { & $add 'Medium' "moves to rarely-checked folder '$($Rule.MoveToFolder)'" }

    $words = @($Rule.SubjectContainsWords) + @($Rule.SubjectOrBodyContainsWords) + @($Rule.BodyContainsWords) | Where-Object { $_ }
    $financial = @($words | Where-Object { $_ -match '(?i)invoice|payment|wire|bank|remit|ach\b|transfer|payroll|w-?2|direct deposit' })
    if ($financial.Count -and ($deletes -or $hidingFolder -or $externalTargets.Count)) {
        & $add 'High' "targets finance keywords ($($financial -join ', '))"
    }

    if ($reasons.Count -and ([string]$Rule.Name).Trim() -match '^[\W_]{0,3}$') {
        & $add 'Low' "rule name '$($Rule.Name)' is blank or punctuation only"
    }
    $reasons.ToArray()
}

function Test-BecSuspiciousInboxRule {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $internal = Get-InternalDomain -Snapshot $Snapshot
    $rules = @(Get-SnapshotData -Snapshot $Snapshot -Name 'exoInboxRules' | Where-Object { $_.Enabled -ne $false })

    $flagged = foreach ($rule in $rules) {
        $reasons = @(Get-InboxRuleFinding -Rule $rule -InternalDomain $internal)
        if (-not $reasons.Count) { continue }
        [pscustomobject]@{
            Mailbox  = $rule.MailboxOwner
            Rule     = $rule.Name
            Risk     = Get-MaxSeverity -Severity ($reasons | ForEach-Object { $_.Severity })
            Reasons  = ($reasons | ForEach-Object { $_.Text }) -join '; '
        }
    }
    $flagged = @($flagged | Sort-Object @{ e = { $script:SeverityRank[$_.Risk] }; Descending = $true }, Mailbox)

    $high = @($flagged | Where-Object { $_.Risk -eq 'High' })
    if ($high.Count) {
        return New-CheckResult -Status Fail -Evidence $flagged `
            -Summary "$($high.Count) inbox rule(s) match patterns used after a mailbox takeover: external forwarding, or hiding mail by moving it out of sight. Treat the owning accounts as possibly compromised."
    }
    if ($flagged.Count) {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $flagged `
            -Summary "$($flagged.Count) inbox rule(s) delete or move mail out of sight. Confirm with the mailbox owners that they created them."
    }
    New-CheckResult -Status Pass -Summary "None of the $($rules.Count) enabled inbox rules forward externally or hide mail."
}

function Test-BecOutboundForwardingPolicy {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $policies = @(Get-SnapshotData -Snapshot $Snapshot -Name 'exoOutboundSpamPolicies')
    $rules = @(Get-SnapshotData -Snapshot $Snapshot -Name 'exoOutboundSpamRules')
    $statuses = @()

    $evidence = foreach ($p in $policies) {
        $rule = $rules | Where-Object { $_.HostedOutboundSpamFilterPolicy -eq $p.Name } | Select-Object -First 1
        $scope = if ($p.IsDefault) { 'Everyone not covered by a custom policy' }
        elseif ($rule) { (@($rule.From) + @($rule.FromMemberOf) + @($rule.SenderDomainIs) | Where-Object { $_ }) -join ', ' }
        else { 'No rule (policy not applied)' }
        $active = $p.IsDefault -or ($rule -and $rule.State -eq 'Enabled')

        $assessment = switch ($p.AutoForwardingMode) {
            'Off' { 'Blocks external auto-forwarding' }
            'On' { if ($active) { 'Allows external auto-forwarding' } else { 'Allows auto-forwarding, but the policy is not applied' } }
            default { 'Automatic: behaviour depends on tenant history (may still allow forwarding)' }
        }
        if ($active) {
            $statuses += switch ($p.AutoForwardingMode) {
                'Off' { 'Pass' }
                'On' { if ($p.IsDefault) { 'Fail' } else { 'Warn' } }
                default { 'Warn' }
            }
        }
        [pscustomobject]@{
            Policy             = $p.Name
            Default            = [bool]$p.IsDefault
            AutoForwardingMode = $p.AutoForwardingMode
            AppliesTo          = $scope
            Assessment         = $assessment
        }
    }

    foreach ($d in @(Get-SnapshotData -Snapshot $Snapshot -Name 'exoRemoteDomains')) {
        $evidence = @($evidence) + [pscustomobject]@{
            Policy             = "Remote domain: $($d.Name) ($($d.DomainName))"
            Default            = $d.DomainName -eq '*'
            AutoForwardingMode = if ($d.AutoForwardEnabled) { 'Allowed' } else { 'Blocked' }
            AppliesTo          = $d.DomainName
            Assessment         = 'A remote-domain block also stops forwarding; when the two settings disagree, the block typically wins.'
        }
    }

    if ($statuses -contains 'Fail') {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary 'The default outbound spam policy sets automatic forwarding to On, so any inbox rule or mailbox forward can send mail outside the organisation.'
    }
    if ($statuses -contains 'Warn') {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $evidence `
            -Summary 'External auto-forwarding is not explicitly off for everyone: a policy uses Automatic (whose effect depends on tenant history) or a custom policy turns it On for some senders.'
    }
    New-CheckResult -Status Pass -Evidence $evidence -Summary 'Every applied outbound spam policy sets automatic external forwarding to Off.'
}

function Test-BecAuditLogging {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $config = Get-SnapshotData -Snapshot $Snapshot -Name 'exoAdminAuditLogConfig'
    $ualOn = [bool]$config.UnifiedAuditLogIngestionEnabled
    $evidence = @([pscustomobject]@{ Setting = 'UnifiedAuditLogIngestionEnabled'; Value = $ualOn; Expected = $true })

    $mailboxAuditOn = $null
    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'exoOrganizationConfig') {
        $mailboxAuditOn = -not [bool](Get-SnapshotData -Snapshot $Snapshot -Name 'exoOrganizationConfig').AuditDisabled
        $evidence += [pscustomobject]@{ Setting = 'AuditDisabled (mailbox auditing by default)'; Value = -not $mailboxAuditOn; Expected = $false }
    }

    $problems = @()
    if (-not $ualOn) { $problems += 'the unified audit log is off' }
    if ($mailboxAuditOn -eq $false) { $problems += 'mailbox auditing by default is disabled for the organisation' }
    if ($problems.Count) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "Audit logging is incomplete: $($problems -join ' and '). Without it there is no record of mailbox access, rule creation or consent grants to investigate a compromise."
    }
    New-CheckResult -Status Pass -Evidence $evidence -Summary 'The unified audit log is on and mailbox auditing is enabled by default.'
}
