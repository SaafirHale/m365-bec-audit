# Emergency access (break-glass) account sanity, against Microsoft's guidance:
# two or more cloud-only *.onmicrosoft.com accounts, permanently active Global
# Administrator, phishing-resistant authentication, and not blocked by enforced
# Conditional Access policies.

function Test-BecBreakGlassAccount {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $accounts = @(Get-BreakGlassAccount -Snapshot $Snapshot -Option $Option)
    if ($accounts.Count -eq 0) {
        $how = if (@($Option.BreakGlassAccounts).Count) { "None of the accounts passed in BreakGlassAccounts ($($Option.BreakGlassAccounts -join ', ')) exist." } else { 'No account name matches the emergency-access pattern; pass -BreakGlassAccount if yours are named differently.' }
        return New-CheckResult -Status Fail -Summary "No emergency access accounts were identified. $how Without one, a Conditional Access mistake or an MFA outage can lock every admin out."
    }

    $globalAdmins = @(Get-PrivilegedRoleMembership -Snapshot $Snapshot | Where-Object { $_.RoleId -eq $script:GlobalAdminRoleId })
    $registration = @{}
    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'userRegistrationDetails') {
        foreach ($r in @(Get-SnapshotData -Snapshot $Snapshot -Name 'userRegistrationDetails')) { $registration[$r.id] = $r }
    }
    $enforcedPolicies = @()
    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'conditionalAccessPolicies') {
        $enforcedPolicies = @(Get-SnapshotData -Snapshot $Snapshot -Name 'conditionalAccessPolicies' | Where-Object { $_.state -eq 'enabled' })
    }

    $issues = New-Object System.Collections.Generic.List[object]
    $add = { param($Account, $Severity, $Text) $issues.Add([pscustomobject]@{ Account = $Account; Severity = $Severity; Issue = $Text }) }

    if ($accounts.Count -eq 1) { & $add $accounts[0].userPrincipalName 'Medium' 'only one emergency access account; Microsoft recommends two or more' }

    foreach ($a in $accounts) {
        $upn = $a.userPrincipalName
        if ($a.accountEnabled -eq $false) { & $add $upn 'High' 'account is disabled' }
        if ($a.onPremisesSyncEnabled) { & $add $upn 'High' 'synchronised from on-premises AD; it should be cloud-only' }
        if ($upn -notmatch '(?i)\.onmicrosoft\.com$') { & $add $upn 'Medium' 'not on the *.onmicrosoft.com domain, so it depends on a custom domain and possibly federation' }

        $ga = @($globalAdmins | Where-Object { $_.PrincipalId -eq $a.id })
        if (-not $ga.Count) { & $add $upn 'High' 'does not hold Global Administrator' }
        elseif (-not @($ga | Where-Object { $_.Assignment -in @('Permanent', 'Active (PIM data unavailable)') }).Count) {
            & $add $upn 'High' "Global Administrator is $(($ga | ForEach-Object { $_.Assignment }) -join ', ') rather than permanently active; PIM activation may be unavailable in an emergency"
        }

        if ($registration.Count) {
            $methods = @($registration[$a.id].methodsRegistered | Where-Object { $_ })
            if (-not @($methods | Where-Object { $_ -match $script:PhishingResistantMethodPattern }).Count) {
                & $add $upn 'Medium' "no phishing-resistant method registered (has: $(if ($methods.Count) { $methods -join ', ' } else { 'none' }))"
            }
        }

        foreach ($p in $enforcedPolicies) {
            $users = $p.conditions.users
            $applies = (@($users.includeUsers) -contains 'All') -or (@($users.includeUsers) -contains $a.id) -or
            (@($users.includeRoles) -contains $script:GlobalAdminRoleId)
            if (-not $applies) { continue }
            if (@($users.excludeUsers) -contains $a.id) { continue }
            if (@($users.excludeGroups | Where-Object { $_ }).Count) {
                & $add $upn 'Low' "policy '$($p.displayName)' excludes groups; confirm the emergency account is a member of one of them"
                continue
            }
            & $add $upn 'High' "subject to enforced Conditional Access policy '$($p.displayName)', which could block it during an outage"
        }
    }

    $evidence = @($issues.ToArray() | Sort-Object @{ e = { $script:SeverityRank[$_.Severity] }; Descending = $true }, Account)
    $names = ($accounts | ForEach-Object { $_.userPrincipalName }) -join ', '
    if (@($evidence | Where-Object { $_.Severity -eq 'High' }).Count) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "Emergency access account(s) $names would not reliably work in an emergency: $(@($evidence | Where-Object { $_.Severity -eq 'High' }).Count) blocking issue(s)."
    }
    if ($evidence.Count) {
        return New-CheckResult -Status Warn -Evidence $evidence -Summary "Emergency access account(s) $names exist but depart from Microsoft guidance in $($evidence.Count) way(s)."
    }
    New-CheckResult -Status Pass -Summary "$($accounts.Count) emergency access accounts ($names) are cloud-only, permanently hold Global Administrator, use phishing-resistant authentication and are excluded from enforced Conditional Access."
}
