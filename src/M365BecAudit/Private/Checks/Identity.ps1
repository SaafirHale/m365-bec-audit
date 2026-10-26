# MFA registration checks, from the authentication methods registration report.

function Test-BecUserMfaRegistration {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $users = Get-UserIndex -Snapshot $Snapshot
    $members = @(Get-SnapshotData -Snapshot $Snapshot -Name 'userRegistrationDetails' | Where-Object {
            $_.userType -ne 'guest' -and -not ($users.ContainsKey($_.id) -and $users[$_.id].accountEnabled -eq $false)
        })
    $missing = @($members | Where-Object { -not $_.isMfaRegistered })

    $evidence = foreach ($r in $missing) {
        [pscustomobject]@{
            User    = $r.userPrincipalName
            Name    = $r.userDisplayName
            Admin   = if ($r.isAdmin) { 'yes' } else { '' }
            Methods = if (@($r.methodsRegistered).Count) { @($r.methodsRegistered) -join ', ' } else { 'none' }
        }
    }

    if ($missing.Count -gt 0) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "$($missing.Count) of $($members.Count) enabled member accounts have no MFA method registered. An attacker holding a phished password can register their own method first."
    }
    New-CheckResult -Status Pass -Summary "All $($members.Count) enabled member accounts have an MFA method registered."
}

function Test-BecAdminPhishingResistantMfa {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $users = Get-UserIndex -Snapshot $Snapshot
    $registration = @{}
    foreach ($r in @(Get-SnapshotData -Snapshot $Snapshot -Name 'userRegistrationDetails')) { $registration[$r.id] = $r }

    # Admins = holders of a privileged role (active or eligible) plus anyone the
    # registration report itself flags as an admin.
    $roles = @{}
    foreach ($m in @(Get-PrivilegedRoleMembership -Snapshot $Snapshot | Where-Object { $_.PrincipalType -eq 'user' })) {
        if (-not $roles.ContainsKey($m.PrincipalId)) { $roles[$m.PrincipalId] = New-Object System.Collections.Generic.List[string] }
        if (-not $roles[$m.PrincipalId].Contains($m.RoleName)) { $roles[$m.PrincipalId].Add($m.RoleName) }
    }
    foreach ($r in $registration.Values) {
        if ($r.isAdmin -and -not $roles.ContainsKey($r.id)) {
            $roles[$r.id] = New-Object System.Collections.Generic.List[string]
            $roles[$r.id].Add('admin role (per registration report)')
        }
    }

    $rows = foreach ($id in $roles.Keys) {
        if ($users.ContainsKey($id) -and $users[$id].accountEnabled -eq $false) { continue }
        $r = $registration[$id]
        $methods = @($r.methodsRegistered | Where-Object { $_ })
        $upn = if ($r) { $r.userPrincipalName } elseif ($users.ContainsKey($id)) { $users[$id].userPrincipalName } else { $id }
        [pscustomobject]@{
            Admin             = $upn
            Roles             = ($roles[$id] | Sort-Object) -join ', '
            MfaRegistered     = [bool]($r -and $r.isMfaRegistered)
            PhishingResistant = [bool](@($methods | Where-Object { $_ -match $script:PhishingResistantMethodPattern }).Count)
            Methods           = if ($methods.Count) { $methods -join ', ' } else { 'none' }
        }
    }
    $rows = @($rows | Sort-Object Admin)
    $weak = @($rows | Where-Object { -not $_.PhishingResistant })
    $noMfa = @($rows | Where-Object { -not $_.MfaRegistered })

    $enforced = @()
    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'conditionalAccessPolicies') {
        $enforced = @(Get-SnapshotData -Snapshot $Snapshot -Name 'conditionalAccessPolicies' | Where-Object {
                $_.state -eq 'enabled' -and
                $_.grantControls.authenticationStrength.id -eq $script:PhishingResistantStrengthId -and
                ((@($_.conditions.users.includeRoles) | Where-Object { $script:PrivilegedRoles.Contains([string]$_) }).Count -gt 0 -or
                    @($_.conditions.users.includeUsers) -contains 'All')
            })
    }
    $policyNote = if ($enforced.Count) { " Enforced by: $(($enforced | ForEach-Object { $_.displayName }) -join ', ')." } else { ' No enabled Conditional Access policy requires the phishing-resistant MFA strength for admin roles.' }

    if ($rows.Count -eq 0) {
        return New-CheckResult -Status Warn -Severity Medium -Summary 'No privileged role holders were found to assess.'
    }
    if ($weak.Count -gt 0) {
        $severity = if ($noMfa.Count -gt 0) { 'Critical' } else { 'High' }
        $extra = if ($noMfa.Count -gt 0) { " $($noMfa.Count) of them cannot do MFA at all." } else { '' }
        return New-CheckResult -Status Fail -Severity $severity -Evidence $weak `
            -Summary "$($weak.Count) of $($rows.Count) admins have no phishing-resistant method (FIDO2/passkey, Windows Hello for Business, certificate) registered.$extra$policyNote"
    }
    if ($enforced.Count -eq 0) {
        return New-CheckResult -Status Warn -Evidence $rows `
            -Summary "All $($rows.Count) admins have a phishing-resistant method registered, but nothing forces them to use it.$policyNote"
    }
    New-CheckResult -Status Pass -Evidence $rows -Summary "All $($rows.Count) admins have a phishing-resistant method registered.$policyNote"
}
