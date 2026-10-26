# Enterprise application checks: high-risk permissions held by third-party
# apps (application permissions and delegated OAuth grants) and the tenant's
# user-consent setting.

# Permissions that let an app read or send mail, take over data broadly, or
# escalate its own privileges. Names are matched across Microsoft Graph and the
# Office 365 Exchange Online resource.
$script:HighRiskPermissions = @{
    # Privilege escalation: the app can grant itself or others more access.
    'RoleManagement.ReadWrite.Directory'      = 'Critical'
    'AppRoleAssignment.ReadWrite.All'         = 'Critical'
    'Application.ReadWrite.All'               = 'Critical'
    'Directory.ReadWrite.All'                 = 'Critical'
    'Policy.ReadWrite.ConditionalAccess'      = 'Critical'
    'full_access_as_app'                      = 'Critical'
    # Mailbox access: the core of BEC.
    'Mail.ReadWrite'                          = 'High'
    'Mail.Read'                               = 'High'
    'Mail.Send'                               = 'High'
    'MailboxSettings.ReadWrite'               = 'High'
    'EWS.AccessAsUser.All'                    = 'High'
    'full_access_as_user'                     = 'High'
    'Exchange.ManageAsApp'                    = 'High'
    # Broad data and account access.
    'Files.ReadWrite.All'                     = 'High'
    'Sites.ReadWrite.All'                     = 'High'
    'Sites.FullControl.All'                   = 'High'
    'User.ReadWrite.All'                      = 'High'
    'UserAuthenticationMethod.ReadWrite.All'  = 'Critical'
}

function Test-BecHighRiskAppPermission {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $servicePrincipals = @{}
    foreach ($sp in @(Get-SnapshotData -Snapshot $Snapshot -Name 'servicePrincipals')) { $servicePrincipals[$sp.id] = $sp }

    # appRoleId -> permission value, per resource service principal.
    $resources = @{}
    $appRoleNames = @{}
    foreach ($r in @(Get-SnapshotData -Snapshot $Snapshot -Name 'resourceServicePrincipals')) {
        $resources[$r.id] = $r
        foreach ($role in @($r.appRoles)) { $appRoleNames["$($r.id)|$($role.id)"] = $role.value }
    }

    $isThirdParty = {
        param($Sp)
        $Sp -and -not ($script:MicrosoftOwnerTenantIds -contains [string]$Sp.appOwnerOrganizationId) -and -not $resources.ContainsKey($Sp.id)
    }

    # client SP id -> grant type -> risky permissions
    $byApp = @{}
    $addFinding = {
        param($ClientId, $Type, [string[]]$Permissions)
        $risky = @($Permissions | Where-Object { $script:HighRiskPermissions.ContainsKey($_) })
        if (-not $risky.Count) { return }
        if (-not $byApp.ContainsKey($ClientId)) { $byApp[$ClientId] = [ordered]@{} }
        if (-not $byApp[$ClientId].Contains($Type)) { $byApp[$ClientId][$Type] = @() }
        $byApp[$ClientId][$Type] = @($byApp[$ClientId][$Type] + $risky | Select-Object -Unique)
    }

    foreach ($a in @(Get-SnapshotData -Snapshot $Snapshot -Name 'appRoleAssignedTo')) {
        if ($a.principalType -ne 'ServicePrincipal') { continue }
        if (-not (& $isThirdParty $servicePrincipals[$a.principalId])) { continue }
        $name = $appRoleNames["$($a.resourceId)|$($a.appRoleId)"]
        if ($name) { & $addFinding $a.principalId 'Application' @($name) }
    }

    $delegatedUsers = @{}
    foreach ($g in @(Get-SnapshotData -Snapshot $Snapshot -Name 'oauth2PermissionGrants')) {
        if (-not (& $isThirdParty $servicePrincipals[$g.clientId])) { continue }
        $scopes = @(([string]$g.scope).Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries))
        if ($g.consentType -eq 'AllPrincipals') {
            & $addFinding $g.clientId 'Delegated (admin consent, all users)' $scopes
        }
        else {
            $key = "$($g.clientId)"
            if (-not $delegatedUsers.ContainsKey($key)) { $delegatedUsers[$key] = @{ Users = 0; Scopes = @() } }
            $delegatedUsers[$key].Users++
            $delegatedUsers[$key].Scopes = @($delegatedUsers[$key].Scopes + $scopes | Select-Object -Unique)
        }
    }
    foreach ($clientId in $delegatedUsers.Keys) {
        $entry = $delegatedUsers[$clientId]
        & $addFinding $clientId "Delegated (user consent, $($entry.Users) user(s))" $entry.Scopes
    }

    $evidence = foreach ($clientId in $byApp.Keys) {
        $sp = $servicePrincipals[$clientId]
        foreach ($type in $byApp[$clientId].Keys) {
            $f = [pscustomobject]@{ Type = $type; Permissions = $byApp[$clientId][$type] }
            $tier = Get-MaxSeverity -Severity ($f.Permissions | ForEach-Object { $script:HighRiskPermissions[$_] })
            # Delegated permissions only reach what the consenting user can reach.
            if ($f.Type -ne 'Application' -and $tier -eq 'Critical') { $tier = 'High' }
            [pscustomobject]@{
                Application = $sp.displayName
                AppId       = $sp.appId
                Publisher   = if ($sp.verifiedPublisher.displayName) { "$($sp.verifiedPublisher.displayName) (verified)" } elseif ($sp.publisherName) { "$($sp.publisherName) (unverified)" } else { 'unverified' }
                Grant       = $f.Type
                Permissions = ($f.Permissions | Sort-Object) -join ', '
                Risk        = $tier
            }
        }
    }
    $evidence = @($evidence | Sort-Object @{ e = { $script:SeverityRank[$_.Risk] }; Descending = $true }, Application)

    if ($evidence.Count) {
        $apps = @($evidence | Select-Object -ExpandProperty AppId -Unique).Count
        $severity = Get-MaxSeverity -Severity ($evidence | ForEach-Object { $_.Risk })
        return New-CheckResult -Status Fail -Severity $severity -Evidence $evidence `
            -Summary "$apps third-party app(s) hold permissions that can read or send mail, reach broad data, or escalate privileges. Confirm each is expected; illicit consent grants keep working after a password reset."
    }
    New-CheckResult -Status Pass -Summary "No third-party application holds a high-risk Microsoft Graph or Exchange Online permission ($($servicePrincipals.Count) service principals reviewed)."
}

function Test-BecUserConsentSetting {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $policy = Get-SnapshotData -Snapshot $Snapshot -Name 'authorizationPolicy'
    $assigned = @($policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Where-Object { $_ })
    $self = @($assigned | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' } | ForEach-Object { $_ -replace '^ManagePermissionGrantsForSelf\.', '' })

    $workflow = $null
    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'adminConsentRequestPolicy') {
        $workflow = [bool](Get-SnapshotData -Snapshot $Snapshot -Name 'adminConsentRequestPolicy').isEnabled
    }
    $evidence = @(
        [pscustomobject]@{ Setting = 'permissionGrantPoliciesAssigned'; Value = if ($assigned.Count) { $assigned -join ', ' } else { '(none)' } }
        if ($null -ne $workflow) { [pscustomobject]@{ Setting = 'Admin consent workflow'; Value = if ($workflow) { 'enabled' } else { 'disabled' } } }
    )
    $workflowNote = if ($workflow -eq $false) { ' The admin consent workflow is off, so users have no sanctioned way to request an app.' } else { '' }

    if ($self -contains 'microsoft-user-default-legacy') {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "Users can consent to any app for any permission that does not need admin consent, including reading their own mail. This is the setting consent-phishing campaigns rely on.$workflowNote"
    }
    $known = @('microsoft-user-default-low')
    $custom = @($self | Where-Object { $known -notcontains $_ })
    if ($custom.Count) {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $evidence `
            -Summary "User consent is governed by custom app consent policy $($custom -join ', '). Review what it allows.$workflowNote"
    }
    if ($self.Count) {
        return New-CheckResult -Status Pass -Evidence $evidence `
            -Summary "User consent is limited by Microsoft's built-in policy ($($self -join ', ')).$workflowNote"
    }
    New-CheckResult -Status Pass -Evidence $evidence -Summary "Users cannot consent to applications; an administrator must approve every app.$workflowNote"
}
