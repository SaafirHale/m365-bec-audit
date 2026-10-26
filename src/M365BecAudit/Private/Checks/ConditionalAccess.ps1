# Conditional Access and security defaults: legacy authentication, baseline MFA
# coverage, and risk-based policies.

function Get-CAPolicyView {
    # Flattens a conditionalAccessPolicy into the handful of facts the checks
    # reason about.
    [CmdletBinding()]
    param($Policy)

    $users = $Policy.conditions.users
    $controls = @($Policy.grantControls.builtInControls | Where-Object { $_ })
    $clientApps = @($Policy.conditions.clientAppTypes | Where-Object { $_ })
    $exclusions = @($users.excludeUsers) + @($users.excludeGroups) + @($users.excludeRoles) | Where-Object { $_ }
    [pscustomobject]@{
        Name             = [string]$Policy.displayName
        State            = [string]$Policy.state
        Enforced         = $Policy.state -eq 'enabled'
        ReportOnly       = $Policy.state -eq 'enabledForReportingButNotEnforced'
        AllUsers         = @($users.includeUsers) -contains 'All'
        AllApps          = @($Policy.conditions.applications.includeApplications) -contains 'All'
        IncludeRoles     = @($users.includeRoles | Where-Object { $_ })
        ExcludeUsers     = @($users.excludeUsers | Where-Object { $_ })
        ExcludeGroups    = @($users.excludeGroups | Where-Object { $_ })
        ExclusionCount   = @($exclusions).Count
        ClientApps       = $clientApps
        Blocks           = $controls -contains 'block'
        RequiresMfa      = ($controls -contains 'mfa') -or [bool]$Policy.grantControls.authenticationStrength
        SignInRisk       = @($Policy.conditions.signInRiskLevels | Where-Object { $_ -and $_ -ne 'none' })
        UserRisk         = @($Policy.conditions.userRiskLevels | Where-Object { $_ -and $_ -ne 'none' })
        # A baseline policy applies to every sign-in, not only some locations,
        # platforms, risk levels or client types.
        Unconditional    = (-not $Policy.conditions.locations) -and (-not $Policy.conditions.platforms) -and
        (@($Policy.conditions.signInRiskLevels | Where-Object { $_ }).Count -eq 0) -and
        (@($Policy.conditions.userRiskLevels | Where-Object { $_ }).Count -eq 0) -and
        ($clientApps.Count -eq 0 -or $clientApps -contains 'all' -or ($clientApps -contains 'browser' -and $clientApps -contains 'mobileAppsAndDesktopClients'))
    }
}

function Get-CAPolicyEvidence {
    [CmdletBinding()]
    param($View)

    [pscustomobject]@{
        Policy     = $View.Name
        State      = $View.State
        Users      = if ($View.AllUsers) { 'All users' } elseif ($View.IncludeRoles.Count) { "$($View.IncludeRoles.Count) role(s)" } else { 'Selected users/groups' }
        Apps       = if ($View.AllApps) { 'All apps' } else { 'Selected apps' }
        Exclusions = $View.ExclusionCount
    }
}

function Test-SecurityDefaultsEnabled {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Snapshot)

    if (-not (Test-SnapshotDataset -Snapshot $Snapshot -Name 'securityDefaults')) { return $false }
    [bool](Get-SnapshotData -Snapshot $Snapshot -Name 'securityDefaults').isEnabled
}

function Test-BecLegacyAuthBlocked {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    if (Test-SecurityDefaultsEnabled -Snapshot $Snapshot) {
        return New-CheckResult -Status Pass -Summary 'Security defaults are enabled, which block legacy authentication protocols for every user.'
    }

    $views = @(Get-SnapshotData -Snapshot $Snapshot -Name 'conditionalAccessPolicies' | ForEach-Object { Get-CAPolicyView -Policy $_ })
    $legacy = @($views | Where-Object { $_.Blocks -and $_.ClientApps -contains 'exchangeActiveSync' -and $_.ClientApps -contains 'other' })
    $complete = @($legacy | Where-Object { $_.AllUsers -and $_.AllApps })
    $evidence = $legacy | ForEach-Object { Get-CAPolicyEvidence -View $_ }

    $enforced = @($complete | Where-Object { $_.Enforced })
    if ($enforced.Count) {
        return New-CheckResult -Status Pass -Evidence $evidence `
            -Summary "Legacy authentication is blocked for all users by: $(($enforced | ForEach-Object { $_.Name }) -join ', ')."
    }
    if (@($complete | Where-Object { $_.ReportOnly }).Count) {
        return New-CheckResult -Status Warn -Evidence $evidence `
            -Summary 'A policy to block legacy authentication exists but is in report-only mode, so legacy protocols still bypass MFA.'
    }
    if (@($legacy | Where-Object { $_.Enforced }).Count) {
        return New-CheckResult -Status Warn -Evidence $evidence `
            -Summary 'Legacy authentication is blocked only for some users or apps. Accounts outside the policy can still be password-sprayed over IMAP, POP and SMTP AUTH.'
    }
    $why = if ($legacy.Count) { 'The only legacy-authentication block policy is disabled.' } else { 'No Conditional Access policy blocks legacy authentication and security defaults are off.' }
    New-CheckResult -Status Fail -Evidence $evidence `
        -Summary "$why Legacy protocols cannot do MFA, so a stolen password is enough to read mail."
}

function Test-BecBaselineCoverage {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $policies = @(Get-SnapshotData -Snapshot $Snapshot -Name 'conditionalAccessPolicies')
    $views = @($policies | ForEach-Object { Get-CAPolicyView -Policy $_ })
    $enabled = @($views | Where-Object { $_.Enforced })

    if (Test-SecurityDefaultsEnabled -Snapshot $Snapshot) {
        return New-CheckResult -Status Pass -Severity Info `
            -Summary 'Security defaults are enabled: every user must register MFA, admins must use it, other users are prompted when needed, and legacy authentication is blocked. Tenants with Entra ID P1 can move to Conditional Access for exclusions and finer control.'
    }
    if ($enabled.Count -eq 0) {
        return New-CheckResult -Status Fail -Severity Critical -Evidence @($views | ForEach-Object { Get-CAPolicyEvidence -View $_ }) `
            -Summary 'Security defaults are off and no Conditional Access policy is enabled. Nothing in the tenant enforces MFA at sign-in.'
    }

    $baseline = @($views | Where-Object { $_.RequiresMfa -and $_.AllUsers -and $_.AllApps -and $_.Unconditional })
    $baselineEnforced = @($baseline | Where-Object { $_.Enforced })
    $evidence = $views | Where-Object { $_.RequiresMfa -or $_.Blocks } | ForEach-Object { Get-CAPolicyEvidence -View $_ }

    if ($baselineEnforced.Count -eq 0) {
        $why = if (@($baseline | Where-Object { $_.ReportOnly }).Count) { 'An all-users MFA policy exists but is only in report-only mode.' } else { 'No enabled policy requires MFA for all users on all cloud apps.' }
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "Security defaults are off and Conditional Access leaves gaps. $why Users outside the scoped policies sign in with a password alone."
    }

    $breakGlassIds = @(Get-BreakGlassAccount -Snapshot $Snapshot -Option $Option | ForEach-Object { $_.id })
    $extraExclusions = @($baselineEnforced | ForEach-Object {
            @($_.ExcludeUsers | Where-Object { $breakGlassIds -notcontains $_ }) + @($_.ExcludeGroups)
        } | Where-Object { $_ } | Select-Object -Unique)
    if ($extraExclusions.Count -gt 0) {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $evidence `
            -Summary "MFA is required for all users, but $($extraExclusions.Count) user or group exclusion(s) beyond the emergency access accounts weaken it. Review each exclusion."
    }
    New-CheckResult -Status Pass -Evidence $evidence `
        -Summary "MFA is required for all users on all cloud apps by: $(($baselineEnforced | ForEach-Object { $_.Name }) -join ', ')."
}

function Test-BecRiskPolicy {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $null = $Option
    $views = @(Get-SnapshotData -Snapshot $Snapshot -Name 'conditionalAccessPolicies' | ForEach-Object { Get-CAPolicyView -Policy $_ })
    $signIn = @($views | Where-Object { $_.SignInRisk.Count -and ($_.RequiresMfa -or $_.Blocks) })
    $user = @($views | Where-Object { $_.UserRisk.Count -and ($_.RequiresMfa -or $_.Blocks) })
    $signInOn = @($signIn | Where-Object { $_.Enforced })
    $userOn = @($user | Where-Object { $_.Enforced })

    $evidence = @($views | Where-Object { ($_.SignInRisk.Count -or $_.UserRisk.Count) -and ($_.RequiresMfa -or $_.Blocks) } | ForEach-Object {
            [pscustomobject]@{
                Policy     = $_.Name
                State      = $_.State
                SignInRisk = $_.SignInRisk -join ', '
                UserRisk   = $_.UserRisk -join ', '
            }
        })

    if ($signInOn.Count -and $userOn.Count) {
        return New-CheckResult -Status Pass -Evidence $evidence -Summary 'Enabled Conditional Access policies respond to both sign-in risk and user risk.'
    }
    if ($signInOn.Count -or $userOn.Count -or $signIn.Count -or $user.Count) {
        $missing = @()
        if (-not $signInOn.Count) { $missing += 'sign-in risk' }
        if (-not $userOn.Count) { $missing += 'user risk' }
        return New-CheckResult -Status Warn -Evidence $evidence `
            -Summary "No enforced policy covers $($missing -join ' or '). Policies in report-only or disabled state do not stop a risky sign-in."
    }
    $sd = if (Test-SecurityDefaultsEnabled -Snapshot $Snapshot) { ' Security defaults are on, but they do not offer configurable risk-based policies.' } else { '' }
    New-CheckResult -Status Fail -Summary "No Conditional Access policy uses sign-in risk or user risk, so a sign-in flagged by Identity Protection (for example from an anonymising proxy or an impossible-travel location) is not challenged or blocked.$sd"
}
