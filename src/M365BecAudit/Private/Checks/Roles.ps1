# Privileged role checks: standing Global Administrators and privileged roles
# held permanently instead of through Privileged Identity Management (PIM).

function Get-PrivilegedRoleMembership {
    # One row per (principal, privileged role, assignment), covering active
    # assignments and, when PIM data is available, eligible ones.
    [CmdletBinding()]
    param($Snapshot)

    $users = Get-UserIndex -Snapshot $Snapshot
    $hasPim = Test-SnapshotDataset -Snapshot $Snapshot -Name 'roleAssignmentScheduleInstances'

    $instances = @{}
    if ($hasPim) {
        foreach ($i in @(Get-SnapshotData -Snapshot $Snapshot -Name 'roleAssignmentScheduleInstances')) {
            $instances["$($i.principalId)|$($i.roleDefinitionId)"] = $i
        }
    }

    $describe = {
        param($PrincipalId, $Principal)
        $type = 'user'
        $name = $PrincipalId
        $upn = $null
        if ($Principal) {
            $odataType = [string]$Principal.'@odata.type'
            if ($odataType) { $type = $odataType -replace '^#microsoft\.graph\.', '' }
            if ($Principal.displayName) { $name = $Principal.displayName }
            $upn = $Principal.userPrincipalName
        }
        elseif ($users.ContainsKey($PrincipalId)) {
            $name = $users[$PrincipalId].displayName
            $upn = $users[$PrincipalId].userPrincipalName
        }
        else {
            $type = 'unknown'
        }
        @{ Type = $type; Name = $name; Upn = $upn }
    }

    foreach ($a in @(Get-SnapshotData -Snapshot $Snapshot -Name 'roleAssignments')) {
        if (-not $script:PrivilegedRoles.Contains([string]$a.roleDefinitionId)) { continue }
        if ($a.directoryScopeId -and $a.directoryScopeId -ne '/') { continue }
        $p = & $describe $a.principalId $a.principal
        $assignment = 'Active (PIM data unavailable)'
        if ($hasPim) {
            $instance = $instances["$($a.principalId)|$($a.roleDefinitionId)"]
            if ($instance -and $instance.assignmentType -eq 'Activated') { $assignment = 'Activated (PIM)' }
            elseif ($instance -and $instance.endDateTime) { $assignment = 'Active (time-bound)' }
            else { $assignment = 'Permanent' }
        }
        [pscustomobject]@{
            PrincipalId   = [string]$a.principalId
            PrincipalType = $p.Type
            DisplayName   = $p.Name
            Upn           = $p.Upn
            RoleId        = [string]$a.roleDefinitionId
            RoleName      = $script:PrivilegedRoles[[string]$a.roleDefinitionId]
            Assignment    = $assignment
        }
    }

    if (Test-SnapshotDataset -Snapshot $Snapshot -Name 'roleEligibilityScheduleInstances') {
        foreach ($e in @(Get-SnapshotData -Snapshot $Snapshot -Name 'roleEligibilityScheduleInstances')) {
            if (-not $script:PrivilegedRoles.Contains([string]$e.roleDefinitionId)) { continue }
            if ($e.directoryScopeId -and $e.directoryScopeId -ne '/') { continue }
            $p = & $describe $e.principalId $null
            [pscustomobject]@{
                PrincipalId   = [string]$e.principalId
                PrincipalType = $p.Type
                DisplayName   = $p.Name
                Upn           = $p.Upn
                RoleId        = [string]$e.roleDefinitionId
                RoleName      = $script:PrivilegedRoles[[string]$e.roleDefinitionId]
                Assignment    = 'Eligible (PIM)'
            }
        }
    }
}

function Test-BecStandingGlobalAdmin {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $breakGlassIds = @(Get-BreakGlassAccount -Snapshot $Snapshot -Option $Option | ForEach-Object { $_.id })
    $globalAdmins = @(Get-PrivilegedRoleMembership -Snapshot $Snapshot | Where-Object { $_.RoleId -eq $script:GlobalAdminRoleId })
    $active = @($globalAdmins | Where-Object { $_.Assignment -ne 'Eligible (PIM)' })
    $standing = @($active | Where-Object { $_.Assignment -in @('Permanent', 'Active (PIM data unavailable)') })

    $evidence = foreach ($ga in $globalAdmins) {
        [pscustomobject]@{
            Principal  = if ($ga.Upn) { $ga.Upn } else { $ga.DisplayName }
            Type       = $ga.PrincipalType
            Assignment = $ga.Assignment
            BreakGlass = if ($breakGlassIds -contains $ga.PrincipalId) { 'yes' } else { '' }
        }
    }
    $groups = @($active | Where-Object { $_.PrincipalType -eq 'group' })
    $groupNote = if ($groups.Count) { " $($groups.Count) assignment(s) are to groups; their members are not expanded here." } else { '' }

    if ($standing.Count -gt $Option.MaxGlobalAdmins) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "$($standing.Count) principals hold Global Administrator permanently (threshold: $($Option.MaxGlobalAdmins)). Microsoft recommends fewer than five, with day-to-day admins made eligible through PIM.$groupNote"
    }
    if ($active.Count -lt $Option.MinGlobalAdmins) {
        return New-CheckResult -Status Warn -Severity Medium -Evidence $evidence `
            -Summary "Only $($active.Count) active Global Administrator(s). Fewer than $($Option.MinGlobalAdmins) leaves no fallback if an admin account is lost or locked out.$groupNote"
    }
    New-CheckResult -Status Pass -Evidence $evidence `
        -Summary "$($standing.Count) standing Global Administrator(s), $($active.Count) active in total (threshold: $($Option.MaxGlobalAdmins)).$groupNote"
}

function Test-BecPrivilegedRoleWithoutPim {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $breakGlassIds = @(Get-BreakGlassAccount -Snapshot $Snapshot -Option $Option | ForEach-Object { $_.id })
    $membership = @(Get-PrivilegedRoleMembership -Snapshot $Snapshot)
    $eligible = @($membership | Where-Object { $_.Assignment -eq 'Eligible (PIM)' })

    # Emergency access accounts are meant to hold Global Administrator permanently.
    $permanent = @($membership | Where-Object {
            $_.Assignment -eq 'Permanent' -and -not ($_.RoleId -eq $script:GlobalAdminRoleId -and $breakGlassIds -contains $_.PrincipalId)
        })

    $evidence = foreach ($m in $permanent) {
        [pscustomobject]@{
            Principal = if ($m.Upn) { $m.Upn } else { $m.DisplayName }
            Type      = $m.PrincipalType
            Role      = $m.RoleName
        }
    }

    if ($permanent.Count -gt 0) {
        $pimNote = if ($eligible.Count -eq 0) { ' No eligible assignments exist, so PIM is not in use for privileged roles.' } else { " $($eligible.Count) eligible assignment(s) already use PIM." }
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "$($permanent.Count) privileged role assignment(s) are permanent rather than eligible through PIM.$pimNote"
    }
    New-CheckResult -Status Pass `
        -Summary "No permanent privileged role assignments outside emergency access accounts; $($eligible.Count) eligible assignment(s) are managed through PIM."
}
