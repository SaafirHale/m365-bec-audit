# Stale guest accounts: guests that have not signed in recently, never
# signed in, or never accepted their invitation.

function Get-LastSignIn {
    [CmdletBinding()]
    param($User)

    $activity = $User.signInActivity
    if (-not $activity) { return $null }
    $dates = @(
        $activity.lastSuccessfulSignInDateTime
        $activity.lastSignInDateTime
        $activity.lastNonInteractiveSignInDateTime
    ) | ForEach-Object { ConvertTo-AuditDate -Value $_ } | Where-Object { $_ }
    $dates | Sort-Object -Descending | Select-Object -First 1
}

function Test-BecStaleGuest {
    [CmdletBinding()]
    param($Snapshot, [hashtable]$Option)

    $now = ConvertTo-AuditDate -Value $Snapshot.Meta.collectedAt
    $guests = @(Get-SnapshotData -Snapshot $Snapshot -Name 'users' | Where-Object { $_.userType -eq 'Guest' -and $_.accountEnabled -ne $false })
    $hasActivity = @($guests | Where-Object { $_.PSObject.Properties['signInActivity'] }).Count -gt 0
    $staleCutoff = $now.AddDays(-$Option.StaleGuestDays)
    $pendingCutoff = $now.AddDays(-$Option.PendingInvitationDays)

    $evidence = foreach ($g in $guests) {
        $created = ConvertTo-AuditDate -Value $g.createdDateTime
        $last = Get-LastSignIn -User $g
        $reason = $null
        if ($g.externalUserState -eq 'PendingAcceptance') {
            $since = ConvertTo-AuditDate -Value $g.externalUserStateChangeDateTime
            if (-not $since) { $since = $created }
            if ($since -and $since -lt $pendingCutoff) { $reason = "invitation not accepted for $([int]($now - $since).TotalDays) days" }
        }
        elseif ($last) {
            if ($last -lt $staleCutoff) { $reason = "no sign-in for $([int]($now - $last).TotalDays) days" }
        }
        elseif ($created -and $created -lt $staleCutoff) {
            $reason = if ($hasActivity) { "never signed in; created $([int]($now - $created).TotalDays) days ago" } else { "created $([int]($now - $created).TotalDays) days ago; sign-in data unavailable" }
        }
        if ($reason) {
            [pscustomobject]@{
                Guest      = if ($g.mail) { $g.mail } else { $g.userPrincipalName }
                Created    = Format-AuditDate -Value $created
                LastSignIn = Format-AuditDate -Value $last
                Reason     = $reason
            }
        }
    }
    $evidence = @($evidence)

    $dataNote = if ($guests.Count -and -not $hasActivity) { ' Sign-in activity was not available (it needs Entra ID P1 and AuditLog.Read.All), so only creation dates and invitation state were used.' } else { '' }
    if ($evidence.Count) {
        return New-CheckResult -Status Fail -Evidence $evidence `
            -Summary "$($evidence.Count) of $($guests.Count) enabled guest accounts are stale (threshold: $($Option.StaleGuestDays) days without sign-in, $($Option.PendingInvitationDays) days for unaccepted invitations). Unused guests are access nobody is watching.$dataNote"
    }
    New-CheckResult -Status Pass -Summary "None of the $($guests.Count) enabled guest accounts are stale.$dataNote"
}
