# Shared constants and helpers used by collectors, checks and the report.

$script:SeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }
$script:StatusRank = @{ Fail = 0; Warn = 1; Error = 2; NotAssessed = 3; Pass = 4 }

# Built-in Entra role template IDs. For built-in roles the roleDefinitionId on
# an assignment equals the template ID.
# Source: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
$script:GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$script:PrivilegedRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
}

# Built-in Conditional Access authentication strength for phishing-resistant MFA.
# Source: https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies
$script:PhishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'

# methodsRegistered values (userRegistrationDetails) that count as phishing-resistant:
# FIDO2 security keys and passkeys, Windows Hello for Business, platform credentials
# and certificate-based authentication. Matched as patterns so variants such as
# passKeyDeviceBoundAuthenticator are covered.
$script:PhishingResistantMethodPattern = '(?i)^(fido2|passkey|windowsHelloForBusiness|macOsSecureEnclaveKey|platformCredential|x509Certificate)'

# Tenants that own Microsoft first-party applications. Service principals owned
# by these tenants are excluded from the third-party permission review.
$script:MicrosoftOwnerTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    '72f988bf-86f1-41af-91ab-2d7cd011db47'
)

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:ExchangeAppId = '00000002-0000-0ff1-ce00-000000000000'

function Get-AuditDefaultOption {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        StaleGuestDays        = 90
        PendingInvitationDays = 30
        MaxGlobalAdmins       = 4
        MinGlobalAdmins       = 2
        BreakGlassAccounts    = @()
        BreakGlassPattern     = '(?i)break[\s\-_.]?glass|emergency'
    }
}

function Merge-AuditOption {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([hashtable]$Option)

    $merged = Get-AuditDefaultOption
    if ($Option) {
        foreach ($key in $Option.Keys) { $merged[$key] = $Option[$key] }
    }
    $merged
}

function ConvertTo-AuditDate {
    # ConvertFrom-Json leaves ISO-8601 strings as strings on Windows PowerShell 5.1
    # and turns them into DateTime on PowerShell 7. Accept either.
    [CmdletBinding()]
    [OutputType([datetime])]
    param($Value)

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Format-AuditDate {
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    $date = ConvertTo-AuditDate -Value $Value
    if ($null -eq $date) { return 'never' }
    $date.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-SnapshotData {
    # Returns a dataset from a snapshot. Collections come back as arrays (use @()
    # at the call site); single objects come back as the object.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($Snapshot.Datasets.ContainsKey($Name)) { return $Snapshot.Datasets[$Name] }
    $null
}

function Test-SnapshotDataset {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)] [string] $Name
    )

    $Snapshot.Datasets.ContainsKey($Name) -and -not $Snapshot.Errors.ContainsKey($Name)
}

function Get-SmtpAddress {
    # Extracts SMTP addresses from Exchange recipient strings such as
    #   "Ext Collector" [SMTP:collector@mail.example.net]
    #   smtp:collector@mail.example.net
    # Legacy EX: addresses (internal recipients) are ignored.
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]]$Value)

    $addresses = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        $text = [string]$item
        $matched = [regex]::Matches($text, '(?i)smtp:([^\s\]\[<>"]+@[^\s\]\[<>"]+)')
        if ($matched.Count -gt 0) {
            foreach ($m in $matched) { $addresses.Add($m.Groups[1].Value.ToLowerInvariant()) }
        }
        elseif ($text -match '^[^\s@\[\]]+@[^\s@\[\]]+$') {
            $addresses.Add($text.ToLowerInvariant())
        }
    }
    $addresses | Select-Object -Unique
}

function Test-ExternalAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Address,
        [string[]] $InternalDomain
    )

    $domain = ($Address -split '@')[-1].ToLowerInvariant()
    -not (@($InternalDomain | ForEach-Object { $_.ToLowerInvariant() }) -contains $domain)
}

function Get-MaxSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]]$Severity)

    $best = 'Info'
    foreach ($s in @($Severity)) {
        if ($s -and $script:SeverityRank[$s] -gt $script:SeverityRank[$best]) { $best = $s }
    }
    $best
}

function New-CheckResult {
    # The value every check function returns. The engine adds the check's
    # metadata (id, title, references) to turn it into a finding.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object; changes no state.')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Fail', 'Warn', 'NotAssessed', 'Error')] [string] $Status,
        [Parameter(Mandatory)] [string] $Summary,
        [object[]] $Evidence = @(),
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')] [string] $Severity
    )

    @{
        Status   = $Status
        Summary  = $Summary
        Evidence = @($Evidence | Where-Object { $null -ne $_ })
        Severity = $Severity
    }
}

function Get-UserIndex {
    # id -> user object, for joining role assignments and registration details.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param($Snapshot)

    $index = @{}
    foreach ($u in @(Get-SnapshotData -Snapshot $Snapshot -Name 'users')) {
        if ($u.id) { $index[$u.id] = $u }
    }
    $index
}

function Get-BreakGlassAccount {
    # Emergency access accounts: the UPNs passed in BreakGlassAccounts, or member
    # users whose UPN or display name matches BreakGlassPattern.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param($Snapshot, [hashtable]$Option)

    $users = @(Get-SnapshotData -Snapshot $Snapshot -Name 'users')
    $named = @($Option.BreakGlassAccounts | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if ($named.Count -gt 0) {
        $users | Where-Object { $_.userPrincipalName -and $named -contains $_.userPrincipalName.ToLowerInvariant() }
        return
    }
    $users | Where-Object {
        $_.userType -ne 'Guest' -and (
            ($_.userPrincipalName -match $Option.BreakGlassPattern) -or ($_.displayName -match $Option.BreakGlassPattern))
    }
}
