# The checks, their metadata, and the engine that runs them against a snapshot.
#
# Each check function takes -Snapshot and -Option and returns New-CheckResult.
# The engine turns that into a finding, and marks the check NotAssessed when a
# required dataset is missing (for example a tenant without Entra ID P2 has no
# PIM data) instead of guessing.

function Get-AuditCheckDefinition {
    [CmdletBinding()]
    param()

    $learn = 'https://learn.microsoft.com/en-us'
    @(
        [pscustomobject]@{
            Id = 'BEC-MFA-01'; Category = 'Identity'; Severity = 'High'
            Title = 'Users without MFA registered'
            Function = 'Test-BecUserMfaRegistration'
            Requires = @('userRegistrationDetails', 'users')
            Remediation = 'Require MFA registration for every member (security defaults, or a Conditional Access policy requiring MFA for all users), and use the registration campaign to move users to Microsoft Authenticator or passkeys. Accounts that never register should be investigated or disabled.'
            References = @(
                @{ Title = 'Require MFA for all users with Conditional Access'; Url = "$learn/entra/identity/conditional-access/policy-all-users-mfa-strength" }
                @{ Title = 'Combined security information registration'; Url = "$learn/entra/identity/authentication/howto-registration-mfa-sspr-combined" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-MFA-02'; Category = 'Identity'; Severity = 'High'
            Title = 'Admins without phishing-resistant MFA'
            Function = 'Test-BecAdminPhishingResistantMfa'
            Requires = @('userRegistrationDetails', 'roleAssignments')
            Remediation = 'Register a FIDO2 security key, passkey or Windows Hello for Business for every privileged account, then enforce it with a Conditional Access policy that requires the Phishing-resistant MFA authentication strength for admin roles.'
            References = @(
                @{ Title = 'Require phishing-resistant MFA for administrators'; Url = "$learn/entra/identity/conditional-access/policy-admin-phish-resistant-mfa" }
                @{ Title = 'Conditional Access authentication strengths'; Url = "$learn/entra/identity/authentication/concept-authentication-strengths" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-CA-01'; Category = 'Conditional Access'; Severity = 'High'
            Title = 'Legacy authentication not blocked'
            Function = 'Test-BecLegacyAuthBlocked'
            Requires = @('conditionalAccessPolicies', 'securityDefaults')
            Remediation = "Create (or enable) a Conditional Access policy for all users and all cloud apps with client apps 'Exchange ActiveSync clients' and 'Other clients' and grant control Block. Run it in report-only first to find remaining legacy clients."
            References = @(
                @{ Title = 'Block legacy authentication with Conditional Access'; Url = "$learn/entra/identity/conditional-access/policy-block-legacy-authentication" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-CA-02'; Category = 'Conditional Access'; Severity = 'High'
            Title = 'Security defaults vs Conditional Access coverage'
            Function = 'Test-BecBaselineCoverage'
            Requires = @('conditionalAccessPolicies', 'securityDefaults')
            Remediation = 'Either enable security defaults, or (with Entra ID P1) enforce a Conditional Access policy requiring MFA for all users on all cloud apps, excluding only the emergency access accounts. Review every other exclusion.'
            References = @(
                @{ Title = 'Security defaults in Microsoft Entra ID'; Url = "$learn/entra/fundamentals/security-defaults" }
                @{ Title = 'Require MFA for all users with Conditional Access'; Url = "$learn/entra/identity/conditional-access/policy-all-users-mfa-strength" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-CA-03'; Category = 'Conditional Access'; Severity = 'Medium'
            Title = 'Sign-in risk and user risk policies'
            Function = 'Test-BecRiskPolicy'
            Requires = @('conditionalAccessPolicies')
            Remediation = 'With Entra ID P2, enforce a sign-in risk policy (require MFA for medium and high risk) and a user risk policy (require a secure password change for high risk).'
            References = @(
                @{ Title = 'Require MFA for elevated sign-in risk'; Url = "$learn/entra/identity/conditional-access/policy-risk-based-sign-in" }
                @{ Title = 'Require a secure password change for elevated user risk'; Url = "$learn/entra/identity/conditional-access/policy-risk-based-user" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-EXO-01'; Category = 'Exchange Online'; Severity = 'High'
            Title = 'Mailbox external forwarding'
            Function = 'Test-BecMailboxForwarding'
            Requires = @('exoMailboxes', 'exoAcceptedDomains')
            Remediation = 'Remove forwarding that is not business-approved (Set-Mailbox -ForwardingSmtpAddress $null -ForwardingAddress $null), check the owning accounts for compromise, and block external auto-forwarding in the outbound spam policy.'
            References = @(
                @{ Title = 'Control automatic external email forwarding'; Url = "$learn/defender-office-365/outbound-spam-policies-external-email-forwarding" }
                @{ Title = 'Responding to a compromised email account'; Url = "$learn/defender-office-365/responding-to-a-compromised-email-account" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-EXO-02'; Category = 'Exchange Online'; Severity = 'High'
            Title = 'Inbox rules that forward, delete or hide mail'
            Function = 'Test-BecSuspiciousInboxRule'
            Requires = @('exoInboxRules', 'exoAcceptedDomains')
            Remediation = 'Confirm each flagged rule with the mailbox owner. If they did not create it, treat the account as compromised: revoke sessions, reset the password, remove the rule, and review sign-in and audit logs for the period it existed.'
            References = @(
                @{ Title = 'Detect and remediate Outlook rules and custom forms injection'; Url = "$learn/defender-office-365/detect-and-remediate-outlook-rules-forms-attack" }
                @{ Title = 'Responding to a compromised email account'; Url = "$learn/defender-office-365/responding-to-a-compromised-email-account" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-EXO-03'; Category = 'Exchange Online'; Severity = 'High'
            Title = 'Outbound spam policy allows auto-forwarding'
            Function = 'Test-BecOutboundForwardingPolicy'
            Requires = @('exoOutboundSpamPolicies')
            Remediation = "Set AutoForwardingMode to Off on the default outbound spam policy (Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off). Allow forwarding only through a custom policy scoped to named senders, or through remote domains for named partner domains."
            References = @(
                @{ Title = 'Control automatic external email forwarding'; Url = "$learn/defender-office-365/outbound-spam-policies-external-email-forwarding" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-EXO-04'; Category = 'Exchange Online'; Severity = 'High'
            Title = 'Audit logging enabled'
            Function = 'Test-BecAuditLogging'
            Requires = @('exoAdminAuditLogConfig')
            Remediation = 'Turn on the unified audit log (Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true in Exchange Online PowerShell) and keep mailbox auditing on by default (Set-OrganizationConfig -AuditDisabled $false).'
            References = @(
                @{ Title = 'Turn auditing on or off'; Url = "$learn/purview/audit-log-enable-disable" }
                @{ Title = 'Manage mailbox auditing'; Url = "$learn/purview/audit-mailboxes" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-APP-01'; Category = 'Applications'; Severity = 'High'
            Title = 'Apps with high-risk permissions'
            Function = 'Test-BecHighRiskAppPermission'
            Requires = @('servicePrincipals', 'oauth2PermissionGrants', 'appRoleAssignedTo', 'resourceServicePrincipals')
            Remediation = 'For each flagged app, confirm the owner and business need. Revoke grants that are not needed (remove the oauth2PermissionGrant or app role assignment) and disable sign-in for apps nobody recognises.'
            References = @(
                @{ Title = 'Detect and remediate illicit consent grants'; Url = "$learn/defender-office-365/detect-and-remediate-illicit-consent-grants" }
                @{ Title = 'Review permissions granted to enterprise applications'; Url = "$learn/entra/identity/enterprise-apps/manage-application-permissions" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-APP-02'; Category = 'Applications'; Severity = 'High'
            Title = 'User consent settings'
            Function = 'Test-BecUserConsentSetting'
            Requires = @('authorizationPolicy')
            Remediation = "Restrict user consent to verified publishers and low-impact permissions (microsoft-user-default-low), or turn it off, and enable the admin consent workflow so users can request apps."
            References = @(
                @{ Title = 'Configure how users consent to applications'; Url = "$learn/entra/identity/enterprise-apps/configure-user-consent" }
                @{ Title = 'Configure the admin consent workflow'; Url = "$learn/entra/identity/enterprise-apps/configure-admin-consent-workflow" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-ROLE-01'; Category = 'Privileged access'; Severity = 'High'
            Title = 'Standing Global Administrator count'
            Function = 'Test-BecStandingGlobalAdmin'
            Requires = @('roleAssignments')
            Remediation = 'Keep fewer than five Global Administrators. Move day-to-day admins to least-privileged roles, and make the remaining Global Administrator assignments eligible through PIM, except the emergency access accounts.'
            References = @(
                @{ Title = 'Best practices for Microsoft Entra roles'; Url = "$learn/entra/identity/role-based-access-control/best-practices" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-ROLE-02'; Category = 'Privileged access'; Severity = 'Medium'
            Title = 'Privileged roles held without PIM'
            Function = 'Test-BecPrivilegedRoleWithoutPim'
            Requires = @('roleAssignments', 'roleAssignmentScheduleInstances')
            Remediation = 'Convert permanent privileged assignments to eligible assignments in Privileged Identity Management, with MFA and justification required on activation.'
            References = @(
                @{ Title = 'What is Microsoft Entra Privileged Identity Management?'; Url = "$learn/entra/id-governance/privileged-identity-management/pim-configure" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-GUEST-01'; Category = 'Identity'; Severity = 'Medium'
            Title = 'Stale guest accounts'
            Function = 'Test-BecStaleGuest'
            Requires = @('users')
            Remediation = 'Remove or disable guests that no longer need access, and schedule access reviews for guest users so stale accounts are removed automatically.'
            References = @(
                @{ Title = 'Clean up stale guest accounts using access reviews'; Url = "$learn/entra/identity/users/clean-up-stale-guest-accounts" }
                @{ Title = 'What are access reviews?'; Url = "$learn/entra/id-governance/access-reviews-overview" }
            )
        }
        [pscustomobject]@{
            Id = 'BEC-BG-01'; Category = 'Privileged access'; Severity = 'Medium'
            Title = 'Emergency access (break-glass) accounts'
            Function = 'Test-BecBreakGlassAccount'
            Requires = @('users', 'roleAssignments')
            Remediation = 'Keep two or more cloud-only *.onmicrosoft.com emergency accounts with permanent Global Administrator, phishing-resistant authentication (FIDO2 or certificate), exclusion from enforced Conditional Access policies that block or restrict sign-in, and alerts on every sign-in.'
            References = @(
                @{ Title = 'Manage emergency access accounts in Microsoft Entra ID'; Url = "$learn/entra/identity/role-based-access-control/security-emergency-access" }
            )
        }
    )
}

function Invoke-AuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] $Snapshot,
        [hashtable] $Option
    )

    $missing = @($Definition.Requires | Where-Object { -not (Test-SnapshotDataset -Snapshot $Snapshot -Name $_) })
    if ($missing.Count) {
        $why = ($missing | ForEach-Object {
                $reason = if ($Snapshot.Errors.ContainsKey($_)) { $Snapshot.Errors[$_] } else { 'not collected' }
                "$_ ($reason)"
            }) -join '; '
        $result = New-CheckResult -Status NotAssessed -Summary "Not assessed: required data unavailable: $why"
    }
    else {
        try {
            $result = & $Definition.Function -Snapshot $Snapshot -Option $Option
        }
        catch {
            $result = New-CheckResult -Status Error -Summary "The check failed: $($_.Exception.Message)"
        }
    }

    $severity = if ($result.Severity) { $result.Severity } else { $Definition.Severity }
    [pscustomobject]@{
        PSTypeName  = 'M365BecAudit.Finding'
        Id          = $Definition.Id
        Title       = $Definition.Title
        Category    = $Definition.Category
        Status      = $result.Status
        Severity    = $severity
        Summary     = $result.Summary
        Evidence    = @($result.Evidence)
        Remediation = $Definition.Remediation
        References  = @($Definition.References | ForEach-Object { [pscustomobject]$_ })
    }
}
