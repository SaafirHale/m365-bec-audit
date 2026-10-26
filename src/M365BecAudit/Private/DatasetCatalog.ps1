# Every piece of tenant data the audit reads, where it comes from, and what it
# costs in permissions. Collectors (live or fixture) are driven from this list,
# so it is also the single source of truth for the README permission table and
# the read-only scope test.
#
# Fields:
#   Name             dataset key; also the fixture file name (<Name>.json)
#   Source           Graph | Exchange
#   Kind             Collection (array) | Object (single object)
#   Request          the Graph endpoint or Exchange cmdlet, for documentation
#   LeastPrivileged  least-privileged permission Microsoft documents for the call
#   Permission       what this tool requests to cover it (Graph scopes only)
#   Fetch            scriptblock used by the live collector; receives the
#                    datasets collected so far

function Get-AuditDatasetCatalog {
    [CmdletBinding()]
    param()

    @(
        @{
            Name = 'organization'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/organization'
            LeastPrivileged = 'Organization.Read.All'; Permission = 'Directory.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/organization?$select=id,displayName,verifiedDomains' }
        }
        @{
            Name = 'users'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/users (with signInActivity)'
            LeastPrivileged = 'User.Read.All + AuditLog.Read.All (signInActivity)'; Permission = 'Directory.Read.All, AuditLog.Read.All'
            Fetch = {
                param($Collected)
                $select = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,externalUserState,externalUserStateChangeDateTime'
                try {
                    # signInActivity needs Entra ID P1/P2; page size is capped at 500 when it is selected.
                    Invoke-AuditGraphGet -Uri "/v1.0/users?`$select=$select,signInActivity&`$top=500"
                }
                catch {
                    Write-Warning "signInActivity unavailable ($($_.Exception.Message)). Collecting users without sign-in data; stale-guest analysis falls back to creation dates."
                    Invoke-AuditGraphGet -Uri "/v1.0/users?`$select=$select&`$top=999"
                }
            }
        }
        @{
            Name = 'userRegistrationDetails'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/reports/authenticationMethods/userRegistrationDetails'
            LeastPrivileged = 'AuditLog.Read.All'; Permission = 'AuditLog.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/reports/authenticationMethods/userRegistrationDetails' }
        }
        @{
            Name = 'conditionalAccessPolicies'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/identity/conditionalAccess/policies'
            LeastPrivileged = 'Policy.Read.All'; Permission = 'Policy.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/identity/conditionalAccess/policies' }
        }
        @{
            Name = 'securityDefaults'; Source = 'Graph'; Kind = 'Object'
            Request = 'GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
            LeastPrivileged = 'Policy.Read.All'; Permission = 'Policy.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -Single }
        }
        @{
            Name = 'authorizationPolicy'; Source = 'Graph'; Kind = 'Object'
            Request = 'GET /v1.0/policies/authorizationPolicy'
            LeastPrivileged = 'Policy.Read.All'; Permission = 'Policy.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/policies/authorizationPolicy' -Single }
        }
        @{
            Name = 'adminConsentRequestPolicy'; Source = 'Graph'; Kind = 'Object'
            Request = 'GET /v1.0/policies/adminConsentRequestPolicy'
            LeastPrivileged = 'Policy.Read.All'; Permission = 'Policy.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/policies/adminConsentRequestPolicy' -Single }
        }
        @{
            Name = 'roleAssignments'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/roleManagement/directory/roleAssignments (filtered per privileged role, principal expanded)'
            LeastPrivileged = 'RoleManagement.Read.Directory'; Permission = 'RoleManagement.Read.Directory'
            Fetch = {
                param($Collected)
                foreach ($roleId in $script:PrivilegedRoles.Keys) {
                    Invoke-AuditGraphGet -Uri "/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$roleId'&`$expand=principal"
                }
            }
        }
        @{
            Name = 'roleAssignmentScheduleInstances'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/roleManagement/directory/roleAssignmentScheduleInstances'
            LeastPrivileged = 'RoleAssignmentSchedule.Read.Directory'; Permission = 'RoleManagement.Read.Directory'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances' }
        }
        @{
            Name = 'roleEligibilityScheduleInstances'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances'
            LeastPrivileged = 'RoleEligibilitySchedule.Read.Directory'; Permission = 'RoleManagement.Read.Directory'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' }
        }
        @{
            Name = 'servicePrincipals'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/servicePrincipals'
            LeastPrivileged = 'Application.Read.All'; Permission = 'Directory.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,verifiedPublisher,publisherName&$top=999' }
        }
        @{
            Name = 'resourceServicePrincipals'; Source = 'Graph'; Kind = 'Collection'
            Request = "GET /v1.0/servicePrincipals?`$filter=appId eq '<Microsoft Graph | Exchange Online>'"
            LeastPrivileged = 'Application.Read.All'; Permission = 'Directory.Read.All'
            Fetch = {
                param($Collected)
                foreach ($appId in @($script:GraphAppId, $script:ExchangeAppId)) {
                    Invoke-AuditGraphGet -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appId,displayName,appRoles"
                }
            }
        }
        @{
            Name = 'appRoleAssignedTo'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/servicePrincipals/{resource-id}/appRoleAssignedTo (Microsoft Graph, Exchange Online)'
            LeastPrivileged = 'Application.Read.All'; Permission = 'Directory.Read.All'
            Fetch = {
                param($Collected)
                foreach ($resource in @($Collected['resourceServicePrincipals'])) {
                    Invoke-AuditGraphGet -Uri "/v1.0/servicePrincipals/$($resource.id)/appRoleAssignedTo?`$top=999"
                }
            }
        }
        @{
            Name = 'oauth2PermissionGrants'; Source = 'Graph'; Kind = 'Collection'
            Request = 'GET /v1.0/oauth2PermissionGrants'
            LeastPrivileged = 'Directory.Read.All'; Permission = 'Directory.Read.All'
            Fetch = { param($Collected) Invoke-AuditGraphGet -Uri '/v1.0/oauth2PermissionGrants' }
        }
        @{
            Name = 'exoAcceptedDomains'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-AcceptedDomain'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = {
                param($Collected)
                Get-AcceptedDomain | Select-Object @{ n = 'DomainName'; e = { [string]$_.DomainName } },
                @{ n = 'DomainType'; e = { [string]$_.DomainType } }, Default
            }
        }
        @{
            Name = 'exoMailboxes'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = {
                param($Collected)
                Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox `
                    -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward |
                    Select-Object DisplayName, UserPrincipalName, PrimarySmtpAddress, ExternalDirectoryObjectId,
                    @{ n = 'RecipientTypeDetails'; e = { [string]$_.RecipientTypeDetails } },
                    @{ n = 'ForwardingSmtpAddress'; e = { if ($_.ForwardingSmtpAddress) { [string]$_.ForwardingSmtpAddress } } },
                    @{ n = 'ForwardingAddress'; e = { if ($_.ForwardingAddress) { [string]$_.ForwardingAddress } } },
                    DeliverToMailboxAndForward
            }
        }
        @{
            Name = 'exoInboxRules'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-InboxRule -Mailbox <each mailbox> -IncludeHidden'
            LeastPrivileged = 'Exchange role containing Get-InboxRule (not Global Reader)'; Permission = $null
            Fetch = {
                param($Collected)
                # The leading comma keeps an empty or single-item list an array.
                $toStrings = { param($v) , @($v | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
                foreach ($mailbox in @($Collected['exoMailboxes'])) {
                    try {
                        $rules = Get-InboxRule -Mailbox $mailbox.PrimarySmtpAddress -IncludeHidden -ErrorAction Stop -WarningAction SilentlyContinue
                    }
                    catch {
                        Write-Warning "Get-InboxRule failed for $($mailbox.PrimarySmtpAddress): $($_.Exception.Message)"
                        continue
                    }
                    foreach ($rule in @($rules)) {
                        [pscustomobject]@{
                            MailboxOwner               = [string]$mailbox.UserPrincipalName
                            Name                       = [string]$rule.Name
                            Enabled                    = [bool]$rule.Enabled
                            Priority                   = $rule.Priority
                            From                       = & $toStrings $rule.From
                            SubjectContainsWords       = & $toStrings $rule.SubjectContainsWords
                            SubjectOrBodyContainsWords = & $toStrings $rule.SubjectOrBodyContainsWords
                            BodyContainsWords          = & $toStrings $rule.BodyContainsWords
                            ForwardTo                  = & $toStrings $rule.ForwardTo
                            ForwardAsAttachmentTo      = & $toStrings $rule.ForwardAsAttachmentTo
                            RedirectTo                 = & $toStrings $rule.RedirectTo
                            DeleteMessage              = [bool]$rule.DeleteMessage
                            SoftDeleteMessage          = [bool]$rule.SoftDeleteMessage
                            MoveToFolder               = if ($rule.MoveToFolder) { [string]$rule.MoveToFolder } else { $null }
                            MarkAsRead                 = [bool]$rule.MarkAsRead
                            StopProcessingRules        = [bool]$rule.StopProcessingRules
                        }
                    }
                }
            }
        }
        @{
            Name = 'exoOutboundSpamPolicies'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-HostedOutboundSpamFilterPolicy'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = {
                param($Collected)
                Get-HostedOutboundSpamFilterPolicy | Select-Object @{ n = 'Name'; e = { [string]$_.Name } }, IsDefault,
                @{ n = 'AutoForwardingMode'; e = { [string]$_.AutoForwardingMode } }
            }
        }
        @{
            Name = 'exoOutboundSpamRules'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-HostedOutboundSpamFilterRule'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = {
                param($Collected)
                Get-HostedOutboundSpamFilterRule | Select-Object @{ n = 'Name'; e = { [string]$_.Name } },
                @{ n = 'HostedOutboundSpamFilterPolicy'; e = { [string]$_.HostedOutboundSpamFilterPolicy } },
                @{ n = 'State'; e = { [string]$_.State } }, Priority,
                @{ n = 'From'; e = { @($_.From | ForEach-Object { [string]$_ }) } },
                @{ n = 'FromMemberOf'; e = { @($_.FromMemberOf | ForEach-Object { [string]$_ }) } },
                @{ n = 'SenderDomainIs'; e = { @($_.SenderDomainIs | ForEach-Object { [string]$_ }) } }
            }
        }
        @{
            Name = 'exoRemoteDomains'; Source = 'Exchange'; Kind = 'Collection'
            Request = 'Get-RemoteDomain'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = {
                param($Collected)
                Get-RemoteDomain | Select-Object @{ n = 'Name'; e = { [string]$_.Name } },
                @{ n = 'DomainName'; e = { [string]$_.DomainName } }, AutoForwardEnabled
            }
        }
        @{
            Name = 'exoAdminAuditLogConfig'; Source = 'Exchange'; Kind = 'Object'
            Request = 'Get-AdminAuditLogConfig (Exchange Online PowerShell, not Security & Compliance)'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = { param($Collected) Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled }
        }
        @{
            Name = 'exoOrganizationConfig'; Source = 'Exchange'; Kind = 'Object'
            Request = 'Get-OrganizationConfig'
            LeastPrivileged = 'Exchange Online read role'; Permission = $null
            Fetch = { param($Collected) Get-OrganizationConfig | Select-Object AuditDisabled }
        }
    )
}
