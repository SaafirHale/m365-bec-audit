# Portfolio entry (draft)

Draft entry for `src/content/projects.ts` on saafirhale.com, in the shape of the site's `Project` type. Every claim below can be checked in this repository: the check list in `src/M365BecAudit/Private/CheckRegistry.ps1`, the scopes in `Get-M365BecAuditPermission`, the test count from `.\build.ps1`, the analyzer result from the same run.

Before publishing:

- Push the repository, then add the GitHub link to `links` and change `status` from `"personal"` to `"live"`.
- If the audit has been run against a real tenant by then, a sentence saying so can be added to `body`. Until then, leave it out.

```ts
{
  slug: "m365-bec-audit",
  category: "security",
  title: "Microsoft 365 BEC Exposure Audit",
  blurb:
    "Read-only PowerShell audit of a Microsoft 365 tenant for the weaknesses business email compromise depends on, with an HTML report.",
  body: [
    "A PowerShell module that audits a Microsoft 365 / Entra ID tenant for the conditions behind business email compromise. Fifteen checks cover MFA registration and phishing-resistant MFA for admins, legacy authentication, security defaults versus Conditional Access coverage, sign-in and user risk policies, external mailbox forwarding, inbox rules that forward, delete or hide mail, the outbound spam policy's auto-forwarding setting, audit logging, third-party apps holding mail or privilege-escalation permissions, user consent settings, standing Global Administrators, privileged roles held outside PIM, stale guests, and emergency access accounts.",
    "Collection is read-only by construction: four read-only Microsoft Graph scopes, GET requests only, and Exchange Online Get-* cmdlets only, each enforced by a test. Every finding carries a severity, the evidence that triggered it, remediation steps and a link to the Microsoft documentation for the fix, and the output is a console summary, a self-contained HTML report and JSON.",
    "The analysis is separated from collection. A live collector and a fixture collector both produce the same tenant snapshot, so every check runs offline against recorded JSON, and a live collection can be saved and replayed. Three synthetic tenants (one failing every check, one passing every check, one on security defaults without premium licences) back a 149-test Pester suite, and the code is clean under PSScriptAnalyzer at every severity.",
  ],
  stack: [
    "PowerShell",
    "Microsoft Graph",
    "Exchange Online PowerShell",
    "Microsoft Entra ID",
    "Conditional Access",
    "Pester",
    "PSScriptAnalyzer",
  ],
  links: [],
  status: "personal",
},
```
