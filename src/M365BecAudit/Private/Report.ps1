# Report rendering: a self-contained HTML page (no external assets, no script)
# and a JSON document. Every tenant-derived string is HTML-encoded, since inbox
# rule names, app names and display names can be chosen by an attacker.

$script:ModuleVersion = '0.1.0'

function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $(if ($Value) { 'yes' } else { 'no' }) }
    if ($Value -is [array]) { $Value = ($Value | ForEach-Object { [string]$_ }) -join ', ' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SortedFinding {
    [CmdletBinding()]
    param([object[]]$Finding)

    $Finding | Sort-Object @{ e = { $script:StatusRank[$_.Status] } },
    @{ e = { $script:SeverityRank[$_.Severity] }; Descending = $true }, Id
}

function Get-AuditSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([object[]]$Finding)

    $failing = @($Finding | Where-Object { $_.Status -eq 'Fail' })
    [pscustomobject]@{
        Total       = @($Finding).Count
        Fail        = $failing.Count
        Warn        = @($Finding | Where-Object { $_.Status -eq 'Warn' }).Count
        Pass        = @($Finding | Where-Object { $_.Status -eq 'Pass' }).Count
        NotAssessed = @($Finding | Where-Object { $_.Status -in @('NotAssessed', 'Error') }).Count
        Critical    = @($failing | Where-Object { $_.Severity -eq 'Critical' }).Count
        High        = @($failing | Where-Object { $_.Severity -eq 'High' }).Count
        Medium      = @($failing | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low         = @($failing | Where-Object { $_.Severity -eq 'Low' }).Count
    }
}

function ConvertTo-EvidenceTable {
    [CmdletBinding()]
    [OutputType([string])]
    param([object[]]$Evidence)

    $rows = @($Evidence | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return '' }
    $columns = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
        foreach ($p in $row.PSObject.Properties) { if (-not $columns.Contains($p.Name)) { $columns.Add($p.Name) } }
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($c in $columns) { [void]$sb.Append("<th>$(ConvertTo-HtmlText $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $columns) {
            $value = $row.$c
            $class = if ($c -in @('Risk', 'Severity') -and $value) { " class=""sev-text sev-$(([string]$value).ToLowerInvariant())""" } else { '' }
            [void]$sb.Append("<td$class>$(ConvertTo-HtmlText $value)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}

function ConvertTo-AuditHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Finding,
        [Parameter(Mandatory)] $Snapshot
    )

    $sorted = @(Get-SortedFinding -Finding $Finding)
    $summary = Get-AuditSummary -Finding $Finding
    $meta = $Snapshot.Meta
    $tenant = if ($meta.tenantName) { $meta.tenantName } else { 'Unknown tenant' }
    $collected = ConvertTo-AuditDate -Value $meta.collectedAt
    $collectedText = if ($collected) { $collected.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { 'unknown' }
    $statusLabel = @{ Fail = 'Fail'; Warn = 'Warning'; Pass = 'Pass'; NotAssessed = 'Not assessed'; Error = 'Error' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
'@)
    [void]$sb.Append("<title>BEC Audit - $(ConvertTo-HtmlText $tenant)</title>")
    [void]$sb.Append(@'
<style>
:root {
  --bg: #f6f7f9; --surface: #ffffff; --text: #1b1f24; --muted: #5b6470; --border: #dde1e6;
  --fail: #b42318; --fail-bg: #fde8e7; --warn: #8a5a00; --warn-bg: #fdf1d8;
  --pass: #1d6b3a; --pass-bg: #e3f4e8; --na: #4b5563; --na-bg: #eceef1;
  --critical: #8e1b10; --high: #c2410c; --medium: #a16207; --low: #2563eb; --info: #4b5563;
  --accent: #1f4fd1; --code: #eef1f5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --surface: #171b21; --text: #e6e9ee; --muted: #9aa4b1; --border: #2a3039;
    --fail: #ff8a80; --fail-bg: #3a1714; --warn: #f5c26b; --warn-bg: #352812;
    --pass: #7ad69a; --pass-bg: #14301f; --na: #b6bec9; --na-bg: #23282f;
    --critical: #ff8a80; --high: #ffab70; --medium: #f5c26b; --low: #93b4ff; --info: #b6bec9;
    --accent: #93b4ff; --code: #222831;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif; }
main { max-width: 1080px; margin: 0 auto; padding: 32px 16px 64px; }
header h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
header .sub { color: var(--muted); margin: 0; }
.meta { display: flex; flex-wrap: wrap; gap: 6px 20px; margin: 14px 0 0; padding: 0; list-style: none; color: var(--muted); font-size: 13px; }
.meta b { color: var(--text); font-weight: 600; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 28px 0; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.tile .n { font-size: 30px; font-weight: 700; line-height: 1.1; }
.tile .l { color: var(--muted); font-size: 13px; }
.tile.fail .n { color: var(--fail); } .tile.warn .n { color: var(--warn); }
.tile.pass .n { color: var(--pass); } .tile.na .n { color: var(--na); }
.sevline { font-size: 13px; color: var(--muted); margin: -12px 0 28px; }
.sevline span { margin-right: 14px; }
h2 { font-size: 18px; margin: 36px 0 12px; }
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
td a { color: var(--accent); text-decoration: none; } td a:hover { text-decoration: underline; }
.chip { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.st-fail { color: var(--fail); background: var(--fail-bg); } .st-warn { color: var(--warn); background: var(--warn-bg); }
.st-pass { color: var(--pass); background: var(--pass-bg); } .st-notassessed, .st-error { color: var(--na); background: var(--na-bg); }
.sev-text { font-weight: 600; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); } .sev-medium { color: var(--medium); }
.sev-low { color: var(--low); } .sev-info { color: var(--info); }
.finding { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--na); border-radius: 10px; padding: 18px 20px; margin: 0 0 16px; }
.finding.fail { border-left-color: var(--fail); } .finding.warn { border-left-color: var(--warn); } .finding.pass { border-left-color: var(--pass); }
.finding h3 { margin: 0; font-size: 17px; }
.finding .head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 10px; }
.finding .id { font: 12px/1 ui-monospace, "Cascadia Mono", Consolas, monospace; color: var(--muted); }
.finding .cat { color: var(--muted); font-size: 13px; }
.finding p { margin: 10px 0; }
.finding .table-wrap { margin: 12px 0; }
.label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin: 14px 0 4px; }
.finding ul { margin: 4px 0 0; padding-left: 20px; }
.finding li a { color: var(--accent); }
details summary { cursor: pointer; color: var(--muted); font-size: 13px; margin-top: 8px; }
footer { color: var(--muted); font-size: 12.5px; margin-top: 40px; border-top: 1px solid var(--border); padding-top: 14px; }
@media print { .finding { break-inside: avoid; } }
</style>
</head>
<body>
<main>
'@)

    [void]$sb.Append('<header><h1>Business email compromise readiness audit</h1>')
    [void]$sb.Append("<p class=""sub"">$(ConvertTo-HtmlText $tenant)</p><ul class=""meta"">")
    if ($meta.defaultDomain) { [void]$sb.Append("<li><b>Domain</b> $(ConvertTo-HtmlText $meta.defaultDomain)</li>") }
    if ($meta.tenantId) { [void]$sb.Append("<li><b>Tenant ID</b> $(ConvertTo-HtmlText $meta.tenantId)</li>") }
    [void]$sb.Append("<li><b>Data collected</b> $(ConvertTo-HtmlText $collectedText)</li>")
    [void]$sb.Append("<li><b>Source</b> $(ConvertTo-HtmlText $meta.source)</li></ul></header>")

    [void]$sb.Append('<section class="tiles" aria-label="Summary">')
    [void]$sb.Append("<div class=""tile fail""><div class=""n"">$($summary.Fail)</div><div class=""l"">Failing checks</div></div>")
    [void]$sb.Append("<div class=""tile warn""><div class=""n"">$($summary.Warn)</div><div class=""l"">Warnings</div></div>")
    [void]$sb.Append("<div class=""tile pass""><div class=""n"">$($summary.Pass)</div><div class=""l"">Passing checks</div></div>")
    [void]$sb.Append("<div class=""tile na""><div class=""n"">$($summary.NotAssessed)</div><div class=""l"">Not assessed</div></div>")
    [void]$sb.Append('</section>')
    [void]$sb.Append("<p class=""sevline"">Failing by severity: <span class=""sev-text sev-critical"">$($summary.Critical) critical</span><span class=""sev-text sev-high"">$($summary.High) high</span><span class=""sev-text sev-medium"">$($summary.Medium) medium</span><span class=""sev-text sev-low"">$($summary.Low) low</span></p>")

    [void]$sb.Append('<h2>All checks</h2><div class="table-wrap"><table><thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Category</th><th>ID</th></tr></thead><tbody>')
    foreach ($f in $sorted) {
        $st = $f.Status.ToLowerInvariant()
        [void]$sb.Append("<tr><td><span class=""chip st-$st"">$($statusLabel[$f.Status])</span></td>")
        [void]$sb.Append("<td class=""sev-text sev-$($f.Severity.ToLowerInvariant())"">$($f.Severity)</td>")
        [void]$sb.Append("<td><a href=""#$($f.Id)"">$(ConvertTo-HtmlText $f.Title)</a></td><td>$(ConvertTo-HtmlText $f.Category)</td><td class=""id"">$($f.Id)</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div>')

    [void]$sb.Append('<h2>Findings</h2>')
    foreach ($f in $sorted) {
        $st = $f.Status.ToLowerInvariant()
        [void]$sb.Append("<section class=""finding $st"" id=""$($f.Id)""><div class=""head"">")
        [void]$sb.Append("<span class=""chip st-$st"">$($statusLabel[$f.Status])</span>")
        [void]$sb.Append("<span class=""sev-text sev-$($f.Severity.ToLowerInvariant())"">$($f.Severity)</span>")
        [void]$sb.Append("<h3>$(ConvertTo-HtmlText $f.Title)</h3><span class=""id"">$($f.Id)</span><span class=""cat"">$(ConvertTo-HtmlText $f.Category)</span></div>")
        [void]$sb.Append("<p>$(ConvertTo-HtmlText $f.Summary)</p>")
        $evidence = @($f.Evidence)
        if ($evidence.Count) {
            $table = ConvertTo-EvidenceTable -Evidence $evidence
            if ($f.Status -eq 'Pass') {
                [void]$sb.Append("<details><summary>Evidence ($($evidence.Count))</summary>$table</details>")
            }
            else {
                [void]$sb.Append("<div class=""label"">Evidence ($($evidence.Count))</div>$table")
            }
        }
        if ($f.Status -ne 'Pass') {
            [void]$sb.Append("<div class=""label"">Remediation</div><p>$(ConvertTo-HtmlText $f.Remediation)</p>")
        }
        [void]$sb.Append('<div class="label">Microsoft documentation</div><ul>')
        foreach ($r in @($f.References)) {
            [void]$sb.Append("<li><a href=""$(ConvertTo-HtmlText $r.Url)"" rel=""noopener noreferrer"">$(ConvertTo-HtmlText $r.Title)</a></li>")
        }
        [void]$sb.Append('</ul></section>')
    }

    [void]$sb.Append("<footer>Generated by M365BecAudit $script:ModuleVersion on $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)) UTC. Collection is read-only: Microsoft Graph GET requests and Exchange Online Get-* cmdlets.</footer>")
    [void]$sb.Append('</main></body></html>')
    $sb.ToString()
}

function ConvertTo-AuditJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Finding,
        [Parameter(Mandatory)] $Snapshot
    )

    $document = [ordered]@{
        tool            = 'M365BecAudit'
        version         = $script:ModuleVersion
        generatedAt     = [datetime]::UtcNow.ToString('o')
        tenant          = $Snapshot.Meta
        collectionErrors = $Snapshot.Errors
        summary         = Get-AuditSummary -Finding $Finding
        findings        = @(Get-SortedFinding -Finding $Finding | ForEach-Object {
                [ordered]@{
                    id          = $_.Id
                    title       = $_.Title
                    category    = $_.Category
                    status      = $_.Status
                    severity    = $_.Severity
                    summary     = $_.Summary
                    evidence    = @($_.Evidence)
                    remediation = $_.Remediation
                    references  = @($_.References)
                }
            })
    }
    $document | ConvertTo-Json -Depth 12
}

function Write-Utf8File {
    [CmdletBinding()]
    param([string]$Path, [string]$Content)

    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}
