function Show-M365BecAuditSummary {
    <#
    .SYNOPSIS
        Prints a colour-coded summary of the findings to the console.
    .EXAMPLE
        $findings | Show-M365BecAuditSummary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object[]] $Finding,
        [string] $TenantName
    )

    begin { $all = New-Object System.Collections.Generic.List[object] }
    process { foreach ($f in $Finding) { $all.Add($f) } }
    end {
        $colour = @{ Fail = 'Red'; Warn = 'Yellow'; Pass = 'Green'; NotAssessed = 'DarkGray'; Error = 'Magenta' }
        $label = @{ Fail = 'FAIL'; Warn = 'WARN'; Pass = 'PASS'; NotAssessed = 'N/A '; Error = 'ERR ' }
        $summary = Get-AuditSummary -Finding $all.ToArray()

        Write-Host ''
        $title = if ($TenantName) { "M365 BEC audit - $TenantName" } else { 'M365 BEC audit' }
        Write-Host $title -ForegroundColor Cyan
        Write-Host ('-' * $title.Length) -ForegroundColor Cyan
        foreach ($f in Get-SortedFinding -Finding $all.ToArray()) {
            Write-Host ('[{0}] ' -f $label[$f.Status]) -ForegroundColor $colour[$f.Status] -NoNewline
            Write-Host ('{0,-9} {1,-13} {2}' -f $f.Severity, $f.Id, $f.Title)
        }
        Write-Host ''
        Write-Host ("{0} checks: {1} fail ({2} critical, {3} high), {4} warn, {5} pass, {6} not assessed" -f
            $summary.Total, $summary.Fail, $summary.Critical, $summary.High, $summary.Warn, $summary.Pass, $summary.NotAssessed)
    }
}
