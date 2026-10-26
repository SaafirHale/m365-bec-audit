function Export-M365BecAuditReport {
    <#
    .SYNOPSIS
        Writes the findings as a self-contained HTML report and a JSON document.
    .EXAMPLE
        Export-M365BecAuditReport -Finding $findings -Snapshot $snapshot -OutputPath .\out
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [object[]] $Finding,
        [Parameter(Mandatory)] $Snapshot,
        [Parameter(Mandatory)] [string] $OutputPath,
        [string] $BaseName = 'm365-bec-audit'
    )

    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Write HTML and JSON report')) { return }
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    $resolved = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $htmlPath = Join-Path -Path $resolved -ChildPath "$BaseName.html"
    $jsonPath = Join-Path -Path $resolved -ChildPath "$BaseName.json"

    Write-Utf8File -Path $htmlPath -Content (ConvertTo-AuditHtml -Finding $Finding -Snapshot $Snapshot)
    Write-Utf8File -Path $jsonPath -Content (ConvertTo-AuditJson -Finding $Finding -Snapshot $Snapshot)

    [pscustomobject]@{ Html = $htmlPath; Json = $jsonPath }
}
