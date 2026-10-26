function Save-M365BecAuditSnapshot {
    <#
    .SYNOPSIS
        Writes a snapshot to disk in the fixture format, so a live collection can
        be replayed offline with Get-M365BecAuditSnapshot -FixturePath.
    .DESCRIPTION
        The recording contains real tenant data (names, addresses, app grants).
        Store it as you would any other sensitive export, and never commit a
        recording of a real tenant to source control.
    .EXAMPLE
        Get-M365BecAuditSnapshot -Live | Save-M365BecAuditSnapshot -Path .\recordings\2026-10-26
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Snapshot,
        [Parameter(Mandatory)] [string] $Path
    )

    process {
        if (-not $PSCmdlet.ShouldProcess($Path, 'Write tenant snapshot')) { return }
        $null = New-Item -ItemType Directory -Path $Path -Force
        $catalog = @{}
        foreach ($d in Get-AuditDatasetCatalog) { $catalog[$d.Name] = $d }

        foreach ($name in $Snapshot.Datasets.Keys) {
            $data = $Snapshot.Datasets[$name]
            $document = if ($catalog[$name].Kind -eq 'Collection') { [ordered]@{ value = @($data) } } else { $data }
            Write-Utf8File -Path (Join-Path -Path $Path -ChildPath "$name.json") -Content ($document | ConvertTo-Json -Depth 20)
        }
        Write-Utf8File -Path (Join-Path -Path $Path -ChildPath '_meta.json') -Content ($Snapshot.Meta | ConvertTo-Json -Depth 5)
        if ($Snapshot.Errors.Count) {
            Write-Utf8File -Path (Join-Path -Path $Path -ChildPath '_errors.json') -Content ($Snapshot.Errors | ConvertTo-Json -Depth 5)
        }
        Get-Item -LiteralPath $Path
    }
}
