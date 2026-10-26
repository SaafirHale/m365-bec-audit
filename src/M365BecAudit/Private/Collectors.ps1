# Collectors turn a tenant (live) or a recorded snapshot directory (fixture)
# into the same in-memory snapshot. The analysis only ever sees the snapshot,
# which is why every check can be tested without a tenant.
#
# Collector contract (any object with these members works, including an
# in-memory stub in a test):
#   Kind         string, e.g. 'Fixture' or 'Live'
#   Description  string shown in the report header
#   Skip         string[] of dataset names not to collect
#   ReadMeta     { param($Collector) -> hashtable of metadata }
#   ReadDataset  { param($Collector, $Definition, $Collected) -> data; throw on failure }

function Invoke-AuditGraphGet {
    # GET-only wrapper around Invoke-MgGraphRequest that follows @odata.nextLink.
    # This is the only place the module talks to Microsoft Graph.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [switch] $Single
    )

    $results = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while ($next) {
        $json = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Json -ErrorAction Stop
        $page = $json | ConvertFrom-Json
        if ($Single) { return $page }
        foreach ($item in @($page.value)) {
            if ($null -ne $item) { $results.Add($item) }
        }
        $next = $page.'@odata.nextLink'
    }
    $results.ToArray()
}

function ConvertTo-PlainObject {
    # Round-trips through JSON so live Exchange objects have exactly the shape a
    # recorded fixture has when it is read back.
    [CmdletBinding()]
    param($InputObject)

    if ($null -eq $InputObject) { return $null }
    $InputObject | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json
}

function Get-AuditCollector {
    [CmdletBinding(DefaultParameterSetName = 'Fixture')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Fixture')] [string] $FixturePath,
        [Parameter(Mandatory, ParameterSetName = 'Live')] [switch] $Live,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipExchange,
        [Parameter(ParameterSetName = 'Live')] [switch] $SkipInboxRules
    )

    if (-not $Live) {
        $resolved = (Resolve-Path -Path $FixturePath -ErrorAction Stop).ProviderPath
        return [pscustomobject]@{
            PSTypeName  = 'M365BecAudit.Collector'
            Kind        = 'Fixture'
            Description = "Recorded snapshot: $(Split-Path -Path $resolved -Leaf)"
            Path        = $resolved
            Skip        = @()
            ReadMeta    = {
                param($Collector)
                $metaFile = Join-Path -Path $Collector.Path -ChildPath '_meta.json'
                $meta = @{}
                if (Test-Path -LiteralPath $metaFile) {
                    $raw = Get-Content -LiteralPath $metaFile -Raw | ConvertFrom-Json
                    foreach ($p in $raw.PSObject.Properties) { $meta[$p.Name] = $p.Value }
                }
                $meta
            }
            ReadDataset = {
                param($Collector, $Definition, $Collected)
                $null = $Collected
                $errorsFile = Join-Path -Path $Collector.Path -ChildPath '_errors.json'
                if (Test-Path -LiteralPath $errorsFile) {
                    $recorded = Get-Content -LiteralPath $errorsFile -Raw | ConvertFrom-Json
                    $message = $recorded.($Definition.Name)
                    if ($message) { throw "Recorded collection error: $message" }
                }
                $file = Join-Path -Path $Collector.Path -ChildPath "$($Definition.Name).json"
                if (-not (Test-Path -LiteralPath $file)) {
                    throw "Dataset '$($Definition.Name)' is not present in the snapshot."
                }
                $doc = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
                if ($Definition.Kind -eq 'Collection') { return , @($doc.value | Where-Object { $null -ne $_ }) }
                $doc
            }
        }
    }

    $skip = @()
    $catalog = Get-AuditDatasetCatalog
    if ($SkipExchange) { $skip += @($catalog | Where-Object { $_.Source -eq 'Exchange' } | ForEach-Object { $_.Name }) }
    if ($SkipInboxRules) { $skip += 'exoInboxRules' }

    [pscustomobject]@{
        PSTypeName  = 'M365BecAudit.Collector'
        Kind        = 'Live'
        Description = 'Live tenant (Microsoft Graph' + $(if ($SkipExchange) { ')' } else { ' + Exchange Online)' })
        Skip        = $skip
        ReadMeta    = {
            param($Collector)
            $null = $Collector
            $context = Get-MgContext
            @{
                collectedAt = [datetime]::UtcNow.ToString('o')
                account     = if ($context) { $context.Account } else { $null }
                tenantId    = if ($context) { $context.TenantId } else { $null }
            }
        }
        ReadDataset = {
            param($Collector, $Definition, $Collected)
            $null = $Collector
            if ($Definition.Source -eq 'Exchange' -and -not (Get-Command -Name 'Get-EXOMailbox' -ErrorAction SilentlyContinue)) {
                throw 'Exchange Online is not connected. Run Connect-M365BecAudit (or Connect-ExchangeOnline) first, or use -SkipExchange.'
            }
            $data = & $Definition.Fetch $Collected
            if ($Definition.Source -eq 'Exchange') {
                $data = @($data | ForEach-Object { ConvertTo-PlainObject -InputObject $_ })
                if ($Definition.Kind -eq 'Object') { $data = $data | Select-Object -First 1 }
            }
            if ($Definition.Kind -eq 'Collection') { return , @($data | Where-Object { $null -ne $_ }) }
            $data
        }
    }
}

function Get-TenantSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Collector)

    $datasets = @{}
    $errors = @{}
    foreach ($definition in Get-AuditDatasetCatalog) {
        if (@($Collector.Skip) -contains $definition.Name) {
            $errors[$definition.Name] = 'Skipped by request.'
            continue
        }
        Write-Verbose "Collecting $($definition.Name) ($($Collector.Kind))"
        try {
            $datasets[$definition.Name] = & $Collector.ReadDataset $Collector $definition $datasets
        }
        catch {
            $errors[$definition.Name] = $_.Exception.Message
            Write-Verbose "  failed: $($_.Exception.Message)"
        }
    }

    $meta = [ordered]@{}
    $read = & $Collector.ReadMeta $Collector
    foreach ($key in $read.Keys) { $meta[$key] = $read[$key] }
    $meta['collector'] = $Collector.Kind
    $meta['source'] = $Collector.Description

    $org = @($datasets['organization']) | Select-Object -First 1
    if ($org) {
        $meta['tenantName'] = $org.displayName
        $meta['tenantId'] = $org.id
        $default = @($org.verifiedDomains) | Where-Object { $_.isDefault } | Select-Object -First 1
        if ($default) { $meta['defaultDomain'] = $default.name }
    }
    if (-not $meta['collectedAt']) { $meta['collectedAt'] = [datetime]::UtcNow.ToString('o') }

    [pscustomobject]@{
        PSTypeName = 'M365BecAudit.Snapshot'
        Meta       = $meta
        Datasets   = $datasets
        Errors     = $errors
    }
}
