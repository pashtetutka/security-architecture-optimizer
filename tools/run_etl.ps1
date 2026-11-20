param(
    [string]$Python = 'python',
    [string]$OutputDir,
    [int]$Timeout = 35,
    [int]$Retries = 2,
    [switch]$ExcludeRestrictedDocuments
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDir) {
    $runId = (Get-Date -Format yyyyMMdd_HHmmss) + '_' + ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $OutputDir = Join-Path $root "results/runs/$runId"
}
$run = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
if (Test-Path -LiteralPath $run) {
    throw "Output directory already exists: $run"
}

$manifest = Join-Path $run 'vendors.json'
$catalog = Join-Path $run 'catalog'
$crawlArgs = @(
    '-m', 'siem.etl', 'crawl', '--registry', (Join-Path $root 'data/etl/vendors.json'),
    '--output', $manifest, '--snapshot-dir', (Join-Path $run 'raw'),
    '--timeout', $Timeout, '--retries', $Retries
)
if ($ExcludeRestrictedDocuments) {
    $crawlArgs += '--exclude-restricted-documents'
}

& $Python @crawlArgs
$collectionExit = $LASTEXITCODE
if ($collectionExit -notin @(0, 3)) { exit $collectionExit }

& $Python (Join-Path $PSScriptRoot 'build_v2_bundle.py') --manifest $manifest --output-dir $catalog
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python -m siem.etl check --etl $manifest --output-dir (Join-Path $run 'report')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output "Catalog: $catalog"
Write-Output "Report: $(Join-Path $run 'report/report.html')"
exit $collectionExit
