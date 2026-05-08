param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 1
}

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if (-not $dumpbin) {
    Write-Error "dumpbin.exe is required for dependency verification"
    exit 1
}

$output = & $dumpbin.Source /DEPENDENTS $BinaryPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "dumpbin /DEPENDENTS failed for $BinaryPath"
    $output | Out-String | Write-Host
    exit 1
}

$blockedDeps = @(
    "libsodium.dll",
    "pthreadVC3.dll",
    "vcruntime140.dll",
    "msvcp140.dll"
)

foreach ($dep in $blockedDeps) {
    if ($output -match [regex]::Escape($dep)) {
        Write-Error "Unexpected runtime dependency detected: $dep"
        $output | Out-String | Write-Host
        exit 1
    }
}

Write-Host "Windows dependency verification passed for $BinaryPath"
