#requires -Version 5.1
<#
.SYNOPSIS
    Verify the CPack-generated Windows MSI registers the ToxTunnel service.

.DESCRIPTION
    The packaging plan requires the MSI to register *and* start the ToxTunnel
    Windows service so packaged installs match Linux postinst (`systemctl
    enable --now`) behavior. The service registration is injected via
    packaging/windows/wix-service-patch.xml, which targets a CPack-generated
    Component Id (`CM_CP_bin.toxtunnel.exe`). If CPack/WiX is upgraded or the
    install path changes, the patch may silently no-op (the CPack patch
    mechanism does not fail when a target component id is missing). This
    script catches that regression by inspecting CPack's intermediate .wxs
    output AND, when WiX `dark.exe` is available, the final MSI itself.

.PARAMETER MsiPath
    Path to the generated .msi.

.PARAMETER CPackBuildDir
    The CMake build directory where `cpack -G WIX` ran. Used to locate
    `_CPack_Packages/<arch>/WIX/*.wxs` intermediate files.

.EXAMPLE
    pwsh tests/packaging/verify_windows_msi.ps1 `
        -MsiPath build/toxtunnel-1.2.3-win64.msi `
        -CPackBuildDir build
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,

    [Parameter(Mandatory = $true)]
    [string]$CPackBuildDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $MsiPath)) {
    throw "MSI not found: $MsiPath"
}
if (-not (Test-Path $CPackBuildDir)) {
    throw "CPack build dir not found: $CPackBuildDir"
}

# 1. Inspect CPack intermediate .wxs files. CPack emits files.wxs (auto-generated
#    component graph) plus any patches it accepted. Our service ServiceInstall +
#    ServiceControl elements must appear there if the CPACK_WIX_PATCH_FILE was
#    actually applied to a real component. If the Component Id in
#    wix-service-patch.xml stops matching CPack's generated ids (e.g. CPack
#    upgrade changes the sanitization rule), the patch becomes a no-op and the
#    MSI installs the binary but does NOT register the service.
$wxsFiles = Get-ChildItem -Path $CPackBuildDir -Recurse -Filter "*.wxs" -ErrorAction SilentlyContinue
if (-not $wxsFiles) {
    throw "No CPack intermediate .wxs files found under $CPackBuildDir/_CPack_Packages. Did `cpack -G WIX` run?"
}

$serviceInstallFound = $false
$serviceControlFound = $false
$serviceControlStartInstallFound = $false
foreach ($wxs in $wxsFiles) {
    $content = Get-Content -Raw -Path $wxs.FullName
    if ($content -match 'ServiceInstall[^>]*Name="ToxTunnel"') {
        $serviceInstallFound = $true
        Write-Host "  found ServiceInstall in $($wxs.FullName)"
    }
    if ($content -match 'ServiceControl[^>]*Name="ToxTunnel"') {
        $serviceControlFound = $true
        Write-Host "  found ServiceControl in $($wxs.FullName)"
    }
    if ($content -match 'ServiceControl[^>]*Name="ToxTunnel"[^>]*Start="install"' -or
        $content -match 'ServiceControl[^>]*Start="install"[^>]*Name="ToxTunnel"') {
        $serviceControlStartInstallFound = $true
        Write-Host "  found ServiceControl Start=`"install`" in $($wxs.FullName)"
    }
}

if (-not $serviceInstallFound) {
    throw @"
CPack WiX intermediate output is missing <ServiceInstall Name="ToxTunnel" .../>.
This usually means packaging/windows/wix-service-patch.xml's CPackWiXFragment
Id no longer matches the Component Id CPack generates for bin/toxtunnel.exe.
Inspect the .wxs files under $CPackBuildDir/_CPack_Packages/.../WIX/ for the
actual Component Id (e.g. `Get-ChildItem -Recurse -Filter *.wxs | Select-String 'toxtunnel.exe'`)
and update wix-service-patch.xml accordingly.
"@
}

if (-not $serviceControlFound) {
    throw "CPack WiX intermediate output is missing <ServiceControl Name=`"ToxTunnel`" .../> — install/uninstall lifecycle will be wrong."
}

if (-not $serviceControlStartInstallFound) {
    throw @"
CPack WiX intermediate output is missing ServiceControl Start="install" for ToxTunnel.
That means MSI will register the service but will not attempt to start it during install,
which violates the packaging policy ("install -> service registered AND started").
"@
}

# 2. Best-effort: if WiX dark.exe is on PATH, decompile the MSI and re-check.
#    dark.exe ships with WiX Toolset; CI installs it for the cpack step.
$dark = Get-Command "dark.exe" -ErrorAction SilentlyContinue
if ($dark) {
    $tmpDir = Join-Path $env:RUNNER_TEMP "toxtunnel-msi-decompile"
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
    New-Item -ItemType Directory -Path $tmpDir | Out-Null
    $decompiled = Join-Path $tmpDir "decompiled.wxs"
    & $dark.Source -nologo -o $decompiled $MsiPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "dark.exe failed to decompile MSI (exit $LASTEXITCODE); skipping MSI-side check."
    } else {
        $decContent = Get-Content -Raw -Path $decompiled
        if ($decContent -notmatch 'ServiceInstall[^>]*Name="ToxTunnel"') {
            throw "Final MSI does not contain <ServiceInstall Name=`"ToxTunnel`" .../> — wix-service-patch.xml was not applied to the shipped artifact."
        }
        if (($decContent -notmatch 'ServiceControl[^>]*Name="ToxTunnel"[^>]*Start="install"') -and
            ($decContent -notmatch 'ServiceControl[^>]*Start="install"[^>]*Name="ToxTunnel"')) {
            throw "Final MSI does not contain <ServiceControl Name=`"ToxTunnel`" Start=`"install`" .../> — install-time start policy is missing."
        }
        Write-Host "  verified ServiceInstall in decompiled MSI: $decompiled"
    }
} else {
    Write-Host "  (dark.exe not on PATH; skipping MSI decompile cross-check)"
}

Write-Host "OK: ToxTunnel service registration is present in MSI ($MsiPath)."
