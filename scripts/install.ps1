#requires -Version 5.1
<#
.SYNOPSIS
    One-line installer for tox-tcp-tunnel on Windows.

.DESCRIPTION
    Downloads the latest MSI from GitHub Releases, installs silently, seeds
    C:\ProgramData\ToxTunnel\config.yaml (the MSI does not seed it on its own),
    and (re)starts the ToxTunnel SCM service.

    For -Mode client, writes a client scaffold and leaves the service idled
    (exit 0) until the user fills in client.server_id and flips
    service.allow_client_daemon to true.

.PARAMETER Mode
    server (default) or client.

.PARAMETER Version
    latest (default) or vX.Y.Z.

.PARAMETER Repo
    GitHub owner/repo. Default: agentx-icu/tox-tcp-tunnel.

.EXAMPLE
    # Server install (default mode)
    irm https://raw.githubusercontent.com/agentx-icu/tox-tcp-tunnel/master/scripts/install.ps1 | iex

.EXAMPLE
    # Client install (env var works around `iex` not passing args)
    $env:TOXTUNNEL_MODE = 'client'; irm https://raw.githubusercontent.com/agentx-icu/tox-tcp-tunnel/master/scripts/install.ps1 | iex

.EXAMPLE
    # Local file (when not piping from raw.githubusercontent.com)
    powershell -ExecutionPolicy Bypass -File install.ps1 -Mode client
#>
[CmdletBinding()]
param(
    # NOTE: do NOT add [ValidateSet] here. The script is documented to be invoked
    # as `irm <url> | iex`, which executes the content as a script block. In that
    # mode PowerShell initializes [string]$Mode to '' before our env-var fallback
    # runs, and [ValidateSet] rejects the empty string at param-binding time,
    # breaking the documented one-liner. The manual check below provides the
    # equivalent validation without the early-binding hazard.
    [string]$Mode,
    [string]$Version,
    [string]$Repo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Mode)    { $Mode    = if ($env:TOXTUNNEL_MODE)    { $env:TOXTUNNEL_MODE }    else { 'server' } }
if (-not $Version) { $Version = if ($env:TOXTUNNEL_VERSION) { $env:TOXTUNNEL_VERSION } else { 'latest' } }
if (-not $Repo)    { $Repo    = if ($env:TOXTUNNEL_REPO)    { $env:TOXTUNNEL_REPO }    else { 'agentx-icu/tox-tcp-tunnel' } }

if ($Mode -notin 'server','client') {
    throw "Invalid -Mode: '$Mode' (expected 'server' or 'client')"
}

# Require Administrator
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This installer must run as Administrator. Open PowerShell as admin and re-run."
}

# Detect arch
$archEnv = $env:PROCESSOR_ARCHITECTURE
switch ($archEnv) {
    'AMD64' { $archName = 'AMD64' }
    'ARM64' { $archName = 'ARM64' }
    default { throw "Unsupported architecture: $archEnv" }
}

# Build URL
if ($Version -eq 'latest') {
    $url = "https://github.com/$Repo/releases/latest/download/toxtunnel-Windows-$archName-latest.msi"
} else {
    $verNum = $Version -replace '^v',''
    $url = "https://github.com/$Repo/releases/download/$Version/toxtunnel-$verNum-Windows-$archName.msi"
}

# Download
$tmp = Join-Path $env:TEMP "toxtunnel-installer-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$msi = Join-Path $tmp 'toxtunnel.msi'
$log = Join-Path $tmp 'install.log'

Write-Host "==> Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

# Install MSI silently
Write-Host "==> Installing $msi"
$proc = Start-Process -FilePath 'msiexec.exe' `
    -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/L*v', "`"$log`"") `
    -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    throw "msiexec failed with exit code $($proc.ExitCode). See log: $log"
}

# Seed config (the MSI does not write a default config)
$configDir  = 'C:\ProgramData\ToxTunnel'
$configPath = Join-Path $configDir 'config.yaml'
$dataDir    = Join-Path $configDir 'data'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
New-Item -ItemType Directory -Path $dataDir   -Force | Out-Null

$serverYaml = @"
mode: server
data_dir: C:\ProgramData\ToxTunnel\data

service:
  auto_start: true
  allow_client_daemon: false

logging:
  level: info

tox:
  udp_enabled: true
  tcp_port: 33445
  bootstrap_mode: auto
  # Fallback bootstrap nodes — used in addition to https://nodes.tox.chat/json,
  # which can be intermittent from VMs/restricted networks. Delete this block
  # if you only want the live list.
  bootstrap_nodes:
    - address: 172.105.109.31
      port: 33445
      public_key: D46E97CF995DC1820B92B7D899E152A217D36ABE22730FEA4B6BF1BFC06C617C
    - address: 144.217.167.73
      port: 33445
      public_key: 7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C
    - address: 3.0.24.15
      port: 33445
      public_key: E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D
    - address: 205.185.115.131
      port: 53
      public_key: 3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68

server:
  # Add access-control settings (rules_file: ...) here to restrict what
  # friends can reach.
"@

$clientYaml = @"
mode: client
data_dir: C:\ProgramData\ToxTunnel\data

service:
  # The system service exits 0 immediately while allow_client_daemon is false,
  # so it never silently binds local forward ports. After you fill in
  # client.server_id and forwards below, set allow_client_daemon: true (and
  # optionally auto_start: true) and restart the service.
  auto_start: false
  allow_client_daemon: false

logging:
  level: info

tox:
  udp_enabled: true
  bootstrap_mode: auto

client:
  # Paste the server's 76-character Tox ID. Get it on the server with:
  #   & 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' print-id --qr
  server_id: REPLACE_WITH_SERVER_TOX_ID
  forwards:
    - local_port: 2222
      remote_host: 127.0.0.1
      remote_port: 22
"@

# Inspect the existing config so we don't blindly overwrite a custom file.
# Note the limited protection: we only refuse to overwrite when `mode:` is
# unrecognized. If the file looks like the seeded server template (or the
# seeded client template), `--Mode` switching it to the OPPOSITE mode WILL
# overwrite it, including any in-place customisations the user added (e.g.
# rules_file, forwards). That's symmetric with scripts/install.sh and is a
# deliberate trade-off — re-running the installer with a different --Mode is
# treated as "give me the canonical template for that mode". Customise after.
$existingMode = $null
if (Test-Path $configPath) {
    $modeLine = Get-Content $configPath | Where-Object { $_ -match '^mode:\s*(\w+)' } | Select-Object -First 1
    if ($modeLine -and $modeLine -match '^mode:\s*(\w+)') {
        $existingMode = $Matches[1]
    }
}

if ($existingMode -eq $Mode) {
    Write-Host "==> $configPath already in $Mode mode — leaving as-is."
} elseif ($existingMode -and $existingMode -notin 'server','client') {
    Write-Warning "$configPath exists with unrecognized mode '$existingMode'; not overwriting. Edit it manually to switch."
} else {
    if ($existingMode) {
        # Warn loudly BEFORE writing — switching --Mode is documented as
        # destructive (replaces in-place customisations with the canonical
        # template for the other mode).
        Write-Warning ""
        Write-Warning "$configPath is currently in '$existingMode' mode."
        Write-Warning "About to OVERWRITE it with the canonical '$Mode' template."
        Write-Warning "Any in-place customisations (rules_file, forwards, …) WILL be lost."
        Write-Warning "(Press Ctrl-C now to abort.)"
        Write-Warning ""
    }
    Write-Host "==> Writing $Mode config at $configPath"
    if ($Mode -eq 'server') {
        $serverYaml | Set-Content -Path $configPath -Encoding ascii
    } else {
        $clientYaml | Set-Content -Path $configPath -Encoding ascii
    }
}

# Restart service so it picks up the (possibly new) config.
# Use Start-Process for stop so we can swallow the "service already stopped" error.
Write-Host "==> Restarting ToxTunnel service"
& sc.exe stop ToxTunnel | Out-Null
Start-Sleep -Seconds 1
& sc.exe start ToxTunnel | Out-Null

Write-Host ""
Write-Host "==> Installed."
Write-Host "    binary:  C:\Program Files\ToxTunnel\bin\toxtunnel.exe"
Write-Host "    config:  $configPath"
Write-Host "    mode:    $Mode"
Write-Host ""
if ($Mode -eq 'server') {
    Write-Host "Next steps (server):"
    Write-Host "  - Get your Tox ID:"
    Write-Host "      & 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' print-id --qr"
    Write-Host "  - Hand the printed Tox ID (or QR code) to the client side."
    Write-Host "  - Optional: tighten access with rules_file in $configPath."
} else {
    Write-Host "Next steps (client):"
    Write-Host "  - Edit $configPath :"
    Write-Host "      * client.server_id: <76-char Tox ID from your server>"
    Write-Host "      * client.forwards:  adjust local_port / remote_host / remote_port"
    Write-Host "  - Then enable the daemon:"
    Write-Host "      * service.allow_client_daemon: true   (required to bind local ports)"
    Write-Host "      * service.auto_start: true            (optional, for auto-start on boot)"
    Write-Host "  - Apply changes:"
    Write-Host "      sc stop ToxTunnel; sc start ToxTunnel"
    Write-Host "  - Or run client in the foreground:"
    Write-Host "      & 'C:\Program Files\ToxTunnel\bin\toxtunnel.exe' -c '$configPath'"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
