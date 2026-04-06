param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$exePath = Join-Path $InstallRoot "bin\\toxtunnel.exe"
if (-not (Test-Path $exePath)) {
    throw "expected installed binary at $exePath"
}

$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $exePath
$startInfo.Arguments = "--version"
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

try {
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
} catch {
    throw "failed to start ${exePath}: $($_.Exception.Message)"
}

$stdout = $process.StandardOutput.ReadToEnd().Trim()
$stderr = $process.StandardError.ReadToEnd().Trim()
$process.WaitForExit()

if ($process.ExitCode -ne 0) {
    throw "expected exit code 0, got $($process.ExitCode). stderr: $stderr"
}

if ($stdout -ne $ExpectedVersion) {
    throw "expected version $ExpectedVersion, got '$stdout'. stderr: $stderr"
}
