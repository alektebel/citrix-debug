[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"

try {
    $target = [Uri]$Url
    if (-not $target.IsAbsoluteUri -or $target.Scheme -notin @("http", "https")) {
        throw "URL must be an absolute HTTP or HTTPS URL."
    }
}
catch {
    Write-Host "Invalid URL: $Url" -ForegroundColor Red
    exit 2
}

$port = if ($target.IsDefaultPort) {
    if ($target.Scheme -eq "https") { 443 } else { 80 }
} else {
    $target.Port
}

Write-Host "Citrix network test" -ForegroundColor Cyan
Write-Host "Host: $($target.DnsSafeHost)"
Write-Host "Port: $port"

try {
    $addresses = [System.Net.Dns]::GetHostAddresses($target.DnsSafeHost) |
        ForEach-Object { $_.IPAddressToString } |
        Sort-Object -Unique
    Write-Host "DNS: OK ($($addresses -join ', '))" -ForegroundColor Green
}
catch {
    Write-Host "DNS: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$client = [System.Net.Sockets.TcpClient]::new()
try {
    $task = $client.ConnectAsync($target.DnsSafeHost, $port)
    if (-not $task.Wait($TimeoutSeconds * 1000)) {
        throw "Connection timed out after $TimeoutSeconds seconds."
    }
    $null = $task.GetAwaiter().GetResult()
    Write-Host "TCP: OK ($($client.Client.RemoteEndPoint))" -ForegroundColor Green
}
catch {
    Write-Host "TCP: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    $client.Dispose()
}

Write-Host "`nWinHTTP proxy configuration:" -ForegroundColor Cyan
& netsh.exe winhttp show proxy

Write-Host "`nUser proxy environment variables:" -ForegroundColor Cyan
foreach ($name in @("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")) {
    $configured = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))
    Write-Host "${name}: $(if ($configured) { 'configured' } else { 'not configured' })"
}
