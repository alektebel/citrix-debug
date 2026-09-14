[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [string]$CerFile = "",
    [string]$Thumbprint = "",

    [ValidateSet("Auto", "CurrentUser", "LocalMachine")]
    [string]$StoreLocation = "Auto",

    [ValidateRange(1, 10000)]
    [int]$Attempts = 5,

    [ValidateRange(0, 3600)]
    [int]$IntervalSeconds = 5,

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15,

    [string]$OutputFile = ".\citrix-windows-debug.jsonl"
)

$ErrorActionPreference = "Stop"

function Get-CertificateFromStore {
    param(
        [string]$CertificateThumbprint,
        [string]$RequestedStore
    )

    $stores = switch ($RequestedStore) {
        "CurrentUser" { @(@{ Path = "Cert:\CurrentUser\My"; Curl = "CurrentUser\MY" }) }
        "LocalMachine" { @(@{ Path = "Cert:\LocalMachine\My"; Curl = "LocalMachine\MY" }) }
        default {
            @(
                @{ Path = "Cert:\CurrentUser\My"; Curl = "CurrentUser\MY" },
                @{ Path = "Cert:\LocalMachine\My"; Curl = "LocalMachine\MY" }
            )
        }
    }

    foreach ($store in $stores) {
        try {
            $certificate = Get-ChildItem -Path $store.Path |
                Where-Object Thumbprint -eq $CertificateThumbprint |
                Select-Object -First 1
            if ($certificate) {
                return [PSCustomObject]@{
                    Certificate = $certificate
                    CurlPath    = "$($store.Curl)\$CertificateThumbprint"
                    Store       = $store.Curl
                }
            }
        }
        catch {
            Write-Warning "Could not read $($store.Path): $($_.Exception.Message)"
        }
    }
    return $null
}

function Find-AuthenticationRequirements {
    param([string]$Text)

    $rules = [ordered]@{
        "Username"                  = "username|user name|name=[`"'](?:username|login|user)[`"']"
        "Password"                  = "password|type=[`"']password[`"']"
        "2FA / MFA / OTP"           = "multi-factor|multifactor|two-factor|2fa|mfa|one-time password|one-time passcode|otp|verification code|duo|rsa securid|authenticator"
        "SSO / identity provider"   = "saml|oauth|openid|single sign-on|microsoftonline|okta|adfs|pingidentity"
        "YubiKey / security key"    = "yubikey|yubi key|webauthn|fido|security key"
        "EPA / device posture"      = "endpoint analysis|device posture|epa scan|epa client|nsepa|epaclient|/epa/"
        "Client/device certificate" = "client certificate|device certificate|smart card|smartcard"
    }

    $findings = [ordered]@{}
    foreach ($entry in $rules.GetEnumerator()) {
        $findings[$entry.Key] = if ($Text -match $entry.Value) { "detected" } else { "not observed" }
    }
    return $findings
}

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

if ($CerFile) {
    try {
        $resolvedCer = (Resolve-Path -LiteralPath $CerFile).Path
        $reference = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedCer)
        if ($Thumbprint -and $Thumbprint -ne $reference.Thumbprint) {
            throw "-CerFile and -Thumbprint refer to different certificates."
        }
        $Thumbprint = $reference.Thumbprint
        Write-Host "Read thumbprint $Thumbprint from $CerFile"
    }
    catch {
        Write-Host "Could not read reference certificate: $($_.Exception.Message)" -ForegroundColor Red
        exit 2
    }
}

$installedCertificate = $null
$certificateIssue = ""
if ($Thumbprint) {
    $Thumbprint = ($Thumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    $installedCertificate = Get-CertificateFromStore -CertificateThumbprint $Thumbprint -RequestedStore $StoreLocation
    if (-not $installedCertificate) {
        $certificateIssue = "matching certificate not installed"
        Write-Warning "Certificate $Thumbprint was not found in the selected Windows Personal store. Continuing without client-certificate authentication."
    }
    elseif (-not $installedCertificate.Certificate.HasPrivateKey) {
        $certificateIssue = "matching certificate has no private key"
        Write-Warning "The installed certificate has no matching private key. Continuing with network/HTTP tests only."
        $installedCertificate = $null
    }
    elseif ($installedCertificate.Certificate.NotAfter -le (Get-Date)) {
        $certificateIssue = "matching certificate is expired"
        Write-Warning "The installed certificate is expired. Continuing with network/HTTP tests only."
        $installedCertificate = $null
    }
    else {
        Write-Host "Using installed certificate: $($installedCertificate.Certificate.Subject)"
        Write-Host "Store: $($installedCertificate.Store)"
        Write-Host "Expires: $($installedCertificate.Certificate.NotAfter)"
    }
}

$curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlCommand) {
    Write-Host "curl.exe was not found. It is included with supported modern Windows versions." -ForegroundColor Red
    exit 2
}
$curlVersion = (& $curlCommand.Source --version 2>$null) -join " "
if ($installedCertificate -and $curlVersion -notmatch "Schannel") {
    Write-Host "This curl.exe does not use Windows Schannel and cannot access the Windows certificate private key." -ForegroundColor Red
    exit 2
}

$port = if ($target.IsDefaultPort) {
    if ($target.Scheme -eq "https") { 443 } else { 80 }
} else {
    $target.Port
}

$allSuccessful = $true
for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    Write-Host "`n=== Attempt $attempt/$Attempts - $(Get-Date -Format o) ===" -ForegroundColor Cyan
    $dnsOk = $false
    $tcpOk = $false
    $httpOk = $false
    $addresses = @()
    $tcpError = ""

    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($target.DnsSafeHost) |
            ForEach-Object { $_.IPAddressToString } |
            Sort-Object -Unique)
        $dnsOk = $addresses.Count -gt 0
        Write-Host "DNS: OK ($($addresses -join ', '))" -ForegroundColor Green
    }
    catch {
        Write-Host "DNS: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($dnsOk) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($target.DnsSafeHost, $port)
            if (-not $task.Wait($TimeoutSeconds * 1000)) {
                throw "Connection timed out after $TimeoutSeconds seconds."
            }
            $null = $task.GetAwaiter().GetResult()
            $tcpOk = $true
            Write-Host "TCP: OK ($($client.Client.RemoteEndPoint))" -ForegroundColor Green
        }
        catch {
            $tcpError = $_.Exception.Message
            Write-Host "TCP: FAILED - $tcpError" -ForegroundColor Red
        }
        finally {
            $client.Dispose()
        }
    }

    $bodyFile = [System.IO.Path]::GetTempFileName()
    try {
        $writeOut = "`nCITRIX_RESULT|%{http_code}|%{remote_ip}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_total}|%{url_effective}`n"
        $curlArguments = @(
            "--silent", "--show-error", "--location",
            "--connect-timeout", "$TimeoutSeconds",
            "--max-time", "$TimeoutSeconds",
            "--output", $bodyFile,
            "--write-out", $writeOut,
            "--header", "Cache-Control: no-cache"
        )
        if ($installedCertificate) {
            $curlArguments += @("--cert", $installedCertificate.CurlPath)
        }
        $curlArguments += $Url

        $curlOutput = @(& $curlCommand.Source @curlArguments 2>&1)
        $curlExitCode = $LASTEXITCODE
        $resultLine = $curlOutput |
            ForEach-Object { "$_" } |
            Where-Object { $_ -like "CITRIX_RESULT|*" } |
            Select-Object -Last 1

        $httpStatus = 0
        $remoteIp = ""
        $totalSeconds = 0.0
        $effectiveUrl = ""
        if ($resultLine) {
            $parts = $resultLine -split "\|", 8
            $httpStatus = [int]$parts[1]
            $remoteIp = $parts[2]
            $totalSeconds = [double]::Parse($parts[6], [Globalization.CultureInfo]::InvariantCulture)
            $effectiveUrl = $parts[7]
        }
        $httpOk = $curlExitCode -eq 0 -and $httpStatus -ge 200 -and $httpStatus -lt 500

        if ($httpOk) {
            Write-Host "$($target.Scheme.ToUpperInvariant()): OK (HTTP $httpStatus, peer $remoteIp, $([math]::Round($totalSeconds * 1000, 2)) ms)" -ForegroundColor Green
        }
        else {
            $curlErrors = ($curlOutput | Where-Object { "$_" -notlike "CITRIX_RESULT|*" }) -join " "
            Write-Host "$($target.Scheme.ToUpperInvariant()): FAILED (curl $curlExitCode, HTTP $httpStatus) $curlErrors" -ForegroundColor Red
        }

        $body = if (Test-Path -LiteralPath $bodyFile) {
            Get-Content -LiteralPath $bodyFile -Raw -ErrorAction SilentlyContinue
        } else { "" }
        $safeEffectiveUrl = ""
        if ($effectiveUrl) {
            try {
                $effective = [Uri]$effectiveUrl
                $safeEffectiveUrl = $effective.GetLeftPart([System.UriPartial]::Path)
            }
            catch {
                $safeEffectiveUrl = "unavailable"
            }
        }
        $requirements = Find-AuthenticationRequirements -Text "$body`n$safeEffectiveUrl"
        if ($installedCertificate) {
            $requirements["Client/device certificate"] = if ($httpOk) { "supplied" } else { "supplied; acceptance unconfirmed" }
        }
        elseif ($certificateIssue) {
            $requirements["Client/device certificate"] = "unavailable - $certificateIssue"
        }

        Write-Host "Authentication requirements visible before login:" -ForegroundColor Cyan
        foreach ($finding in $requirements.GetEnumerator()) {
            Write-Host "  $($finding.Key): $($finding.Value)"
        }

        $record = [ordered]@{
            timestamp       = (Get-Date).ToUniversalTime().ToString("o")
            target          = $target.GetLeftPart([System.UriPartial]::Path)
            attempt         = $attempt
            dns_ok          = $dnsOk
            addresses       = $addresses
            tcp_ok          = $tcpOk
            tcp_error       = $tcpError
            http_ok         = $httpOk
            http_status     = $httpStatus
            remote_ip       = $remoteIp
            total_ms        = [math]::Round($totalSeconds * 1000, 2)
            final_url       = $safeEffectiveUrl
            certificate     = if ($installedCertificate) {
                @{ supplied = $true; store = $installedCertificate.Store; thumbprint = $Thumbprint; expires = $installedCertificate.Certificate.NotAfter.ToUniversalTime().ToString("o") }
            } else {
                @{ supplied = $false; issue = $certificateIssue }
            }
            auth_findings   = $requirements
        }
        $record | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $OutputFile -Encoding UTF8
    }
    finally {
        Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
    }

    if (-not ($dnsOk -and $tcpOk -and $httpOk)) {
        $allSuccessful = $false
    }
    if ($attempt -lt $Attempts) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Write-Host "`nEvidence written to: $((Resolve-Path -LiteralPath $OutputFile).Path)"
Write-Host "'Not observed' means a factor was not visible before login; Citrix may reveal it later."
Write-Host "No password, 2FA code, cookie value, private key, or response body was written to the log."

if ($allSuccessful) { exit 0 } else { exit 1 }
