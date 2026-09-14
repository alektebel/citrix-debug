[CmdletBinding()]
param(
    [string]$CerFile = "",
    [switch]$IncludeExpired
)

$ErrorActionPreference = "Stop"

function Get-StoreCertificates {
    $stores = @(
        @{ Path = "Cert:\CurrentUser\My"; Name = "CurrentUser\MY" },
        @{ Path = "Cert:\LocalMachine\My"; Name = "LocalMachine\MY" }
    )

    foreach ($store in $stores) {
        try {
            foreach ($certificate in Get-ChildItem -Path $store.Path) {
                $clientAuth = $certificate.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.2"
                if ($IncludeExpired -or $certificate.NotAfter -gt (Get-Date)) {
                    [PSCustomObject]@{
                        Store          = $store.Name
                        Subject        = $certificate.Subject
                        Issuer         = $certificate.Issuer
                        Thumbprint     = $certificate.Thumbprint
                        NotAfter       = $certificate.NotAfter
                        HasPrivateKey  = $certificate.HasPrivateKey
                        ClientAuthEKU  = $clientAuth
                        Certificate    = $certificate
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not read $($store.Path): $($_.Exception.Message)"
        }
    }
}

$certificates = @(Get-StoreCertificates)

if ($CerFile) {
    $resolvedPath = (Resolve-Path -LiteralPath $CerFile).Path
    $reference = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedPath)
    $matches = @($certificates | Where-Object Thumbprint -eq $reference.Thumbprint)

    Write-Host "Reference certificate thumbprint: $($reference.Thumbprint)"
    if ($matches.Count -eq 0) {
        Write-Host "No matching certificate was found in CurrentUser\MY or LocalMachine\MY." -ForegroundColor Red
        Write-Host "Importing a .cer alone does not create its missing private key."
        exit 2
    }

    $matches |
        Select-Object Store, Subject, Issuer, Thumbprint, NotAfter, HasPrivateKey, ClientAuthEKU |
        Format-List

    if (-not ($matches | Where-Object HasPrivateKey)) {
        Write-Host "The matching certificate has no private key and cannot perform TLS client authentication." -ForegroundColor Red
        exit 3
    }
    exit 0
}

$candidates = @($certificates | Where-Object { $_.HasPrivateKey -and $_.ClientAuthEKU })
if ($candidates.Count -eq 0) {
    Write-Host "No unexpired client-authentication certificate with a private key was found." -ForegroundColor Yellow
    exit 1
}

Write-Host "Candidate Citrix/EPA client certificates:" -ForegroundColor Cyan
$candidates |
    Select-Object Store, Subject, Issuer, Thumbprint, NotAfter, HasPrivateKey |
    Format-Table -AutoSize

Write-Host "The thumbprint is the hexadecimal ID in the Thumbprint column. It is not a password or private key."
