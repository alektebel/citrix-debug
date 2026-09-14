# Edit only this section, then right-click this file and choose "Run with PowerShell",
# or run: powershell.exe -NoProfile -File .\windows\Run-Me.ps1
$CitrixUrl = "https://YOUR-HOST/logon/LogonPoint/tmindex.html"
$MaquinaCer = ".\maquina.cer"  # Set to "" if you do not have this public certificate.
$Attempts = 5
$SecondsBetweenAttempts = 5

# Do not paste account passwords, 2FA codes, certificate contents, or private keys here.

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Path $PSScriptRoot -Parent

if ($CitrixUrl -match "YOUR-HOST") {
    Write-Host "Edit CitrixUrl at the top of windows\Run-Me.ps1 before running it." -ForegroundColor Yellow
    exit 2
}

$testScript = Join-Path $PSScriptRoot "Test-CitrixConnection.ps1"
$arguments = @{
    Url             = $CitrixUrl
    Attempts        = $Attempts
    IntervalSeconds = $SecondsBetweenAttempts
}

if ($MaquinaCer) {
    $certificatePath = if ([System.IO.Path]::IsPathRooted($MaquinaCer)) {
        $MaquinaCer
    } else {
        Join-Path $projectRoot $MaquinaCer
    }
    if (Test-Path -LiteralPath $certificatePath) {
        $arguments.CerFile = $certificatePath
    }
    else {
        Write-Warning "maquina.cer was not found at '$certificatePath'. Continuing without it."
    }
}

& $testScript @arguments
exit $LASTEXITCODE
