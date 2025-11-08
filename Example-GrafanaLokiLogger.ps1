param(
    [Parameter()][string]$CredentialFile = "loki_credentials.json",
    [string]$Job = "windows-update",
    [string]$Level = "info",
    [string]$Message = "Windows update workflow started."
)

$ErrorActionPreference = "Stop"

# Resolve the path to the logger class and load it.
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$loggerPath = Join-Path -Path $scriptRoot -ChildPath "GrafanaLokiLogger.ps1"
. $loggerPath

$resolvedCredentialPath = if ([System.IO.Path]::IsPathRooted($CredentialFile)) {
    $CredentialFile
}
else {
    Join-Path -Path $scriptRoot -ChildPath $CredentialFile
}

if (-not (Test-Path -LiteralPath $resolvedCredentialPath)) {
    throw [System.IO.FileNotFoundException]::new("Credential file not found.", $resolvedCredentialPath)
}

try {
    $credentialContent = Get-Content -LiteralPath $resolvedCredentialPath -Raw
    $credentialData = $credentialContent | ConvertFrom-Json
}
catch {
    throw [System.Exception]::new("Failed to parse credentials from file.", $_.Exception)
}

if ([string]::IsNullOrWhiteSpace($credentialData.BaseUri)) {
    throw [System.ArgumentException]::new("Credential file must include a non-empty 'BaseUri' value.", "CredentialFile")
}

if ([string]::IsNullOrWhiteSpace($credentialData.Username)) {
    throw [System.ArgumentException]::new("Credential file must include a non-empty 'Username' value.", "CredentialFile")
}

if ([string]::IsNullOrWhiteSpace($credentialData.Password)) {
    throw [System.ArgumentException]::new("Credential file must include a non-empty 'Password' value.", "CredentialFile")
}

$securePassword = $credentialData.Password | ConvertTo-SecureString -AsPlainText -Force
$credential = [System.Management.Automation.PSCredential]::new($credentialData.Username, $securePassword)

$baseUri = [string]$credentialData.BaseUri

$logger = [GrafanaLokiLogger]::new($baseUri, $credential)

try {
    $logger.SendLog(
        $Job,
        [System.Environment]::MachineName,
        $Message,
        $Level,
        [System.DateTimeOffset]::UtcNow
    )

    Write-Host "Log entry pushed to Loki for job '$Job'."
}
catch {
    if ($_.Exception -is [System.Net.Http.HttpRequestException] -and $null -ne $_.Exception.InnerException) {
        Write-Error "Failed to push log entry: $($_.Exception.InnerException.Message)"
    }
    else {
        Write-Error $_
    }

    exit 1
}
finally {
    if ($null -ne $logger) {
        $logger.Dispose()
    }
}

