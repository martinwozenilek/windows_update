# GrafanaLokiLogger
# Simple reusable logger that pushes JSON log lines to Grafana Loki with Basic Auth.
class GrafanaLokiLogger : System.IDisposable {
    [System.Uri] hidden $EndpointUri
    [System.Management.Automation.PSCredential] hidden $Credential
    [System.Net.Http.HttpClient] hidden $HttpClient
    [hashtable] hidden $DefaultLabels

    # Create a new Loki logger instance.
    # baseUri: Loki base URL (with or without /loki/api/v1/push suffix).
    # credential: PSCredential holding Grafana basic-auth username/password.
    # defaultLabels: Labels applied to every stream (e.g. job, environment).
    GrafanaLokiLogger([string]$baseUri, [System.Management.Automation.PSCredential]$credential, [hashtable]$defaultLabels = @{}) {
        if ([string]::IsNullOrWhiteSpace($baseUri)) {
            throw [System.ArgumentException]::new("Base URI must be provided.", "baseUri")
        }

        if ($null -eq $credential) {
            throw [System.ArgumentNullException]::new("credential", "Credential must be provided.")
        }

        [System.Uri] $parsedBaseUri = $null

        if (-not [System.Uri]::TryCreate($baseUri, [System.UriKind]::Absolute, [ref] $parsedBaseUri)) {
            throw [System.ArgumentException]::new("Base URI must be a valid absolute URI.", "baseUri")
        }

        if ($parsedBaseUri.AbsolutePath.TrimEnd('/') -ieq "/loki/api/v1/push") {
            $this.EndpointUri = $parsedBaseUri
        }
        else {
            $this.EndpointUri = [System.Uri]::new($parsedBaseUri, "/loki/api/v1/push")
        }

        $networkCredential = $credential.GetNetworkCredential()

        if ([string]::IsNullOrWhiteSpace($networkCredential.UserName)) {
            throw [System.ArgumentException]::new("Credential must include a username.", "credential")
        }

        if ([string]::IsNullOrWhiteSpace($networkCredential.Password)) {
            throw [System.ArgumentException]::new("Credential must include a password.", "credential")
        }

        $this.Credential = $credential
        $this.DefaultLabels = @{}

        $labelsToApply = if ($null -ne $defaultLabels) { $defaultLabels } else { @{} }

        foreach ($key in $labelsToApply.Keys) {
            $this.DefaultLabels[$key] = [string]$labelsToApply[$key]
        }

        if (-not $this.DefaultLabels.ContainsKey("app")) {
            $this.DefaultLabels["app"] = "powershell"
        }

        $this.HttpClient = [System.Net.Http.HttpClient]::new()
        $this.HttpClient.DefaultRequestHeaders.Clear()
        $this.HttpClient.DefaultRequestHeaders.Accept.ParseAdd("application/json")
        $this.HttpClient.DefaultRequestHeaders.Authorization = $this.BuildBasicAuthHeader()
    }

    # Push a log entry to Loki.
    # message: Human-readable message.
    # level: Severity label; defaults to info.
    # labels: Additional Loki labels merged with defaults.
    # fields: Extra JSON fields appended to the log body.
    [void] SendLog([string]$message, [string]$level = 'info', [hashtable]$labels = @{}, [hashtable]$fields = @{}) {
        if ([string]::IsNullOrWhiteSpace($message)) {
            throw [System.ArgumentException]::new("Message must not be empty.", "message")
        }

        $payload = $this.BuildPayload($message, $level, $labels, $fields)
        $jsonBody = $payload | ConvertTo-Json -Depth 10
        $content = [System.Net.Http.StringContent]::new($jsonBody, [System.Text.Encoding]::UTF8, "application/json")

        try {
            $response = $this.HttpClient.PostAsync($this.EndpointUri, $content).ConfigureAwait($false).GetAwaiter().GetResult()
        }
        catch {
            throw [System.Net.Http.HttpRequestException]::new("Failed to send logs to Loki endpoint.", $_.Exception)
        }

        if (-not $response.IsSuccessStatusCode) {
            $responseBody = $response.Content.ReadAsStringAsync().ConfigureAwait($false).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode
            $reason = $response.ReasonPhrase
            throw [System.Net.Http.HttpRequestException]::new(
                "Loki push request failed.",
                [System.Exception]::new("StatusCode: $statusCode ($reason). Response: $responseBody")
            )
        }
    }

    hidden [hashtable] BuildPayload([string]$message, [string]$level, [hashtable]$labels, [hashtable]$fields) {
        $mergedLabels = @{}

        foreach ($key in $this.DefaultLabels.Keys) {
            $mergedLabels[$key] = [string]$this.DefaultLabels[$key]
        }

        foreach ($key in $labels.Keys) {
            $mergedLabels[$key] = [string]$labels[$key]
        }

        $mergedLabels["level"] = $level

        $timestampNs = $this.GetUnixTimeNanoseconds()

        $logBody = [ordered]@{
            message = $message
        }

        if ($fields.Count -gt 0) {
            foreach ($fieldKey in $fields.Keys) {
                $logBody[$fieldKey] = $fields[$fieldKey]
            }
        }

        $logLine = $logBody | ConvertTo-Json -Depth 10 -Compress

        return @{
            streams = @(
                @{
                    stream = $mergedLabels
                    values = @(
                        @(
                            $timestampNs,
                            $logLine
                        )
                    )
                }
            )
        }
    }

    hidden [System.Net.Http.Headers.AuthenticationHeaderValue] BuildBasicAuthHeader() {
        $netCredential = $this.Credential.GetNetworkCredential()
        $raw = "{0}:{1}" -f $netCredential.UserName, $netCredential.Password
        $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($raw))
        return [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Basic", $encoded)
    }

    hidden [string] GetUnixTimeNanoseconds() {
        $timestamp = [System.DateTimeOffset]::UtcNow
        $milliseconds = $timestamp.ToUnixTimeMilliseconds()
        $nanoseconds = $milliseconds * 1000000
        return $nanoseconds.ToString()
    }

    [void] Dispose() {
        if ($null -ne $this.HttpClient) {
            $this.HttpClient.Dispose()
            $this.HttpClient = $null
        }
    }
}

<#
.SYNOPSIS
 Demonstrates how to use the GrafanaLokiLogger class.

.EXAMPLE
 $securePassword = "api-super-secret" | ConvertTo-SecureString -AsPlainText -Force
 $credential = [System.Management.Automation.PSCredential]::new("123456", $securePassword)

 $logger = [GrafanaLokiLogger]::new(
     "https://logs-prod-us-central1.grafana.net",
     $credential,
     @{ job = "windows-maintenance"; environment = "dev" }
 )

 $logger.SendLog(
     "Windows update workflow started.",
     "info",
     @{ component = "scheduler" },
     @{ correlationId = "7f1f1b15-1c3e-4b61-a5c1-3ddf6c770d2e"; host = $env:COMPUTERNAME }
 )

 $logger.Dispose()
#>

