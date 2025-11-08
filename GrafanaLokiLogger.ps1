# GrafanaLokiLogger
# Simple reusable logger that pushes JSON log lines to Grafana Loki with Basic Auth.
class GrafanaLokiLogger : System.IDisposable {
    [System.Uri] hidden $EndpointUri
    [System.Management.Automation.PSCredential] hidden $Credential
    [System.Net.Http.HttpClient] hidden $HttpClient

    # Create a new Loki logger instance.
    # baseUri: Loki base URL (with or without /loki/api/v1/push suffix).
    # credential: PSCredential holding Grafana basic-auth username/password.
    GrafanaLokiLogger([string]$baseUri, [System.Management.Automation.PSCredential]$credential) {
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

        $this.HttpClient = [System.Net.Http.HttpClient]::new()
        $this.HttpClient.DefaultRequestHeaders.Clear()
        $this.HttpClient.DefaultRequestHeaders.Accept.ParseAdd("application/json")
        $this.HttpClient.DefaultRequestHeaders.Authorization = $this.BuildBasicAuthHeader()
    }

    # Push a log entry to Loki.
    # message: Human-readable message.
    # level: Severity level; defaults to info.
    # job: Logical operation name added to the Loki stream.
    # machine: Machine identifier added to the Loki stream.
    # timestamp: Optional explicit timestamp (DateTime/DateTimeOffset/Unix epoch/ISO string) used for the Loki entry.
    [void] SendLog([string]$job, [string]$machine, [string]$message, [string]$level = 'info', [object]$timestamp = $null) {
        if ([string]::IsNullOrWhiteSpace($job)) {
            throw [System.ArgumentException]::new("Job must not be empty.", "job")
        }

        if ([string]::IsNullOrWhiteSpace($machine)) {
            throw [System.ArgumentException]::new("Host must not be empty.", "machine")
        }

        if ([string]::IsNullOrWhiteSpace($message)) {
            throw [System.ArgumentException]::new("Message must not be empty.", "message")
        }

        $effectiveLevel = if ([string]::IsNullOrWhiteSpace($level)) { "info" } else { $level }
        $timestampNs = $this.ResolveTimestampToNanoseconds($timestamp)
        $stream = @{
            job = [string]$job
            host = [string]$machine
            level = $effectiveLevel
        }

        $payload = $this.BuildPayload($message, $stream, $timestampNs)
        $jsonBody = $payload | ConvertTo-Json -Depth 10 -Compress
        Write-Verbose ("Loki payload: {0}" -f $jsonBody)
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

    # Accepts a hashtable with Loki-compatible fields (job, host, level, timestamp, message).
    [void] SendLog([hashtable]$entry) {
        if ($null -eq $entry) {
            throw [System.ArgumentNullException]::new("entry", "Log entry data must be provided.")
        }

        if (-not $entry.ContainsKey("job")) {
            throw [System.ArgumentException]::new("Log entry must include a 'job' value.", "entry")
        }

        if (-not $entry.ContainsKey("host")) {
            throw [System.ArgumentException]::new("Log entry must include a 'host' value.", "entry")
        }

        if (-not $entry.ContainsKey("message")) {
            throw [System.ArgumentException]::new("Log entry must include a 'message' value.", "entry")
        }

        $job = [string]$entry["job"]
        $entryHost = [string]$entry["host"]
        $message = [string]$entry["message"]
        $explicitLevel = if ($entry.ContainsKey("level")) { [string]$entry["level"] } else { $null }
        $level = if ([string]::IsNullOrWhiteSpace($explicitLevel)) { "info" } else { $explicitLevel }

        $timestamp = if ($entry.ContainsKey("timestamp")) { $entry["timestamp"] } else { $null }

        $this.SendLog($job, $entryHost, $message, $level, $timestamp)
    }

    hidden [hashtable] BuildPayload([string]$message, [hashtable]$stream, [string]$timestampNs) {
        if (-not $stream.ContainsKey("job") -or [string]::IsNullOrWhiteSpace($stream["job"])) {
            throw [System.ArgumentException]::new("Stream data must include a non-empty 'job' value.", "stream")
        }

        if (-not $stream.ContainsKey("host") -or [string]::IsNullOrWhiteSpace($stream["host"])) {
            throw [System.ArgumentException]::new("Stream data must include a non-empty 'host' value.", "stream")
        }

        if (-not $stream.ContainsKey("level") -or [string]::IsNullOrWhiteSpace($stream["level"])) {
            $stream["level"] = "info"
        }

        $values = [System.Collections.Generic.List[object]]::new()
        $values.Add(([object[]]@(
            $timestampNs,
            [string]$message
        ))) | Out-Null

        return @{
            streams = @(
                @{
                    stream = $stream
                    values = $values
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

    hidden [string] ResolveTimestampToNanoseconds([object]$timestampCandidate) {
        $timestamp = $this.ConvertToDateTimeOffset($timestampCandidate)
        return $this.ToUnixTimeNanoseconds($timestamp)
    }

    hidden [System.DateTimeOffset] ConvertToDateTimeOffset([object]$candidate) {
        if ($null -eq $candidate) {
            return [System.DateTimeOffset]::UtcNow
        }

        if ($candidate -is [System.DateTimeOffset]) {
            return ([System.DateTimeOffset]$candidate).ToUniversalTime()
        }

        if ($candidate -is [datetime]) {
            return [System.DateTimeOffset]::new(([datetime]$candidate)).ToUniversalTime()
        }

        if ($candidate -is [System.Int64] -or $candidate -is [System.Int32]) {
            return $this.ConvertEpochNumberToDateTimeOffset([System.Int64]$candidate)
        }

        if ($candidate -is [string]) {
            $trimmed = $candidate.Trim()

            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                return [System.DateTimeOffset]::UtcNow
            }

            [System.Int64] $numericValue = 0
            if ([System.Int64]::TryParse($trimmed, [ref]$numericValue)) {
                return $this.ConvertEpochNumberToDateTimeOffset($numericValue)
            }

            [System.DateTimeOffset] $parsedTimestamp = [System.DateTimeOffset]::MinValue
            if ([System.DateTimeOffset]::TryParse($trimmed, [ref]$parsedTimestamp)) {
                return $parsedTimestamp.ToUniversalTime()
            }

            throw [System.ArgumentException]::new("Unable to parse timestamp string. Provide ISO8601 text or Unix epoch value.", "timestamp")
        }

        throw [System.ArgumentException]::new("Unsupported timestamp type. Provide a string, DateTimeOffset, DateTime, or Unix epoch integer.", "timestamp")
    }

    hidden [System.DateTimeOffset] ConvertEpochNumberToDateTimeOffset([System.Int64]$epochValue) {
        if ($epochValue -lt 0) {
            throw [System.ArgumentOutOfRangeException]::new("timestamp", "Timestamp cannot be negative.")
        }

        $digits = $epochValue.ToString().Length
        $epoch = [System.DateTimeOffset]::UnixEpoch

        $offset = switch ($digits) {
            { $_ -le 10 } {
                [System.DateTimeOffset]::FromUnixTimeSeconds($epochValue)
            }
            { $_ -le 13 } {
                $seconds = [System.Math]::Floor($epochValue / 1000)
                $milliseconds = $epochValue % 1000
                [System.DateTimeOffset]::FromUnixTimeSeconds([long]$seconds).AddMilliseconds($milliseconds)
            }
            { $_ -le 16 } {
                $seconds = [System.Math]::Floor($epochValue / 1000000)
                $microseconds = $epochValue % 1000000
                $epoch.AddSeconds($seconds).AddTicks($microseconds * 10)
            }
            default {
                $seconds = [System.Math]::Floor($epochValue / 1000000000)
                $nanoseconds = $epochValue % 1000000000
                $epoch.AddSeconds($seconds).AddTicks([long]([System.Math]::Floor($nanoseconds / 100)))
            }
        }

        return $offset.ToUniversalTime()
    }

    hidden [string] ToUnixTimeNanoseconds([System.DateTimeOffset]$timestamp) {
        $utcTimestamp = $timestamp.ToUniversalTime()
        $ticksSinceEpoch = $utcTimestamp.Ticks - [System.DateTimeOffset]::UnixEpoch.Ticks
        return ($ticksSinceEpoch * 100).ToString()
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
     $credential
 )

$logger.SendLog(@{
    job = "windows-update"
    host = [System.Environment]::MachineName
     level = "info"
     timestamp = [System.DateTimeOffset]::UtcNow
     message = "Windows update workflow started."
 })

 $logger.Dispose()
#>

