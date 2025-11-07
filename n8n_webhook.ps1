#
# Provides a reusable PowerShell class for triggering an n8n webhook endpoint.
# Callers can instantiate the class with a webhook URL and invoke SendTestPayload
# to POST a JSON payload containing the current timestamp.
#

class N8nWebhookClient {
    [string]$WebhookUrl

    N8nWebhookClient([string]$webhookUrl) {
        # Guard against missing or whitespace-only URLs which would cause Invoke-RestMethod to fail.
        if ([string]::IsNullOrWhiteSpace($webhookUrl)) {
            throw [System.ArgumentException]::new("Webhook URL cannot be null or empty.")
        }

        $this.WebhookUrl = $webhookUrl
    }

    [void] SendTestPayload() {
        # Build a simple payload containing the current timestamp (ISO 8601 format) for testing purposes.
        $payload = [pscustomobject]@{
            timestamp = (Get-Date).ToString("o")
        }

        $bodyJson = $payload | ConvertTo-Json -Depth 5

        try {
            # POST the JSON payload to the configured webhook endpoint.
            Write-Verbose "Sending webhook request to $($this.WebhookUrl)"
            Invoke-RestMethod -Uri $this.WebhookUrl -Method Post -Body $bodyJson -ContentType "application/json" | Out-Null
            Write-Verbose "Webhook request completed successfully"
        }
        catch {
            # Re-throw with clearer context so callers can handle or log the failure.
            $message = "Failed to invoke webhook: $($_.Exception.Message)"
            throw [System.Exception]::new($message, $_.Exception)
        }
    }
}

