#
# Convenience script that loads the N8nWebhookClient class and invokes the
# configured n8n webhook with a timestamp payload. Run manually to validate
# webhook connectivity independent of the Windows Update workflow.
#

#Requires -RunAsAdministrator

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path -Path $ScriptRoot -ChildPath "n8n_webhook.ps1")

try {
    # Instantiate the webhook client and send the test payload.
    $webhookClient = [N8nWebhookClient]::new("http://192.168.1.88:5678/webhook/7657d7e2-3f88-46d0-9459-33aafeb097a6")
    $webhookClient.SendTestPayload()
    Write-Host "n8n webhook invoked successfully"
}
catch {
    # Surface the error and signal failure to the shell.
    Write-Warning "Failed to invoke n8n webhook: $($_.Exception.Message)"
    exit 1
}

exit 0

