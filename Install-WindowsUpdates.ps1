#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks for and installs Windows Updates, managing the Windows Update service as needed.

.DESCRIPTION
    This script checks for available Windows Updates. If updates are found, it enables and starts
    the Windows Update service (if disabled), downloads and installs the updates, and restarts
    the system if required.

.EXITCODES
    0 - Success (no updates available or updates installed successfully)
    1 - Error occurred during execution
    2 - Updates were installed (informational)
#>

[CmdletBinding()]
param()

# Exit codes
$Script:ExitSuccess = 0
$Script:ExitError = 1
$Script:ExitUpdatesInstalled = 2

$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsUpdateServiceStatus {
    $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "Windows Update service (wuauserv) not found" "ERROR"
        return $null
    }
    return @{
        Status = $service.Status
        StartType = $service.StartType
    }
}

function Enable-WindowsUpdateService {
    Write-Log "Enabling and starting Windows Update service..."
    
    try {
        $service = Get-Service -Name "wuauserv" -ErrorAction Stop
        
        # Enable the service (set to Automatic or Manual)
        if ($service.StartType -eq [System.ServiceProcess.ServiceStartMode]::Disabled) {
            Write-Log "Service is disabled. Enabling service..."
            Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction Stop
            Write-Log "Service enabled successfully"
        }
        
        # Start the service if not running
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Log "Starting Windows Update service..."
            Start-Service -Name "wuauserv" -ErrorAction Stop
            
            # Wait for service to be running
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, (New-TimeSpan -Seconds 30))
            Write-Log "Windows Update service started successfully"
        } else {
            Write-Log "Windows Update service is already running"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to enable/start Windows Update service: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-AvailableUpdates {
    Write-Log "Checking for available Windows Updates..."
    
    try {
        # Create Windows Update Session
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        Write-Log "Searching for updates (this may take a while)..."
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        $updateCount = $searchResult.Updates.Count
        Write-Log "Found $updateCount available update(s)"
        
        if ($updateCount -eq 0) {
            return $null
        }
        
        # Display update information
        foreach ($update in $searchResult.Updates) {
            Write-Log "  - $($update.Title) (Size: $([math]::Round($update.MaxDownloadSize / 1MB, 2)) MB)"
        }
        
        return $searchResult.Updates
    }
    catch {
        Write-Log "Error checking for updates: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-WindowsUpdates {
    param(
        [object]$Updates
    )
    
    Write-Log "Preparing to install $($Updates.Count) update(s)..."
    
    try {
        # Create update collection and downloader
        $updateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $Updates) {
            $updateCollection.Add($update) | Out-Null
        }
        
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updateCollection
        
        # Download updates
        Write-Log "Downloading updates..."
        $downloadResult = $downloader.Download()
        
        # Check download result
        if ($downloadResult.ResultCode -ne 2) {
            Write-Log "Some updates failed to download. Result code: $($downloadResult.ResultCode)" "WARNING"
        } else {
            Write-Log "All updates downloaded successfully"
        }
        
        # Install updates
        Write-Log "Installing updates (this may take a while)..."
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updateCollection
        
        $installResult = $installer.Install()
        
        # Check installation result
        if ($installResult.ResultCode -eq 2) {
            Write-Log "All updates installed successfully"
            return $true
        }
        elseif ($installResult.ResultCode -eq 3) {
            Write-Log "Updates installed but a reboot is required"
            return $true
        }
        else {
            Write-Log "Some updates failed to install. Result code: $($installResult.ResultCode)" "WARNING"
            
            # Display failed updates
            for ($i = 0; $i -lt $updateCollection.Count; $i++) {
                $updateResult = $installResult.GetUpdateResult($i)
                # Result code 2 = Success, 3 = Success with reboot required
                if ($updateResult.ResultCode -ne 2 -and $updateResult.ResultCode -ne 3) {
                    Write-Log "  Failed: $($Updates[$i].Title)" "WARNING"
                }
            }
            
            return $false
        }
    }
    catch {
        Write-Log "Error installing updates: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Test-PendingReboot {
    # Check if reboot is required
    $pendingReboot = $false
    
    # Method 1: Check registry for pending reboot
    $rebootPending = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
    if ($rebootPending) {
        $pendingReboot = $true
        Write-Log "Reboot required (registry check)"
    }
    
    # Method 2: Check Component Based Servicing
    $cbsRebootPending = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
    if ($cbsRebootPending) {
        $pendingReboot = $true
        Write-Log "Reboot required (Component Based Servicing)"
    }
    
    # Method 3: Check System File Protection
    $sccmRebootPending = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
    if ($sccmRebootPending) {
        $pendingReboot = $true
        Write-Log "Reboot required (System File Protection)"
    }
    
    return $pendingReboot
}

function Restart-ComputerIfRequired {
    if (Test-PendingReboot) {
        Write-Log "System restart is required. Restarting in 60 seconds..."
        Write-Log "To cancel the restart, run: shutdown /a"
        Start-Sleep -Seconds 5
        Restart-Computer -Force -Timeout 60
        exit $Script:ExitUpdatesInstalled
    } else {
        Write-Log "No restart required"
    }
}

# Main execution
try {
    Write-Log "========================================="
    Write-Log "Windows Update Installation Script"
    Write-Log "========================================="
    
    # Check admin privileges
    if (-not (Test-AdminPrivileges)) {
        Write-Log "This script requires administrator privileges. Please run as administrator." "ERROR"
        exit $Script:ExitError
    }
    
    # Check for available updates
    $availableUpdates = Get-AvailableUpdates
    
    if ($null -eq $availableUpdates -or $availableUpdates.Count -eq 0) {
        Write-Log "No Windows Updates available. Exiting."
        exit $Script:ExitSuccess
    }
    
    # Enable and start Windows Update service
    $serviceStatus = Get-WindowsUpdateServiceStatus
    if ($null -eq $serviceStatus) {
        Write-Log "Could not access Windows Update service. Exiting." "ERROR"
        exit $Script:ExitError
    }
    
    if (-not (Enable-WindowsUpdateService)) {
        Write-Log "Failed to enable/start Windows Update service. Exiting." "ERROR"
        exit $Script:ExitError
    }
    
    # Install updates
    $installSuccess = Install-WindowsUpdates -Updates $availableUpdates
    if (-not $installSuccess) {
        Write-Log "Some updates may have failed to install. Check the log above for details." "WARNING"
    }
    
    # Check for restart requirement and restart if needed
    Restart-ComputerIfRequired
    
    Write-Log "Script completed successfully"
    exit $Script:ExitUpdatesInstalled
}
catch {
    Write-Log "An error occurred: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit $Script:ExitError
}

