#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks for and installs Windows Updates, managing the Update Orchestrator Service as needed.

.DESCRIPTION
    This script manages the Update Orchestrator Service (sets to Automatic and starts if disabled), then
    checks for available Windows Updates. If updates are found, it downloads and installs them,
    and restarts the system if required. If no updates are found, it stops and disables the service
    and shuts down the system.

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
    $service = Get-Service -Name "UsoSvc" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "Update Orchestrator Service (UsoSvc) not found" "ERROR"
        return $null
    }
    return @{
        Status = $service.Status
        StartType = $service.StartType
    }
}

function Enable-WindowsUpdateService {
    Write-Log "Setting up and starting Update Orchestrator Service..."
    
    try {
        $service = Get-Service -Name "UsoSvc" -ErrorAction Stop
        
        # Set service to Automatic startup type if disabled
        if ($service.StartType -eq [System.ServiceProcess.ServiceStartMode]::Disabled) {
            Write-Log "Service is disabled. Setting to Automatic startup type..."
            Set-Service -Name "UsoSvc" -StartupType Automatic -ErrorAction Stop
            Write-Log "Service startup type set to Automatic successfully"
        }
        
        # Start the service if not running
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Log "Starting Update Orchestrator Service..."
            Start-Service -Name "UsoSvc" -ErrorAction Stop
            
            # Wait for service to be running
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, (New-TimeSpan -Seconds 30))
            Write-Log "Update Orchestrator Service started successfully"
        } else {
            Write-Log "Update Orchestrator Service is already running"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to enable/start Update Orchestrator Service: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disable-WindowsUpdateService {
    Write-Log "Stopping and disabling Update Orchestrator Service..."
    
    try {
        $service = Get-Service -Name "UsoSvc" -ErrorAction Stop
        
        # Stop the service if running
        if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Log "Stopping Update Orchestrator Service..."
            Stop-Service -Name "UsoSvc" -ErrorAction Stop
            
            # Wait for service to be stopped
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, (New-TimeSpan -Seconds 30))
            Write-Log "Update Orchestrator Service stopped successfully"
        }
        
        # Disable the service
        if ($service.StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled) {
            Write-Log "Disabling Update Orchestrator Service..."
            Set-Service -Name "UsoSvc" -StartupType Disabled -ErrorAction Stop
            Write-Log "Update Orchestrator Service disabled successfully"
        } else {
            Write-Log "Update Orchestrator Service is already disabled"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to stop/disable Update Orchestrator Service: $($_.Exception.Message)" "ERROR"
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
        shutdown.exe /r /t 60 /f /c "System restart required after Windows Update installation"
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
    
    # Set up Update Orchestrator Service first (required before checking for updates)
    $serviceStatus = Get-WindowsUpdateServiceStatus
    if ($null -eq $serviceStatus) {
        Write-Log "Could not access Update Orchestrator Service. Exiting." "ERROR"
        exit $Script:ExitError
    }
    
    if (-not (Enable-WindowsUpdateService)) {
        Write-Log "Failed to enable/start Update Orchestrator Service. Exiting." "ERROR"
        exit $Script:ExitError
    }
    
    # Check for available updates
    $availableUpdates = Get-AvailableUpdates
    
    if ($null -eq $availableUpdates -or $availableUpdates.Count -eq 0) {
        Write-Log "No Windows Updates available."
        
        # Stop and disable Update Orchestrator Service
        if (-not (Disable-WindowsUpdateService)) {
            Write-Log "Warning: Failed to stop/disable Update Orchestrator Service. Continuing with shutdown..." "WARNING"
        }
        
        # Shutdown Windows
        Write-Log "Shutting down Windows in 60 seconds..."
        Write-Log "To cancel the shutdown, run: shutdown /a"
        shutdown.exe /s /t 60 /f /c "No updates available. System will shutdown."
        exit $Script:ExitSuccess
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

