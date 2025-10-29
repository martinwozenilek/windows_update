# Windows Update Automation Script

PowerShell script that automates checking for, downloading, and installing Windows Updates, including automatic service management and system restart when needed.

## Features

- ✅ Sets Update Orchestrator Service to Automatic and starts it (as first step)
- ✅ Checks for available Windows Updates
- ✅ Downloads and installs all available updates
- ✅ Automatically restarts the system if required
- ✅ Comprehensive logging with timestamps
- ✅ Proper exit codes for automation
- ✅ Error handling and progress reporting

## Requirements

- **Windows Operating System** (Windows 7 or later)
- **PowerShell** (Windows PowerShell 3.0+ or PowerShell Core)
- **Administrator Privileges** (required for Windows Update operations)

## Usage

### Running the Script

Run PowerShell as Administrator and execute:

```powershell
.\Install-WindowsUpdates.ps1
```

### Alternative: Run from Command Prompt

```cmd
powershell.exe -ExecutionPolicy Bypass -File .\Install-WindowsUpdates.ps1
```

### Execution Policy

If you encounter execution policy restrictions, you can:

1. **Temporarily bypass** (recommended for testing):
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Install-WindowsUpdates.ps1
   ```

2. **Set execution policy** for current user:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Script Workflow

1. **Privilege Check**: Verifies administrator privileges
2. **Service Setup** (First Step - Required):
   - Checks Update Orchestrator Service (`UsoSvc`) status
   - Sets service startup type to Automatic (if disabled)
   - Starts service if not running
   - This must be done first as it's required to check for updates
3. **Update Check**: Searches for available Windows Updates
4. **Early Exit**: If no updates found, script exits (exit code 0)
5. **Download & Install**: Downloads and installs all available updates
6. **Restart Check**: Checks if system restart is required
7. **Automatic Restart**: If restart needed, reboots system after 60 seconds (can be cancelled)

## Exit Codes

The script uses the following exit codes for automation and scripting:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success - No updates available |
| `1` | Error - An error occurred during execution |
| `2` | Updates installed - Updates were successfully installed |

These exit codes can be checked in batch files or scheduled tasks:

```batch
powershell.exe -File .\Install-WindowsUpdates.ps1
if %errorlevel% equ 2 (
    echo Updates were installed
)
```

## Scheduled Task Setup

You can schedule this script to run automatically using Windows Task Scheduler:

1. Open **Task Scheduler** (`taskschd.msc`)
2. Create a **New Task**
3. **General Tab**:
   - Name: "Windows Update Automation"
   - Check "Run whether user is logged on or not"
   - Check "Run with highest privileges"
4. **Triggers Tab**: Set your desired schedule (e.g., Daily at 2 AM)
5. **Actions Tab**:
   - Action: Start a program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "C:\Path\To\Install-WindowsUpdates.ps1"`
6. **Settings Tab**: Configure as needed (e.g., allow task to run on demand)

## Logging

The script provides detailed logging with timestamps:

```
[2024-01-15 14:30:00] [INFO] =========================================
[2024-01-15 14:30:00] [INFO] Windows Update Installation Script
[2024-01-15 14:30:00] [INFO] =========================================
[2024-01-15 14:30:01] [INFO] Checking for available Windows Updates...
[2024-01-15 14:30:15] [INFO] Found 3 available update(s)
[2024-01-15 14:30:15] [INFO]   - Security Update for Windows (KB123456) (Size: 125.5 MB)
```

## Service Management

The script automatically manages the Update Orchestrator Service (`UsoSvc`) as the **very first step** (before checking for updates):

- **If disabled**: Sets startup type to `Automatic` and starts the service
- **If stopped**: Starts the service
- **If already running**: Proceeds without changes

**Note**: The service is set to `Automatic` startup type when disabled. The script does NOT disable the service after completion. If you need to disable it again, you can do so manually or use a separate script.

## Restart Behavior

If a system restart is required after installing updates:

- The script will detect the requirement using multiple registry checks
- A restart will be initiated after a 60-second countdown
- The restart can be cancelled by running: `shutdown /a` from an elevated command prompt

## Troubleshooting

### "This script requires administrator privileges"

**Solution**: Run PowerShell as Administrator. Right-click PowerShell and select "Run as Administrator".

### "Update Orchestrator Service (UsoSvc) not found"

**Solution**: This usually indicates a corrupted Windows installation. Run `sfc /scannow` to check system file integrity.

### Updates fail to download or install

**Solution**: 
- Check internet connectivity
- Verify Update Orchestrator Service is running: `Get-Service UsoSvc`
- Try running Windows Update manually first to check for errors
- Check Windows Update log files in `C:\Windows\Logs\WindowsUpdate\`

### Execution Policy Error

**Solution**: Use the bypass method shown in the Usage section, or modify the execution policy for your user account.

## Technical Details

### COM Objects Used

- `Microsoft.Update.Session` - Creates update session and searcher
- `Microsoft.Update.UpdateColl` - Collection of updates to install
- `Microsoft.Update.UpdateDownloader` - Handles update downloads
- `Microsoft.Update.UpdateInstaller` - Handles update installation

### Registry Checks for Reboot

The script checks multiple registry locations for pending reboot:
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`

## Security Considerations

- Always verify the script source before running
- Run only on trusted systems
- The script requires administrator privileges and can modify system settings
- Review the script contents if downloaded from the internet

## License

This script is provided as-is for automation purposes. Use at your own risk.

## Contributing

Suggestions and improvements are welcome. Please ensure any modifications maintain backward compatibility and include appropriate error handling.

