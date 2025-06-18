# Create-PowerStruxScheduledTask
This PowerShell script automates the creation of a scheduled task on either a local or remote Windows system.

---

## Requirements

- Windows PowerShell 5.1 or later
- Administrator rights on the target system
- WinRM must be enabled and accessible for remote deployments
- Administrative access to admin shares (`C$`) for copying files
- Valid and trusted `.cer` file for code signing

---

## Features

- Supports both local and remote deployment
- Automatically checks for and installs code signing certificates
- Verifies remote connectivity and WinRM availability
- Schedules tasks as SYSTEM or a specified user
- Supports Daily or Weekly task execution
- Handles cleanup of temporary files on remote systems

## Instructions

1. Open PowerShell as **Administrator** on your management machine.
2. Copy the `.cer` certificate file to a known local path (e.g., `C:\Certificates\MyCert.cer`).
3. Download or clone this script to your local machine.
4. Run the script using parameters appropriate for your use case. Example:

   ```powershell
   .\Initiate-PowerStrux.ps1 \
       -ComputerName "Server01" \
       -TaskName "Initiate PowerStrux" \
       -ExecutablePath "C:\Program Files\MyApp\Initiate-PowerStruxWA.exe" \
       -TriggerTime "02:00AM" \
       -ScheduleType "Weekly" \
       -DayOfWeek "Friday" \
       -User "SYSTEM" \
       -CertThumbprint "9147D6FA4DD42EDCD983300B485A396D060B9214" \
       -CertPath "C:\Certificates\MyCert.cer"
   ```

6. Verify the task was created by checking Task Scheduler on the target machine.

---

## Parameters

| Name             | Description |
|------------------|-------------|
| `ComputerName`    | Target hostname or IP address. Default is `localhost`. |
| `TaskName`        | Name of the scheduled task. Default is `Initiate PowerStrux`. |
| `ExecutablePath`  | Full path to the executable to run. Required. |
| `TriggerTime`     | Time to trigger the task (e.g., `03:00AM`). Default is `03:00AM`. |
| `ScheduleType`    | Task frequency. Accepts `Daily` or `Weekly`. Default is `Weekly`. |
| `DayOfWeek`       | Day for weekly execution. Only used if `ScheduleType` is `Weekly`. Default is `Monday`. |
| `User`            | Account to run the task under. Default is `SYSTEM`. |
| `CertThumbprint`  | Thumbprint of the code signing certificate. Required. |
| `CertPath`        | Full path to the `.cer` certificate file for importing the certificate if it's missing. |

## Troubleshooting

- **WinRM connection issues**: Run `Enable-PSRemoting -Force` on the remote system and ensure firewall rules allow WinRM.
- **Certificate import fails**: Verify that the certificate is valid, unexpired, and accessible at the specified path.
- **Task does not appear or run**: Check Task Scheduler and ensure the account running the task has sufficient permissions and the executable path is valid.

---
