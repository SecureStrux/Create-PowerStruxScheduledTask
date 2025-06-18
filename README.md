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

---

## Instructions

## Instructions

1. Download the repository as a ZIP archive from GitHub.
2. Extract the ZIP archive to a known location (e.g., `C:\Scripts\InitiatePowerStrux`).
3. Open PowerShell **as Administrator**.
4. Change to the extracted directory:
   ```powershell
   Set-Location -Path "C:\Scripts\InitiatePowerStrux"
   ```
5. Run the script with appropriate parameters. Example:
   ```powershell
   .\Initiate-PowerStrux.ps1 `
       -ComputerName "Server01" `
       -TriggerTime "02:00AM" `
       -ScheduleType "Weekly" `
       -DayOfWeek "Friday" `
   ```
6. Verify the task was created by checking Task Scheduler on the target machine.

---
