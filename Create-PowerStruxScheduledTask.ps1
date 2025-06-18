param (
    [string]$ComputerName = "localhost", # Target system (local or remote)
    [string]$TaskName = "Initiate PowerStrux", # Scheduled task name
    [string]$ExecutablePath = "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\Initiate-PowerStruxWA.exe", # Path to executable
    [string]$TriggerTime = "03:00AM", # Time the task should trigger
    [ValidateSet("Daily", "Weekly")]
    [string]$ScheduleType = "Weekly", # Frequency of task
    [string]$DayOfWeek = "Monday",
    [string]$User = "SYSTEM", # Account to run task as (default is SYSTEM)
    [string]$CertThumbprint = "9147D6FA4DD42EDCD983300B485A396D060B9214", # Thumbprint of code signing cert
    [string]$CertPath = "$PSScriptRoot\2025 - 2027 SecureStrux Code Signing Certificate.cer"  # Path to .cer file for import if needed
)

# Checks if certificate exists in Trusted Publisher store; imports if not
function Test-CodeCertificate {
    param (
        [string]$Thumbprint,
        [string]$CertPath
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "TrustedPublisher", "LocalMachine"
    $store.Open("ReadWrite")  # Open store with write access

    # Look for cert by thumbprint
    $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }

    if (-not $found) {
        Write-Warning "Certificate not found in Trusted Publishers. Attempting to import..."
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertPath
            $store.Add($cert)
            Write-Host "Certificate imported successfully."
        }
        catch {
            Write-Error "Failed to import certificate: $_"
            $store.Close()
            return $false
        }
    }

    $store.Close()
    return $true
}

# Checks if the remote system is online and WinRM is running
function Test-RemoteConnectivity {
    param ([string]$Target)

    # Ping the target
    if (-not (Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Warning "Host [$Target] is unreachable."
        return $false
    }

    try {
        # Check WinRM service
        $winrmService = Get-Service -ComputerName $Target -Name WinRM -ErrorAction Stop
        if ($winrmService.Status -ne 'Running') {
            Write-Host "WinRM is not running on [$Target]. Attempting to start..."
            Start-Service -InputObject $winrmService -ErrorAction Stop
            Start-Sleep -Seconds 3
        }

        $status = (Get-Service -ComputerName $Target -Name WinRM).Status
        if ($status -ne 'Running') {
            Write-Warning "WinRM failed to start on [$Target]."
            return $false
        }
    }
    catch {
        Write-Warning "Could not query or start WinRM on [$Target]: $_"
        return $false
    }

    return $true
}

# Creates the scheduled task on the current system
function Create-ScheduledTask {
    param (
        [string]$Name,
        [string]$ExePath,
        [string]$Time,
        [string]$Frequency,
        [string]$RunUser
    )

    # Define trigger based on frequency
    switch ($Frequency) {
        "Daily" { $Trigger = New-ScheduledTaskTrigger -Daily -At $Time }
        "Weekly" { $Trigger = New-ScheduledTaskTrigger -Weekly -At $Time -DaysOfWeek $DayOfWeek }
    }

    # Define the action to run the executable
    $Action = New-ScheduledTaskAction -Execute $ExePath

    # Define the principal (user) and register the task
    if ($RunUser -eq "SYSTEM") {
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $Name -Trigger $Trigger -Action $Action -Principal $Principal -Force
    }
    else {
        Register-ScheduledTask -TaskName $Name -Trigger $Trigger -Action $Action -User $RunUser -RunLevel Highest -Force
    }
}

# === Main Execution Block ===

#Create an array that contains the target Computer Name, IP Addresses, and localhost.
#The array will be compared against the $ComputerName parameter to whether the target is local or remote.
$arrIsLocalHost = @()
$arrIsLocalHost += Get-NetIPAddress | Select-Object -ExpandProperty IPAddress
$arrIsLocalHost += $env:COMPUTERNAME
$arrIsLocalHost += "localhost"

# If the target is the local computer then set the $boolIsLocalHost variable to $true, otherwise set it to $false.
# This allows the script to dynamically assign cmdlet parameters based on local or remote status.
$boolIsLocalHost = $arrIsLocalHost.Contains($ComputerName)

if ($boolIsLocalHost -eq $TRUE) {
    # Local system: ensure cert exists/imported, then create task
    if (-not (Test-CodeCertificate -Thumbprint $CertThumbprint -CertPath $CertPath)) {
        Write-Error "Certificate check/import failed. Aborting."
        return
    }

    Create-ScheduledTask -Name $TaskName -ExePath $ExecutablePath -Time $TriggerTime -Frequency $ScheduleType -RunUser $User
}
else {
    # Remote: connectivity checks (ping + WinRM)
    if (-not (Test-RemoteConnectivity -Target $ComputerName)) {
        Write-Warning "Remote pre-checks failed. Aborting."
        return
    }

    # Copy the cert file to remote temp location
    $remoteCertPath = "C:\Program Files\WindowsPowerShell\Modules\ReportHTML\2025 - 2027 SecureStrux Code Signing Certificate.cer"
    Copy-Item -Path $CertPath -Destination "\\$ComputerName\C$\Program Files\WindowsPowerShell\Modules\ReportHTML" -Force -ErrorAction Stop

    # Remotely check/import cert and create task
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($TaskName, $ExecutablePath, $TriggerTime, $ScheduleType, $User, $Thumbprint, $remoteCertPath, $DayOfWeek)

        # Remote cert check/import logic
        function Test-CodeCertificateRemote {
            param (
                [string]$Thumbprint,
                [string]$CertPath
            )

            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "TrustedPublisher", "LocalMachine"
            $store.Open("ReadWrite")  # Open store with write access

            # Look for cert by thumbprint
            $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }

            if (-not $found) {
                Write-Warning "Certificate not found in Trusted Publishers. Attempting to import..."
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertPath
                    $store.Add($cert)
                    Write-Host "Certificate imported successfully."
                }
                catch {
                    Write-Error "Failed to import certificate: $_"
                    $store.Close()
                    return $false
                }
            }

            $store.Close()
            return $true
        }

        # Remote task creation logic
        function Create-ScheduledTaskRemote {
            param($Name, $ExePath, $Time, $Frequency, $RunUser)

            switch ($Frequency) {
                "Daily" { $Trigger = New-ScheduledTaskTrigger -Daily -At $Time }
                "Weekly" { $Trigger = New-ScheduledTaskTrigger -Weekly -At $Time -DaysOfWeek $DayOfWeek }
            }

            $Action = New-ScheduledTaskAction -Execute $ExePath

            if ($RunUser -eq "SYSTEM") {
                $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -TaskName $Name -Trigger $Trigger -Action $Action -Principal $Principal -Force
            }
            else {
                Register-ScheduledTask -TaskName $Name -Trigger $Trigger -Action $Action -User $RunUser -RunLevel Highest -Force
            }
        }

        # Import cert and create task
        if (-not (Test-CodeCertificateRemote -Thumbprint $Thumbprint -CertPath $remoteCertPath)) {
            Write-Error "Cert import failed. Aborting remote task creation."
            return
        }

        Create-ScheduledTaskRemote -Name $TaskName -ExePath $ExecutablePath -Time $TriggerTime -Frequency $ScheduleType -RunUser $User

        # Optional: Clean up temp cert file
        Remove-Item -Path $remoteCertPath -Force -ErrorAction SilentlyContinue

    } -ArgumentList $TaskName, $ExecutablePath, $TriggerTime, $ScheduleType, $User, $CertThumbprint, $remoteCertPath, $DayOfWeek
}
