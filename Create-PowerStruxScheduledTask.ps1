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

Function Test-CodeSignatureTrust {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Path to the file whose digital signature will be validated
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        # Array of expected (trusted) certificate thumbprints
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedThumbprints
    )

    try {
        # Retrieve digital signature details from the specified file
        $signatureInfo = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop

        # Extract and normalize the thumbprint from the signer's certificate
        $actualThumbprint = $signatureInfo.SignerCertificate.Thumbprint.ToUpper()
    }
    catch {
        # Warn and return false if signature cannot be retrieved
        Write-Warning "Unable to obtain digital signature information for $FilePath`: $_"
        return $false
    }

    # Normalize all expected thumbprints for case-insensitive comparison
    $normalizedExpectedThumbprints = $ExpectedThumbprints | ForEach-Object { $_.ToUpper() }

    # Validate the signature and check the thumbprint against expected values
    if ($signatureInfo.Status -ne "Valid" -or $actualThumbprint -notin $normalizedExpectedThumbprints) {
        Write-Warning "The digital signature is either not valid or does not match an expected thumbprint."
        return $false
    }

    # Signature is valid and from an expected certificate
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

    if (-not (Test-CodeSignatureTrust -FilePath $ExecutablePath -ExpectedThumbprints $CertThumbprint)) {
        Write-Error "The digital signature's thumbprint applied to $ExecutablePath does not match $CertThumbprint ."
        return
    }

    if (-not (Test-CodeSignatureTrust -FilePath 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTML.psm1' -ExpectedThumbprints $CertThumbprint)) {
        Write-Error "The digital signature's thumbprint applied to C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTML.psm1 does not match $CertThumbprint ."
        return
    }

    if (-not (Test-CodeSignatureTrust -FilePath 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTMLHelp.psm1' -ExpectedThumbprints $CertThumbprint)) {
        Write-Error "The digital signature's thumbprint applied to C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTMLHelp.psm1 does not match $CertThumbprint ."
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

        Function Test-CodeSignatureTrustRemote {
            [CmdletBinding()]
            [OutputType([bool])]
            param (
                # Path to the file whose digital signature will be validated
                [Parameter(Mandatory = $true)]
                [string]$FilePath,

                # Array of expected (trusted) certificate thumbprints
                [Parameter(Mandatory = $true)]
                [string[]]$ExpectedThumbprints
            )

            try {
                # Retrieve digital signature details from the specified file
                $signatureInfo = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop

                # Extract and normalize the thumbprint from the signer's certificate
                $actualThumbprint = $signatureInfo.SignerCertificate.Thumbprint.ToUpper()
            }
            catch {
                # Warn and return false if signature cannot be retrieved
                Write-Warning "Unable to obtain digital signature information for $FilePath`: $_"
                return $false
            }

            # Normalize all expected thumbprints for case-insensitive comparison
            $normalizedExpectedThumbprints = $ExpectedThumbprints | ForEach-Object { $_.ToUpper() }

            # Validate the signature and check the thumbprint against expected values
            if ($signatureInfo.Status -ne "Valid" -or $actualThumbprint -notin $normalizedExpectedThumbprints) {
                Write-Warning "The digital signature is either not valid or does not match an expected thumbprint."
                return $false
            }

            # Signature is valid and from an expected certificate
            return $true
        }

        # Import cert and create task
        if (-not (Test-CodeCertificateRemote -Thumbprint $Thumbprint -CertPath $remoteCertPath)) {
            Write-Error "Cert import failed. Aborting remote task creation."
            return
        }

        if (-not (Test-CodeSignatureTrustRemote -FilePath $ExecutablePath -ExpectedThumbprints $Thumbprint)) {
            Write-Error "The digital signature's thumbprint applied to $ExecutablePath does not match $Thumbprint ."
            return
        }

        if (-not (Test-CodeSignatureTrustRemote -FilePath 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTML.psm1' -ExpectedThumbprints $Thumbprint)) {
            Write-Error "The digital signature's thumbprint applied to C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTML.psm1 does not match $Thumbprint ."
            return
        }

        if (-not (Test-CodeSignatureTrustRemote -FilePath 'C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTMLHelp.psm1' -ExpectedThumbprints $Thumbprint)) {
            Write-Error "The digital signature's thumbprint applied to C:\Program Files\WindowsPowerShell\Modules\ReportHTML\1.4.1.2\ReportHTMLHelp.psm1 does not match $Thumbprint ."
            return
        }

        Create-ScheduledTaskRemote -Name $TaskName -ExePath $ExecutablePath -Time $TriggerTime -Frequency $ScheduleType -RunUser $User

        # Optional: Clean up temp cert file
        Remove-Item -Path $remoteCertPath -Force -ErrorAction SilentlyContinue

    } -ArgumentList $TaskName, $ExecutablePath, $TriggerTime, $ScheduleType, $User, $CertThumbprint, $remoteCertPath, $DayOfWeek
}

# SIG # Begin signature block
# MIIoZgYJKoZIhvcNAQcCoIIoVzCCKFMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB/tcO4iodrjvCn
# CiYkpiAjZOKdZbvLbUjrpd4VWyY8YaCCDZwwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggbkMIIEzKADAgECAhAK+QKGTe+/MPpscRiU2yndMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjQwODE1MDAwMDAwWhcNMjcwODMw
# MjM1OTU5WjBsMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRIw
# EAYDVQQHEwlMYW5jYXN0ZXIxGDAWBgNVBAoTD1NlY3VyZVN0cnV4IExMQzEYMBYG
# A1UEAxMPU2VjdXJlU3RydXggTExDMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEA4b6Y2BiEX7bdOCFVTQsZogfL0ueF+uYRW8LeVVKPAhUYigg80C+Mopsh
# 9/DIsSYzwEHH/lcvWfRfGJtlEKGKBdDP3gdLbEjgBxrzQbbxycO1SUQaLioHeLA1
# r3E6Nw2fiDwJ7ImxIMG4iwsoo8DbaR22oTi8nH0vEmyXawnGOz5gg9YOoXYtxgmN
# 614JIaOAzjKyZhdSs5NvwOhmT/XWkP4v76l4GuZbCZ0mLBT02iV2ZPjJVzDRSRW+
# 7II0cvp8n/92ZLqVsoi70qENLsmMF7mT3Sp6dHPLlil6o5oU80YrHcxSp8HJkzGe
# ghToTeOAoHjBK2HET+w6ALpJYUrpz1ZK94LTDMiqKMdYRD9z/qq3RnClO2nASBjq
# l1DmxkvrxWiT2kFvGu4maHiwTsxIuRx2EVCgu5Ju6znOAysYEOMZTBEtMSn+GYtK
# qpTiJfmZvGhKEad7tQI0fM4KE0eFeMUbkbiQxmSB8Cm4vgPNFeRkCDzOAH3KlwpH
# b3LANW6jAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQUJ0oFI6IcLSL2vRvWctc1Q1nqLi4wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBALO0iBY6A5vb6JoZRFapFP59aqGkKqTq3J5L
# nwbqb+4xbhUt1oWVaDP7OeMg5uIEavu5JLFhPj3kAQHC5hCc/WED9qPKs+9j5IJT
# n2JMMiNVwc3rtEaKDw+ZU1Pi1nhDqUIIapmFJ1f/DWgj7HXmliyxj7/sgaKzRCLK
# xk5HCA2L4QwQrrVGh8SP0B5J41hEcjAk7TTJmq3+8fha6V/AEvf3jTw0efiq/+3J
# VR+1vsGL2ujEZUMZ/R/V78X93NM3iCJzzW2a6GeqzZh8iClMbuO+mAir68tHdFhF
# j0MwdjlQK+UdkkI+mcjUrrUtqAU3xuafNfyuV+l2WpVi0giajcm1Is4Cpf1u6Pb9
# UzJfIo3/ygKNLiMKfwP4Nm1fW7gwZte+cdjk1erhsQtm9X4TP01ZUD0MVj2cnmK8
# 1lanxnb8J1csheUk9QoMdvDllz1icaIKiwCiQZBGq+5XpUCZqnmpiBrekcPpwGyB
# O82HrNzb0GhsYbcK5jZ98ataad7XJw2tE49LUJAGiv2SP0kYvGzoTJ4zpkEy7Ks/
# EbYAEtRz+o9QmzO3p8kw6MJW7sK28pTUaqXWmYiXz5jMxK+Pz37+Bv+DG8bn942Q
# 4I6pXPpmA/tpBwQrdNhlHvc2eusFQ4F7muO4FioafeH8NXUgvBUjj3i6cR3HZwQV
# Ef4lQCufMYIaIDCCGhwCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAK+QKGTe+/MPpscRiU2ynd
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIKm0Cg/z+CSAs+tbkUh29I0fTIgyTSUOlxkUoCAH40jHMA0G
# CSqGSIb3DQEBAQUABIIBgIwLjACmlOcuOauXnTK3djE4eLkD5S5BimL2XTUapNPq
# CSERLP3tj8hcJ7Jh7RFYAzcnp5LhVqUgfSfuG2eNOe6UthYzZD6qH7jnO8RJewy3
# igswy+QI4XmAdKzDiUuWZc0ZGSsqb0ye6BDfucpe3HCefNVYSCrA4QBwRrQ5UTCx
# f9tSsbGhUXf3onRRbKMn3qVgVoBDvyNeqy1JtgJ1xrE5pOzP/FIIp6LfFFkR6xuo
# Frp4AfhGJGpp5Ic0/Bt7EoWOaiQwhbSB+HeCewRNq0bVxrcVXg5eAXAvUO5DtRhG
# Sypjqtion+CE7FgInKDSBLU9gC3EJVOfgElKgjyYC5b5s0RtXr9AwLRCHDqGRYub
# IQtTFl5Xp468yEUkWo1JuVFJM/YRF559BdmLDh2uJgXzMUmPogzM9GR/HbiOL2Fy
# +4I3WpDmEBwwOcOHWgMFPLhf10DAOuuAu3k3jrRwkMDOgaV8kYHbF9qEx9jRZa6c
# 5K7W/tw32JdmTuHuLNTU9aGCF3YwghdyBgorBgEEAYI3AwMBMYIXYjCCF14GCSqG
# SIb3DQEHAqCCF08wghdLAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCyLywvPJ4e
# pDBrRPiconbo1BYeKgkjX21uWtieKYfREQIQF4B/6faFxngC7QWmTnEPChgPMjAy
# NTA5MTcxOTU2MzJaoIITOjCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgw
# DQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5
# MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJl
# c3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQ
# RqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8
# AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSb
# f+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAl
# dytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkT
# lCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA
# 98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmH
# HjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvu
# ndrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5av
# Mcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGi
# fgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHN
# m0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYD
# VR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0j
# BBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1w
# aW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQC
# MAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhE
# nmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPB
# VBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+
# 2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM
# 4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F
# /0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZ
# agHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaE
# t2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66G
# p3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUX
# f53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW
# +yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3
# Qrx5bIbY3TVzgiFI7Gq3zWcwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmG
# MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5
# NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0
# eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+Ruw
# OnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4B
# t0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1U
# kxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTca
# arps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zb
# CclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnG
# pTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/
# AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v
# 5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoi
# wOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm
# 2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Q
# h8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3
# YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQ
# wr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/
# wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81
# hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00
# TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNj
# qFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0
# cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9
# sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0
# LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2
# tszWkPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG
# 9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1
# cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAi
# MGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnny
# yhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE
# 5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm
# 7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5
# w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsD
# dV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1Z
# XUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS0
# 0mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hk
# pjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m8
# 00ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+i
# sX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReui
# r/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0w
# azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF
# BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAG
# BgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9
# mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxS
# A8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/
# 6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSM
# b++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt
# 9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDfDCC
# A3gCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQC
# AQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUx
# DxcNMjUwOTE3MTk1NjMyWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTdYjCshgot
# MGvaOLFoeVIwB/tBfjAvBgkqhkiG9w0BCQQxIgQganvY5+7HRv71UlBOQd/XMTUL
# 6LqDDRC2QalemnYuEfUwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgSqA/oizXXITF
# XJOPgo5na5yuyrM/420mmqM08UYRCjMwDQYJKoZIhvcNAQEBBQAEggIAEjUICf8E
# 9PYmNG1ud63iKEmkRE+4Tj/KuE0BGPvlhi72drGI6b6po5rwPs7uEOuoAmyJapU3
# TiGvzeLhTP0en5nE0+mQTE36VKcoPUTrEVo+0fvfF01WZWVKnZExIxWtz/HdLfZS
# n5sZGIHJpL2/VV1e1nfjMXLUjex8usS8KbvkgxltTBH/nwBI9BK+rrqfABJIoBKL
# JIRoJEHueulzBiY0PsDP5GLgFyuifCQFyXKG2pOXR09uXoIdxwRLBbm3ZVGcRHzx
# tVHoRFB/onAZxquUvBmdnVx8UWybhi3kn0YHg6GJVx40XsGSEFqyEikHtsPP7Qut
# 9b8G3GwEI/uqpqop5FnanoWRylORl99zxUO/OrQyU6m+omOyyiIHc9k5fr0BVwLZ
# yRnORVdMLOaLnuw/+pHJvoj+yAqD5+SSaoMAdHG924682raFE/Dy1vemTRIQdtys
# pfLxrPFqwnPSPjs733QvMf4cTHmr5YyseQ1AANQpZkZqd8esBSIjwYEZ8qXEyhU1
# lUOhLhzTQ4cRxBqEyxB1A07yrBLO/cIS2Ll5pURv8aS6G22KFHPZBJNTnQaCcz5x
# m6hwMjHQn5Rk8XHNo+rkjpBevWtMvjntWHnUyGZ4/A1XNn3Y4aaE6Hc78HqzkDmf
# FJQMV4fWGpM8l56D5pbMD02HM8DG++MMAPU=
# SIG # End signature block
