$insecureProtocols = @('FTP', 'Telnet', 'HTTP', 'SMBv1')

Function Get-NetworkTraffic {
    Param (
        [string]$Interface = "Ethernet"
    )
    Get-NetTCPConnection -State Established | Where-Object { $_.LocalAddress -like '192.168.*' -or $_.RemoteAddress -like '192.168.*' }
}

Function Detect-InsecureProtocols {
    $networkTraffic = Get-NetworkTraffic
    foreach ($connection in $networkTraffic) {
        foreach ($protocol in $insecureProtocols) {
            if ($connection.ApplicationProtocol -eq $protocol) {
                Write-Warning "Insecure protocol detected: $protocol on connection $($connection.LocalAddress) to $($connection.RemoteAddress)"
                Send-Alert $protocol $connection
            }
        }
    }
}

Function Send-Alert {
    Param (
        [string]$Protocol,
        [Microsoft.PowerShell.Commands.GetNetTCPConnection]$Connection
    )
    $message = "Alert: Insecure protocol $Protocol detected between $($Connection.LocalAddress) and $($Connection.RemoteAddress)."
    [System.Console]::WriteLine($message)
    # Optionally, send email alert
    # Send-MailMessage -To "admin@example.com" -From "alert@example.com" -Subject "Insecure Protocol Detected" -Body $message -SmtpServer "smtp.example.com"
}

while ($true) {
    Detect-InsecureProtocols
    Start-Sleep -Seconds 60
}
