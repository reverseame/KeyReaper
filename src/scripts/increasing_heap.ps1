for ($i = 0; $i -le 300; $i += 10) {
    # Write the number 100 to the first line and the iteration number to the second line of "test.txt"
    "100`r`n$i" | Set-Content -Path ".\test.txt"

    # Run the ransomware in the background
    $process1 = Start-Process -FilePath ".\ransy_x86.exe" -PassThru

    # Wait for ransomware to generate keys
    Start-Sleep -Seconds 5

    # Start KeyReaper
    Start-Process -FilePath ".\KeyReaper_x86.exe" -ArgumentList "scan --scanners crapi --pid ", $process1.Id -Wait -NoNewWindow

    # Forcefully stop the ransomware
    Stop-Process -Id $process1.Id -Force
}