$count = 0
for ($i = 0; $i -le 100; $i += 1) {

    # Run the ransomware in the background
    $process1 = Start-Process -FilePath ".\ransy_x86.exe" -PassThru

    # Wait for ransomware to generate keys
    Start-Sleep -Seconds 5

    # Start KeyReaper
    Start-Process -FilePath ".\KeyReaper_x86.exe" -ArgumentList "scan --scanners crapi -x -a kill -o krkeys.json --pid ", $process1.Id -Wait #-NoNewWindow

    # Forcefully stop the ransomware
    # Stop-Process -Id $process1.Id -Force

    $hash1 = (Get-FileHash -Algorithm MD5 "keys_ransy.json").Hash
    $hash2 = (Get-FileHash -Algorithm MD5 "krkeys.json").Hash

    if ($hash1 -eq $hash2) {
        Write-Host "Hashes match"
    } else {
        Write-Host "Hashes do not match"
        $count += 1
    }
}

Write-Host "Mismatches:" $count