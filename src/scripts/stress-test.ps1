$process = Start-Process -FilePath ".\ransy_x86.exe" -PassThru

# Start the ransomware
Start-Sleep -Milliseconds 1000
Write-Host "Capturing PID: $process.Id"
#.\craper_x86.exe $process.Id p

# Stress test
$executionTimes = @()
foreach ($number in 1..100) {
    $time = (Measure-Command -Expression {
        # Start the analysis
        .\craper_x86.exe $process.Id p
    }).TotalSeconds

    $executionTimes += $time
}

# Stop the ransomware and calculte the average
Stop-Process -Id $process.Id -Force
$average = ($executionTimes | Measure-Object -Average).Average
Write-Output "Average execution time $average seconds"
