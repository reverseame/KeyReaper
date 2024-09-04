# Script for automatically running the analyzer after the ransomware
$ransomware = ".\ransy_x64.exe"
$process = Start-Process -FilePath "$ransomware" -PassThru

# Give the process enough time for generating keys
Start-Sleep -Milliseconds 1000
Write-Host "Capturing PID: $process.Id" 

# Start the analysis
.\craper_x64.exe $process.Id p

# Run as admin (willa prompt the user)
#Start-Process -FilePath "cmd.exe" -ArgumentList "/c start C:\Users\Leon\Documents\craper\craper_x86.exe $process.Id p" -PassThru -Verb RunAs
