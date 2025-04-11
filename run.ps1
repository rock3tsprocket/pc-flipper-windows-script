$mainFolderPath = "$env:temp\pc-flipper-script"
$scriptDownloadPath = "bin"

# Deletes old files to avoid conflicts if you've run the script before.
if (Test-Path -Path "$mainFolderPath") { Remove-Item -Recurse -Force -Confirm:$false -Path "$mainFolderPath" }

# Creates new directory for files and scripts
New-Item -Type Directory -Path "$mainFolderPath"

# Sets location to the script folder
Set-Location -Path "$mainFolderPath"


# SCRIPT DOWNLOADS
New-Item -Type Directory -Path "$scriptDownloadPath"

# Main Script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "$scriptDownloadPath\pc-flip-preparation-script.ps1"
# functions.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/functions.ps1" -OutFile "$scriptDownloadPath\functions.ps1"
# hwid.cmd
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/mas/hwid.cmd" -OutFile "$scriptDownloadPath\mas\hwid.cmd"

# Changes PowerShell's execution policy to Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Runs the main script
powershell.exe ".\pc-flip-preparation-script.ps1"