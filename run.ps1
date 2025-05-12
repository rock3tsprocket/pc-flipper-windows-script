$mainFolderPath = "$env:temp\pc-flipper-script"
$scriptDownloadPath = "bin"

# Deletes old files to avoid conflicts if you've run the script before.
if (Test-Path -Path "$mainFolderPath") { 
    Remove-Item -Recurse -Force -Confirm:$false -Path "$mainFolderPath" 
}

# Creates new directory for files and scripts
New-Item -Type Directory -Path "$mainFolderPath" | Out-Null

# Sets location to the script folder
Set-Location -Path "$mainFolderPath"

# SCRIPT DOWNLOADS
New-Item -Type Directory -Path "$scriptDownloadPath" | Out-Null
# Downloads main script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "$scriptDownloadPath\pc-flip-preparation-script.ps1"

# Changes PowerShell's execution policy and run script
# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
powershell.exe -ExecutionPolicy Bypass -File ".\bin\pc-flip-preparation-script.ps1"
