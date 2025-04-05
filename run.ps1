$mainFolderPath = "$env:temp\pc-flipper-script"
# $scriptDownloadPath = "$mainFolderPath\bin"
$scriptDownloadPath = "bin"

# Deletes old files to avoid conflicts if you've run the script before.
if (Test-Path -Path "$mainFolderPath") {
    Remove-Item -Recurse -Force -Confirm:$false -Path "$mainFolderPath"
}

# Creates new directory for files and scripts
New-Item -Type Directory -Path "$mainFolderPath"

# Sets location to the script folder
Set-Location -Path "$mainFolderPath"


# SCRIPT DOWNLOADS
New-Item -Type Directory -Path "$scriptDownloadPath"

# UNCOMMENT THIS FOR MAIN BRANCH
# Main Script
# Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "$scriptDownloadPath\pc-flip-preparation-script.ps1"
# functions.ps1
# Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/functions.ps1" -OutFile "$scriptDownloadPath\functions.ps1"

# UNCOMMENT THIS FOR TESTING UNSTABLE BRANCH
# Main Script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/testing-unstable/pc-flip-preparation-script.ps1" -OutFile "$scriptDownloadPath\pc-flip-preparation-script.ps1"
# functions.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/testing-unstable/functions.ps1" -OutFile "$scriptDownloadPath\functions.ps1"

# Changes PowerShell's execution policy to Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Runs the main script
powershell.exe ".\pc-flip-preparation-script.ps1"
