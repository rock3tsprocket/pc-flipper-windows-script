$mainFolderPath = "$env:temp\pc-flipper-script"
$scriptDownloadPath = "bin"
$scriptDownloadPathFull = "$mainFolderPath\$scriptDownloadPath"

# Deletes old files to avoid conflicts if you've run the script before.
if (Test-Path -Path "$mainFolderPath") { Remove-Item -Recurse -Force -Confirm:$false -Path "$mainFolderPath" }

# Creates new directory for files and scripts
New-Item -Type Directory -Path "$mainFolderPath" | Out-Null

# Sets location to the script folder
Set-Location -Path "$mainFolderPath"


# SCRIPT DOWNLOADS
New-Item -Type Directory -Path "$scriptDownloadPath" | Out-Null
New-Item -Type Directory -Path "$scriptDownloadPath\mas" | Out-Null

# Main Script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "$scriptDownloadPath\pc-flip-preparation-script.ps1"

# hwid.cmd
# convert line endings lf to crlf
$masUrl = "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/mas/hwid.cmd"
$masOutFilePath = "$scriptDownloadPathFull\mas\hwid.cmd"
$lfcontent = (Invoke-WebRequest -UseBasicParsing -Uri $masUrl).Content
$crlfContent = $lfcontent -replace "`r?`n", "`r`n"
[System.IO.File]::WriteAllText($masOutFilePath, $crlfContent, [System.Text.Encoding]::UTF8)

# Changes PowerShell's execution policy to Unrestricted and run script
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
powershell.exe ".\bin\pc-flip-preparation-script.ps1"