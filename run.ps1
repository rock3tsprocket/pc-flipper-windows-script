# Set variables:
$temp = $env:Temp
$folderName = "pc-flipper-script"
$scriptName = "pc-flip-preparation-script.ps1"

# Changes directory to the Windows temp folder.
Set-Location $temp

# Deletes old Windows Toolbox files to avoid conflicts if you've run the script before.
Remove-Item -Recurse -Force -Confirm:$false "$folderName"
# Creates new directory for UltimateWindowsToolbox's files and scripts
New-Item -Name "$folderName" -Type Directory

# Sets location to the windows toolbox folder
Set-Location "$folderName"

# Downloads main script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "$scriptName"

# Changes PowerShell's execution policy to Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Runs the script
powershell.exe ".\scriptName"
