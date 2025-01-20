# Set variables:
$temp = $env:Temp
# I don't remember why I made this variable instead of just using the environment variable but if it ain't broke don't fix it!! :D

# Changes directory to the Windows temp folder.
Set-Location $temp

# Deletes old files to avoid conflicts if you've run the script before.
Remove-Item -Recurse -Force -Confirm:$false "pc-flipper-script"
# Creates new directory for files and scripts
New-Item -Name "pc-flipper-script" -Type Directory

# Sets location to the script folder
Set-Location "pc-flipper-script"

# Downloads main script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1" -OutFile "pc-flip-preparation-script.ps1"

# Changes PowerShell's execution policy to Unrestricted
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Runs the script
powershell.exe ".\pc-flip-preparation-script.ps1"
