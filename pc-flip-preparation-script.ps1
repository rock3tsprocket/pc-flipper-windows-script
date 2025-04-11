. .\functions.ps1
$ProgressPreference = 'SilentlyContinue' # for commands like invoke-webrequest/invoke-restmethod

# Start Transcript
Start-Logging

Write-Host "Checking for administrator privileges..."
Test-AdminPrivileges
Write-Host "Checking for internet and DNS..."
Test-Internet
# unless I overlooked something, this will only print when the checks are successful since both functions interrupt the script if they fail
Write-Host -ForegroundColor Green "Success"

# Install prerequisites and import modules
Install-Prerequisites
Import-Module AnyBox

# Show the main window and run selected tasks
$selectedTasks = Show-ScriptOptionsWindow
Invoke-SelectedScriptTasks -Tasks $selectedTasks

# Show completion dialog and stop transcript
Show-ScriptCompleteBox
Stop-Transcript