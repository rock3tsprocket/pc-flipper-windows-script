. "bin\functions.ps1"

Test-AdminPrivileges

Install-Prerequisites
Import-Module AnyBox

Install-GPUDrivers

New-Item -Type Directory -Path "chipset"
Install-ChipsetDrivers
Write-Host "Chipset drivers have finished installing."

Open-MotherboardDriverPage

Start-WindowsTweaks
Restart-WindowsExplorer

$selectedApps = New-AppInstallerWindow
Install-SelectedApps -SelectedApps $selectedApps

if ($furmarkInstalled) {
    Get-UserChoice -readHostMessage "[Y] Yes [N] No" -choicePrompt "It appears that you have installed FurMark, would you like to run a stress test?" -keys "Y", "N" -choiceActions @{
        choiceIsY = { Start-FurmarkTest }
    }
}

Show-ScriptCompleteBox