# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
Clear-Host
    Write-Host "Failure: Current permissions inadequate. Please run the file again as administrator." -ForegroundColor Red
    Read-Host "Press any key to exit..."
	Exit
}

# WinGet
try {
    winget --version
} catch {
    Write-Host "Winget not present / outdated"
    # Get the download URL of the latest winget installer from GitHub:
    $API_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
    $DOWNLOAD_URL = $(Invoke-RestMethod $API_URL).assets.browser_download_url |
    Where-Object {$_.EndsWith(".msixbundle")}

    # Download the installer:
    Invoke-WebRequest -URI $DOWNLOAD_URL -OutFile winget.msixbundle -UseBasicParsing

    # Install winget:
    Add-AppxPackage winget.msixbundle

    # Remove the installer:
    Remove-Item winget.msixbundle
}


# NuGet (idk if this is necessary or not but whatever)
Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Force -Confirm


# # Commented out since i found a better way to do this
# # AnyBox stuff
# # Check if AnyBox version 0.5.1 is installed
# if (Test-Path "$env:programfiles\WindowsPowerShell\Modules\AnyBox\0.5.1") {
#     Write-Host -ForegroundColor Green "SUCCESS: AnyBox version 0.5.1 is installed. Continuing..."
# } else {
#     # Check if ANY version of AnyBox is installed
#     if (Test-Path "$env:programfiles\WindowsPowerShell\Modules\AnyBox") {
#         Write-Warning "Old version of AnyBox detected. Reinstalling..."
#         Install-PSResource -Name 'AnyBox' -Repository 'PSGallery' -Version '0.5.1' -Reinstall -Quiet -AcceptLicense -TrustRepository 
#     } else {
#         Write-Host -ForegroundColor Red "ERROR: AnyBox not found. Installing..."
#         Install-PSResource -Name 'AnyBox' -Repository 'PSGallery' -Version '0.5.1' -Quiet -AcceptLicense -TrustRepository
#     }
# }


# AnyBox stuff
$moduleName = 'AnyBox'
$requiredVersion = '0.5.1'
$module = Get-Module -ListAvailable -Name $moduleName -All | Where-Object { $_.Version -eq $requiredVersion }
if (-not $module) {
    if (-not (Get-Module PSResourceGet -listavailable -All)) {
        Install-Module -Name $moduleName -RequiredVersion $requiredVersion -Force -TrustRepository -Reinstall -Repository PSGallery -Confirm:$false
    } else {
        Install-PSResource -Name $moduleName -Version $requiredVersion -Force -TrustRepository -Reinstall -Repository PSGallery -Quiet -AcceptLicense
    }
}

Import-Module AnyBox



function Install-GPUDrivers {
    $gpu = Get-CimInstance Win32_VideoController | Where-Object { $_.Status -eq 'OK' -and $_.Availability -eq 3 } | Select-Object Name, AdapterRAM, DriverVersion
    if ($gpu -like "*NVIDIA*" -or $gpu -like "*GeForce*") {
Clear-Host
        Write-Host "Nvidia GPU detected. Drivers downloading and installing..."
	    Remove-Item -Recurse -Force "$env:Temp\Nvidia-Drivers"
        mkdir "$env:Temp\Nvidia-Drivers"
        $nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.1.163/NVIDIA_app_v11.0.1.163.exe" -OutFile "$nvidiaDrivers"
        Write-Output "Drivers successfully downloaded. Press ENTER to install."
        Read-Host
        Start-Process $nvidiaDrivers
    } elseif ($gpu -like "*AMD*" -or $gpu -like "*Radeon*") {
Clear-Host
        Write-Host "AMD GPU detected. Drivers downloading and installing..."
        Remove-Item -Recurse -Force "$env:Temp\AMD-Drivers"
        mkdir "$env:Temp\AMD-Drivers"
        $amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
		$adrenalinDriverLink = (curl.exe "https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/main/configs/link_full.txt")
		curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $adrenalinDriverLink -o $amdDrivers
        Write-Output "Drivers successfully downloaded. Press ENTER to install."
        Read-Host
        Start-Process $amdDrivers
    } elseif ($gpu -like "*Intel*") {
Clear-Host
        Write-Host "Intel GPU detected. Please download manually, this script doesn't currently support Intel iGPUs and Intel Arc GPUs."
        Read-Host "Press ENTER to skip the GPU driver part of this script."
    } else {
        $anybox = New-Object AnyBox.AnyBox
		
        $anybox.Message = 'Error detecting. What brand is your GPU?'

        $anybox.Buttons = @(
            New-AnyBoxButton -Name 'amd' -Text 'AMD'
            New-AnyBoxButton -Name 'nvidia' -Text 'Nvidia'
            New-AnyBoxButton -Name 'other' -Text 'Other'
        )

        # Show the AnyBox; collect responses.
        $response = $anybox | Show-AnyBox

        # Act on responses.
        if ($response['amd'] -eq $true) {
Clear-Host
			Write-Host "Drivers downloading and installing..."
            Remove-Item -Recurse -Force "$env:Temp\AMD-Drivers"
			mkdir "$env:Temp\AMD-Drivers"
			$amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
			$adrenalinDriverLink = (curl.exe "https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/main/configs/link_full.txt")
			curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $adrenalinDriverLink -o $amdDrivers
			Write-Output "Drivers successfully downloaded. Press ENTER to install."
			Read-Host
			Start-Process $amdDrivers
        } elseif ($response['nvidia'] -eq $true) {
Clear-Host
			Write-Host "Drivers downloading and installing..."
            Remove-Item -Recurse -Force "$env:Temp\Nvidia-Drivers"
			mkdir "$env:Temp\Nvidia-Drivers"
			$nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
			$ProgressPreference = 'SilentlyContinue'
			Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.1.163/NVIDIA_app_v11.0.1.163.exe" -OutFile "$nvidiaDrivers"
			Write-Output "Drivers successfully downloaded. Press ENTER to install."
			Read-Host
			Start-Process $nvidiaDrivers
        } elseif ($response['other'] -eq $true) {
Clear-Host
            Write-Host "You selected other, which means your GPU is not from AMD or Nvidia and it is currently unsupported. Please download drivers manually."
            Read-Host "Press any key to continue"
        }
    }
}


function runTweaks {
Clear-Host
    Write-Host "Disabling Search Box Suggestions in start menu..."
    reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f > $null

Write-Output "Disabling Search Box Suggestions in start menu..."
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f > $null

Write-Output "Disabling Location Services..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f > $null

Write-Output "Disabling Windows Error Reporting..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f > $null

Write-Output "Enabling Long File Paths..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f > $null

    Write-Host "Enabling Dark Mode..."
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f > $null
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f > $null

Write-Output "Enabling Dark Mode..."
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f > $null

Write-Output "Disabling Sticky Keys..."
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f

Write-Output "Disabling Toggle Keys..."
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f

    # Check if the OS is Windows 11
    $windowsOSVersion = (systeminfo | findstr /B /C:"OS Name")
    if ($windowsOSVersion -like "*Windows 11*") {
        Write-Host "Aligning taskbar to the left..."
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f > $null
    }

Clear-Host

    Write-Host -ForegroundColor Green "Windows tweaks complete."
}

Clear-Host

# Detect and install GPU drivers
Install-GPUDrivers

# Dot source chipset.ps1 to install chipset drivers
Set-Location "$env:Temp"
Set-Location "pc-flipper-script"
# i can probably just do Set-Location "$env:Temp\pc-flipper-script" but this works so why not
$chipsetPs1Url = "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/testing-unstable/chipset.ps1"
Invoke-WebRequest -Uri "$chipsetPs1Url" -OutFile "chipset.ps1"
# dot source file
. .\chipset.ps1

# Run tweaks
runTweaks
Write-Output "Press ENTER to finish applying the tweaks."
Read-Host
TASKKILL.exe /F /IM explorer.exe
Start-Process "$env:WinDir\explorer.exe"
Write-Output "Tweaks done."

Write-Output "Press ENTER to download and install Firefox Browser."
Write-Host -ForegroundColor Green "Note: More apps coming, and a 'skip' option! Check back soon, and please star the repo!"
Read-Host
# Install Firefox
$FirefoxInstaller = "$env:TEMP\FirefoxInstaller.exe"
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US" -OutFile $FirefoxInstaller
Start-Process -FilePath $firefoxInstaller -ArgumentList "/S" -Wait

Write-Output "Press ENTER to download and install FurMark."
Read-Host
# Install FurMark
$furmarkInstaller = "$env:TEMP\FurMarkInstaller.exe"
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://geeks3d.com/dl/get/738" -OutFile $furmarkInstaller
Start-Process -FilePath $furmarkInstaller -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait

# Prompt the user for the test duration
$furmarkTestDuration = Read-Host -Prompt "Input the duration of the FurMark test in seconds:"

# Convert the duration from seconds to milliseconds
$furmarkTestDuration = [int]$furmarkTestDuration * 1000

# Run FurMark stress test
$furmarkPath = "C:\Program Files (x86)\Geeks3D\Benchmarks\FurMark\FurMark.exe"
Start-Process -FilePath $furmarkPath -ArgumentList "/nogui /width=1920 /height=1080 /msaa=4 /max_time=$furmarkTestDuration"

Write-Output "Once the FurMark test is over, please press ENTER to continue."
Read-Host

Write-Output Cleaning up files, please wait...
Remove-Item -Path $firefoxInstaller | Out-Null
Remove-Item -Path $furmarkInstaller | Out-Null
Remove-Item -Path $nvidiaDrivers | Out-Null
Remove-Item -Path $amdDrivers | Out-Null
Write-Output "Cleanup has finished."

# Create the checkbox window
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Application Installer" Height="$windowHeight" Width="$windowWidth">
    <StackPanel Margin="10">
        <TextBlock Text="App Installer" $titleFontSize $bold $font $textMargin />
        <TextBlock Text="Select the applications you would like to install." $bold $font $textMargin />
        <CheckBox Name="Firefox" Content="Firefox" $font $checkboxMargin />
        <CheckBox Name="Chrome" Content="Chrome" $font $checkboxMargin />
        <CheckBox Name="Steam" Content="Steam" $font $checkboxMargin />
        <CheckBox Name="Discord" Content="Discord" $font $checkboxMargin />
        <CheckBox Name="EpicGamesLauncher" Content="Epic Games Launcher" $font $checkboxMargin />
        <CheckBox Name="OpenRGB" Content="OpenRGB" $font $checkboxMargin />
        <CheckBox Name="SignalRGB" Content="SignalRGB" $font $checkboxMargin />
        <CheckBox Name="VLC" Content="VLC Media Player" $font $checkboxMargin />
        <CheckBox Name="SevenZip" Content="7-Zip" $font $checkboxMargin />
        <CheckBox Name="Malwarebytes" Content="Malwarebytes" $font $checkboxMargin />
        <CheckBox Name="FurMark" Content="FurMark" $font $checkboxMargin /
        <CheckBox Name="HWMonitor" Content="HWMonitor" $font $checkboxMargin />
        <CheckBox Name="MSIAfterburner" Content="MSI Afterburner" $font $checkboxMargin />
        <CheckBox Name="CinebenchR23" Content="Cinebench R23" $font $checkboxMargin />
        <Button Content="OK" Name="OkButton" HorizontalAlignment="Right" Margin="0,10,0,0" Width="75" />
    </StackPanel>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Link checkbox identification variables to the checkboxes in the UI
$firefoxCheckbox = $window.FindName("Firefox")
$chromeCheckbox = $window.FindName("Chrome")
$steamCheckbox = $window.FindName("Steam")
$discordCheckbox = $window.FindName("Discord")
$epicGamesLauncherCheckbox = $window.FindName("EpicGamesLauncher")
$openRGBCheckbox = $window.FindName("OpenRGB")
$signalRGBCheckbox = $window.FindName("SignalRGB")
$vlcCheckbox = $window.FindName("VLC")
$sevenZipCheckbox = $window.FindName("SevenZip")
$malwarebytesCheckbox = $window.FindName("Malwarebytes")
$furmarkCheckbox = $window.FindName("FurMark")
$hwmonitorCheckbox = $window.FindName("HWMonitor")
$msiafterburnerCheckbox = $window.FindName("MSIAfterburner")
$cinebenchCheckbox = $window.FindName("CinebenchR23")
$okButton = $window.FindName("OkButton")

# OK button
$okButton.Add_Click({
    # Update checkbox stuff
    if ($firefoxCheckbox.IsChecked -eq $true) { $script:firefoxChecked = $true }
    if ($chromeCheckbox.IsChecked -eq $true) { $script:chromeChecked = $true }
    if ($steamCheckbox.IsChecked -eq $true) { $script:steamChecked = $true }
    if ($discordCheckbox.IsChecked -eq $true) { $script:discordChecked = $true }
    if ($epicGamesLauncherCheckbox.IsChecked -eq $true) { $script:epicGamesLauncherChecked = $true }
    if ($openRGBCheckbox.IsChecked -eq $true) { $script:openRGBChecked = $true }
    if ($signalRGBCheckbox.IsChecked -eq $true) { $script:signalRGBChecked = $true }
    if ($vlcCheckbox.IsChecked -eq $true) { $script:vlcChecked = $true }
    if ($sevenZipCheckbox.IsChecked -eq $true) { $script:sevenZipChecked = $true }
    if ($malwarebytesCheckbox.IsChecked -eq $true) { $script:malwarebytesChecked = $true }
    if ($furmarkCheckbox.IsChecked -eq $true) { $script:furmarkChecked = $true }
    if ($hwmonitorCheckbox.IsChecked -eq $true) { $script:hwmonitorChecked = $true }
    if ($msiafterburnerCheckbox.IsChecked -eq $true) { $script:msiafterburnerChecked = $true }
    if ($cinebenchCheckbox.IsChecked -eq $true) { $script:cinebenchChecked = $true }

    # Close the window
    $window.Close()
})

# Show the window
$window.ShowDialog() | Out-Null

if ($firefoxChecked -eq $true) {
    $FirefoxInstaller = "$env:TEMP\FirefoxInstaller.exe"
    $ProgressPreference = 'SilentlyContinue'
    Write-Host -ForegroundColor Green "Downloading Mozilla Firefox..."
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US" -OutFile $FirefoxInstaller
    Write-Host -ForegroundColor Green "Installing Mozilla Firefox..."
    Start-Process -FilePath $firefoxInstaller -ArgumentList "/S" -Wait
} if ($chromeChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing Google Chrome..."
    winget install --id "Google.Chrome.EXE"
} if ($steamChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing Steam..."
    winget install --id "Valve.Steam"
} if ($discordChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing Discord..."
    winget install --id "Discord.Discord"
} if ($epicGamesLauncherChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing Epic Games Launcher..."
    winget install --id "EpicGames.EpicGamesLauncher"
} if ($openRGBChecked -eq $true) {
    Write-Host -ForegroundColor Green "Downloading OpenRGB Version 0.9..."
    Invoke-WebRequest -Uri "https://openrgb.org/releases/release_0.9/OpenRGB_0.9_Windows_64_b5f46e3.zip" -OutFile "$env:Temp\openrgb-installer.exe"
    Write-Host -ForegroundColor Green "Installing OpenRGB..."
    Start-Process "$env:Temp\openrgb-installer.exe"
} if ($signalRGBChecked -eq $true) {
    Write-Host -ForegroundColor Green "Downloading SignalRGB..."
    Invoke-WebRequest -Uri "https://release.signalrgb.com/Install_SignalRgb.exe" -OutFile "$env:Temp\signalrgb-installer.exe"
    Write-Host -ForegroundColor Green "Installing SignalRGB..."
    Start-Process "$env:Temp\signalrgb-installer.exe"
} if ($vlcChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing VLC media player..."
    winget install --id "VideoLAN.VLC"
} if ($sevenZipChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing 7-Zip..."
    winget install --id "7zip.7zip"
} if ($malwarebytesChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing Malwarebytes Anti-Malware..."
    winget install --id "Malwarebytes.Malwarebytes"
} if ($furmarkChecked -eq $true) {
    Write-Host -ForegroundColor Green "Downloading FurMark..."
    $furmarkInstaller = "$env:TEMP\FurMarkInstaller.exe"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://geeks3d.com/dl/get/738" -OutFile $furmarkInstaller
    Write-Host -ForegroundColor Green "Installing FurMark..."
    Start-Process -FilePath $furmarkInstaller -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
} if ($hwmonitorChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing CPUID HWMonitor..."
    winget install --id "CPUID.HWMonitor"
} if ($msiafterburnerChecked -eq $true) {
    Write-Host -ForegroundColor Green "Installing MSI Afterburner and RivaTuner Statistics Server..."
    winget install --id "Guru3D.Afterburner"
    winget install --id "Guru3D.RTSS"
}

if ($furmarkChecked -eq $true) {
    $readHostMessage = "[Y] Yes  [N] No"
    $choicePrompt = "It appears that you have installed FurMark, would you like to run a stress test?"
    $choiceIsYes = "FurmarkTest"
    yesOrNo
}

if ($cinebenchChecked -eq $true) {

}

function FurmarkTest {
    $prompts = @(New-Prompt -ValidateNotEmpty)
    $prompts += @(New-Prompt -Message 'Resolution' -ValidateSet '720p', '1080p', '1440p' -ShowSeparator)
    $prompts += @(New-Prompt -Message 'Anti-aliasing' -ValidateSet 'None', 'MSAA 2x', 'MSAA 4x', 'MSAA 8x' -ShowSeparator)
    $results = (Show-AnyBox -Message 'Test duration (minutes):' -Prompts $prompts -Buttons 'Start')

    # Fix $results formatting
    if ($results -is [System.Collections.IDictionary]) {
        $formattedResults = $results.GetEnumerator() | ForEach-Object {
            "[{0}, {1}]" -f $_.Key, $_.Value
        }
        $formattedResults = $formattedResults -join " "
    } else {
Clear-Host
        Write-Warning -Message "The 'results' variable does not contain a dictionary or hashtable. Script continuing..." 
        Start-Sleep -Seconds 3
    }



    # furmark test resolution
    if ($formattedResults -like "*720p*") { 
        $furmarkTestWidth = "1280"
        $furmarkTestHeight = "720"
    } if ($formattedResults -like "*1080p*") { 
        $furmarkTestWidth = "1920"
        $furmarkTestHeight = "1080"
    } if ($formattedResults -like "*1440p*") { 
        $furmarkTestWidth = "2560"
        $furmarkTestHeight = "1440"
    } 

    # furmark anti aliasing
    if ($formattedResults -like "*None*") { $furmarkAntiAliasing = "none"}
    if ($formattedResults -like "*MSAA 2x*") { $furmarkAntiAliasing = "2x"}
    if ($formattedResults -like "*MSAA 4x*") { $furmarkAntiAliasing = "4x"}
    if ($formattedResults -like "*MSAA 8x*") { $furmarkAntiAliasing = "8x"}

    # test duration
    $furmarkTestDuration = ([regex]::Match($formattedResults, '[0-9]+').Value)
    # minutes to milliseconds
    $furmarkTestDuration = [int]$furmarkTestDuration * 60 * 1000

    $furmarkPath = "C:\Program Files (x86)\Geeks3D\Benchmarks\FurMark\FurMark.exe"

    if ($formattedResults -like '*Start, True*') {
        Start-Process -FilePath "$furmarkPath" -ArgumentList "/nogui /width=$furmarkTestWidth /height=$furmarkTestHeight /msaa=$furmarkAntiAliasing /max_time=$furmarkTestDuration"
    }

}

# file cleanup idk why it's way down here
Remove-Item -Recurse -Force -Path $nvidiaDrivers | Out-Null
Remove-Item -Recurse -Force -Path $amdDrivers | Out-Null


Show-AnyBox -Title 'Script complete' -Message 'The script has finished running!', 'Please give it a star on GitHub!', 'Created by PowerPCFan' -Buttons 'Ok' -MinWidth 325 -MinHeight 150 -WindowStyle ToolWindow


# Yes or No choice dialog box
# .
# Required variables for proper execution of yesOrNo:
# $readHostMessage - it should look something like "[Y] Yes, <action>  [N] No, skip"
# $choicePrompt - question, like "Would you like to <action>?"
# $choiceIsYes - the logic for what to do if the user responds "yes" to the prompt. choiceIsYes should look something like this:
# $choiceIsYes = @"
#     Write-Host "example1"
#     Write-Host "example2"
# "@

function yesOrNo {
    Write-Host "$choicePrompt"
    $validInput = $false
    $key = Read-Host "$readHostMessage"
    while (-not $validInput) {
        switch ($key.ToUpper()) {
            'Y' {
                $validInput = $true
                Invoke-Expression $choiceIsYes
            }
            'N' {
                $validInput = $true
            }
            default {
                $validInput = $false
                Write-Host -ForegroundColor Red "Invalid input. Please try again"
                $key = Read-Host "$readHostMessage"
            }
        }
    }
}
