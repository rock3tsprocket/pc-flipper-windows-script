# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Clear-Host
    Write-Host "Failure: Current permissions inadequate. Please run the file again as administrator." -ForegroundColor Red
    Write-Host "Press any key to exit..."
	Read-Host
	Exit
}

# AnyBox
Install-Module -Name 'AnyBox' -RequiredVersion 0.5.1
Import-Module AnyBox

function InitializeGPUCheck {
	$gpuIsNvidia = $false
	$gpuIsAMD = $false
}

# Detect GPU and download drivers based on detected GPU
function Install-GPUDrivers {
    # $gpu = Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty Name
    # temp for debugging 
    $gpu = $debug
    Write-Output "Detected GPU: $gpu"
    InitializeGPUCheck

    if ($gpu -like "*NVIDIA*" -or $gpu -like "*GeForce*") {
        $gpuIsNvidia = $true
        Write-Output "NVIDIA GPU detected. Press ENTER to download drivers..."
        Read-Host
        mkdir "$env:Temp\Nvidia-Drivers"
        $nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.1.163/NVIDIA_app_v11.0.1.163.exe" -OutFile "$nvidiaDrivers"
        Write-Output "Drivers successfully downloaded. Press ENTER to install."
        Read-Host
        Start-Process $nvidiaDrivers
    } elseif ($gpu -like "*AMD*" -or $gpu -like "*Radeon*") {
        $gpuIsAMD = $true
        Write-Output "AMD GPU detected. Press ENTER to download drivers..."
        Read-Host
        mkdir "$env:Temp\AMD-Drivers"
        $amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://cold7.gofile.io/download/web/a985dc51-6a64-45b3-aa83-38acbaf28ce6/amd-software-adrenalin-edition-24.10.1-minimalsetup-241031_web.exe" -OutFile "$amdDrivers"
        Write-Output "Drivers successfully downloaded. Press ENTER to install."
        Read-Host
        Start-Process $amdDrivers
    } elseif ($gpu -like "*Intel*") {
        Write-Output "Intel GPU detected. Please download manually, this script doesn't currently support Intel iGPUs and Intel Arc GPUs."
        Write-Output "Press ENTER to skip the GPU driver part of this script."
        Read-Host
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
            mkdir "$env:Temp\AMD-Drivers"
            $amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "https://cold7.gofile.io/download/web/a985dc51-6a64-45b3-aa83-38acbaf28ce6/amd-software-adrenalin-edition-24.10.1-minimalsetup-241031_web.exe" -OutFile "$amdDrivers"
            Write-Output "Drivers successfully downloaded. Press ENTER to install."
            Read-Host
            Start-Process $amdDrivers
        } elseif ($response['nvidia'] -eq $true) {
            mkdir "$env:Temp\Nvidia-Drivers"
            $nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.1.163/NVIDIA_app_v11.0.1.163.exe" -OutFile "$nvidiaDrivers"
            Write-Output "Drivers successfully downloaded. Press ENTER to install."
            Read-Host
            Start-Process $nvidiaDrivers
        } elseif ($response['other'] -eq $true) {
            Write-Output "You selected other, which means your GPU is not from AMD or Nvidia and it is currently unsupported. Please download drivers manually."
            Write-Output "Press any key to continue"
            Read-Host
        }
    }
}



# Function to detect motherboard and search for drivers
function Search-MotherboardDrivers {
    $board = (Get-WmiObject Win32_BaseBoard).Product
    $manufacturer = (Get-WmiObject Win32_BaseBoard).Manufacturer
	$fullMotherboardName = $manufacturer + " " + $board
    Write-Output "Detected Motherboard: $fullMotherboardName"
    $searchUrl = "https://duckduckgo.com/?q=motherboard+drivers+for+$($fullMotherboardName -replace ' ', '+')"
	Write-Output "Press ENTER to open your default browser and display the search results for your motherboard drivers."
	Read-Host
    Start-Process $searchUrl
}

function Run-Tweaks {
Write-Output "Press ENTER to run basic Windows tweaks to improve the user experience."
Read-Host

Write-Output "Disabling Search Box Suggestions in start menu..."
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f > $null

Write-Output "Disabling Location Services..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f > $null

Write-Output "Disabling Windows Error Reporting..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f > $null

Write-Output "Enabling Long File Paths..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f > $null

Write-Output "Enabling Verbose Mode..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f > $null

Write-Output "Enabling Dark Mode..."
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f > $null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f > $null

Write-Output "Disabling Sticky Keys..."
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f

Write-Output "Disabling Toggle Keys..."
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f

Write-Output "Disabling Cortana..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > $null

# Get OS information from the registry
$osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# Check if the OS is Windows 11 based on the build number
if ($osInfo.ProductName -match "Windows 10" -and $osInfo.BuildLabEx -ge "22000") {
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f > $null
}
}

Clear-Host

# Detect and install GPU drivers
Install-GPUDrivers

# Search for motherboard drivers
Search-MotherboardDrivers

# Run tweaks
Run-Tweaks
Write-Output "Press ENTER to finish applying the tweaks."
Read-Host
TASKKILL /F /IM explorer.exe
Start-Process "$env:WinDir\explorer.exe"
Write-Output "Tweaks done."

Write-Output "Press ENTER to download and install Firefox Browser."
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

# Open Sysprep
Write-Output "Press ENTER to run Sysprep."
Read-Host
Start-Process -FilePath "C:\Windows\System32\Sysprep\sysprep.exe"
