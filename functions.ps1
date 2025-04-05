function Remove-IfExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [switch]$Recurse,
        [Parameter(Mandatory=$true)]
        [switch]$Force
    )

    $params = @{ Path = $Path }

    if ($Recurse) { $params["Recurse"] = $true }
    if ($Force) { $params["Force"] = $true }

    if (Test-Path -Path $Path) {
        Remove-Item @params
    }
}

function Install-PSModule { 
    param (
        [Parameter(Mandatory=$true)]
        [string]$moduleName,
        
        [Parameter(Mandatory=$true)]
        [string]$requiredVersion
    )

    $module = Get-Module -ListAvailable -Name $moduleName -All | Where-Object { $_.Version -eq $requiredVersion }
    if (-not $module) {
        if (-not (Get-Module PSResourceGet -listavailable -All)) {
            Install-Module -Name $moduleName -RequiredVersion $requiredVersion -Force -Repository PSGallery -Confirm:$false
        } else {
            Install-PSResource -Name $moduleName -Version $requiredVersion -TrustRepository -Reinstall -Repository PSGallery -Quiet -AcceptLicense
        }
    }
}

function Get-UserChoice {
    param (
        [Parameter(Mandatory=$true)]
        [string]$readHostMessage,
        
        [Parameter(Mandatory=$true)]
        [string]$choicePrompt,
        
        [Parameter(Mandatory=$true)]
        [string[]]$keys,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$choiceActions
    )
    
    # Validate that there's an action for each key
    foreach ($key in $keys) {
        $actionKey = "choiceIs$key"
        if (-not $choiceActions.ContainsKey($actionKey)) {
            Write-Warning "No action defined for key '$key'. This key will have no action."
        }
    }
    
    Write-Host "$choicePrompt"    
    $key = Read-Host "$readHostMessage"
    $validInput = $false
    
    while (-not $validInput) {
        $upperKey = $key.ToUpper()
        
        if ($keys -contains $upperKey) {
            $validInput = $true
            $actionKey = "choiceIs$upperKey"
            
            if ($choiceActions.ContainsKey($actionKey) -and $null -ne $choiceActions[$actionKey]) {
                & $choiceActions[$actionKey]
            }
        }
        else {
            Write-Host -ForegroundColor Red "Invalid input. Please try again"
            $key = Read-Host "$readHostMessage"
        }
    }
    
    return $upperKey
}

function Start-FurmarkTest {
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
# Clear-Host
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

function Install-GPUDrivers {
    $gpu = Get-CimInstance Win32_VideoController | Where-Object { $_.Status -eq 'OK' -and $_.Availability -eq 3 } | Select-Object Name, AdapterRAM, DriverVersion
    if ($gpu -like "*NVIDIA*" -or $gpu -like "*GeForce*") {
        # Clear-Host
        Write-Host "Nvidia GPU detected. Drivers downloading and installing..."
        Remove-IfExists -Recurse -Force -Path "$env:Temp\Nvidia-Drivers"
        New-Item -Type Directory -Path "$env:Temp\Nvidia-Drivers"
        $nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.3.218/NVIDIA_app_v11.0.3.218.exe" -OutFile "$nvidiaDrivers"
        Start-Process $nvidiaDrivers
    } elseif ($gpu -like "*AMD*" -or $gpu -like "*Radeon*") {
        # Clear-Host
        Write-Host "AMD GPU detected. Drivers downloading and installing..."
        Remove-IfExists -Recurse -Force -Path "$env:Temp\AMD-Drivers"
        New-Item -ItemType Directory -Path "$env:Temp\AMD-Drivers"
        $amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
        # $adrenalinDriverLink = (curl.exe "https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/main/configs/link_full.txt")
        $adrenalinDriverLink = (curl.exe "https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/drivers/amd/link.txt")
        curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $adrenalinDriverLink -o $amdDrivers
        if (Test-Path $amdDrivers) {
            Start-Process $amdDrivers
            $Script:amdDrivers = $amdDrivers # Make sure the variable is available throughout the script
        } else {
            Write-Host -ForegroundColor Red "Error: AMD driver installer not found."
        }    
    } elseif ($gpu -like "*Intel*") {
        # Clear-Host
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
		# Clear-Host
		Write-Host "Drivers downloading and installing..."
        Remove-IfExists -Recurse -Force -Path "$env:Temp\AMD-Drivers"
		New-Item -ItemType Directory -Path "$env:Temp\AMD-Drivers"
		$amdDrivers = "$env:Temp\AMD-Drivers\setup.exe"
		$adrenalinDriverLink = (curl.exe "https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/main/configs/link_full.txt")
		curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $adrenalinDriverLink -o $amdDrivers
		Start-Process $amdDrivers
        } elseif ($response['nvidia'] -eq $true) {
		# Clear-Host
		Write-Host "Drivers downloading and installing..."
        Remove-IfExists -Recurse -Force -Path "$env:Temp\Nvidia-Drivers"
		New-Item -ItemType Directory -Path "$env:Temp\Nvidia-Drivers"
		$nvidiaDrivers = "$env:Temp\Nvidia-Drivers\setup.exe"
		$ProgressPreference = 'SilentlyContinue'
		Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.1.163/NVIDIA_app_v11.0.1.163.exe" -OutFile "$nvidiaDrivers"
		Start-Process $nvidiaDrivers
        } elseif ($response['other'] -eq $true) {
		# Clear-Host
            	Write-Host "You selected other, which means your GPU is not from AMD or Nvidia and it is currently unsupported. Please download drivers manually."
            	Read-Host "Press any key to continue"
        }
    }
}

function Install-ChipsetDrivers {
    $currentCPU = (Get-CimInstance Win32_Processor).Name
    if ($currentCPU -like "*AMD*") {
        $chipsetDriverPath = "chipset\ChipsetDrivers_AMD.exe"
        $chipsetDriverLink = (curl.exe "https://raw.githubusercontent.com/notFoxils/AMD-Chipset-Drivers/refs/heads/main/configs/link.txt")
        curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $chipsetDriverLink -o "$chipsetDriverPath"
        Write-Host -ForegroundColor Green "AMD chipset drivers successfully downloaded."
        Write-Host -ForegroundColor Green "Installing drivers..."
        Start-Process "$chipsetDriverPath"
    } elseif ($currentCPU -like "*Intel*") {
        $chipsetDriverPath = "chipset\ChipsetDrivers_Intel.exe"
        Invoke-WebRequest -Uri "https://downloadmirror.intel.com/843223/SetupChipset.exe" -OutFile "$chipsetDriverPath"
        Write-Host -ForegroundColor Green "Intel chipset drivers successfully downloaded."
        Write-Host -ForegroundColor Green "Installing drivers..."
        Start-Process $chipsetDriverPath
    }
}

function Open-MotherboardDriverPage {
    $board = (Get-CimInstance Win32_BaseBoard -Property Product).Product
    $manufacturer = (Get-CimInstance Win32_BaseBoard -property Manufacturer).Manufacturer
    $fullMotherboardName = $manufacturer + " " + $board

    Get-UserChoice -readHostMessage "[Y] Yes, search for motherboard page  [N] No, continue" -choicePrompt "Would you like to search for your motherboard's driver page to download any additional drivers?" -keys "Y", "N" -choiceActions @{
        choiceIsY = { 
            $searchUrl = "https://duckduckgo.com/?q=motherboard+drivers+for+$($fullMotherboardName -replace ' ', '+')"
            Start-Process $searchUrl
        }
    }
}

function Start-WindowsTweaks {
	# Clear-Host
 	Write-Host "RUNNING TWEAKS"
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
	
	# Clear-Host
	Write-Host -ForegroundColor Green "Windows tweaks complete."
}

function New-AppInstallerWindow {
    param(
        [string] $titleFontSize = "20",
        [string] $font = "Georgia",
        [string] $margin = "0,0,0,10",
        [string] $height = "475",
        [string] $width = "475"
    )

    # wpf
    Add-Type -AssemblyName PresentationFramework

    [xml]$xaml = @"
    <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Application Installer" Height="$height" Width="$width">
        <Grid Margin="10">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <TextBlock Grid.Row="0" Text="App Installer" FontSize='$titleFontSize' FontWeight='Bold' FontFamily='$font' Margin='$margin' />
            <TextBlock Grid.Row="1" Text="Select the applications you would like to install." FontWeight='Bold' FontFamily='$font' Margin='$margin' />
            
            <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
                <StackPanel>
                    <CheckBox Name="redist" Content="Visual C++ Redist Runtimes (Recommended)" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Firefox" Content="Firefox" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Chrome" Content="Chrome" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Steam" Content="Steam" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Discord" Content="Discord" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="EpicGamesLauncher" Content="Epic Games Launcher" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="OpenRGB" Content="OpenRGB" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="SignalRGB" Content="SignalRGB" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="VLC" Content="VLC Media Player" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="SevenZip" Content="7-Zip" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Malwarebytes" Content="Malwarebytes" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="HWMonitor" Content="HWMonitor" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="MSIAfterburner" Content="MSI Afterburner" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="FurMark" Content="FurMark" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="OCCT" Content="OCCT" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="Cinebench" Content="Cinebench R23" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="CrystalDiskMark" Content="CrystalDiskMark" FontFamily='$font' Margin='$margin' />
                    <CheckBox Name="CrystalDiskInfo" Content="CrystalDiskInfo" FontFamily='$font' Margin='$margin' />
                </StackPanel>
            </ScrollViewer>
            
            <Button Grid.Row="3" Content="OK" Name="OkButton" HorizontalAlignment="Right" Margin="0,10,0,0" Width="75" />
        </Grid>
    </Window> 
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $selectedApps = @{}

    # OK button
    $okButton = $window.FindName("OkButton")
    $okButton.Add_Click({
        # Get all CheckBox elements from the ScrollViewer's StackPanel
        $scrollViewer = $window.Content.Children[2]  # The ScrollViewer is the third child in the Grid
        $stackPanel = $scrollViewer.Content          # Get the StackPanel inside the ScrollViewer
        $checkboxes = $stackPanel.Children           # Get all children of the StackPanel
        
        # Store selections in the hashtable and update script variables
        foreach ($checkbox in $checkboxes) {
            $script:selectedApps[$checkbox.Name] = $checkbox.IsChecked
            
            # Also set individual script variables for backward compatibility
            $varName = "$($checkbox.Name)Checked"
            Set-Variable -Name $varName -Value $checkbox.IsChecked -Scope Script
        }

        $window.DialogResult = $true
        $window.Close()
    })

    # Initialize the selectedApps as a script variable
    $script:selectedApps = @{}

    # Show the window
    $window.ShowDialog() | Out-Null
    
    return $script:selectedApps
}

function Install-SelectedApps {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$SelectedApps
    )
    
    if ($SelectedApps.redist) {
        Write-Host -ForegroundColor Green "Installing Visual C++ Redist Runtimes..."
        Install-WindowsRedists
    }
    if ($SelectedApps.Firefox) {
        $FirefoxInstaller = "$env:TEMP\FirefoxInstaller.exe"
        $ProgressPreference = 'SilentlyContinue'
        Write-Host -ForegroundColor Green "Downloading Mozilla Firefox..."
        Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US" -OutFile $FirefoxInstaller
        Write-Host -ForegroundColor Green "Installing Mozilla Firefox..."
        Start-Process -FilePath $FirefoxInstaller -ArgumentList "/S" -Wait
    }
    if ($SelectedApps.Chrome) {
        Write-Host -ForegroundColor Green "Installing Google Chrome..."
        winget install --id "Google.Chrome.EXE"
    }
    if ($SelectedApps.Steam) {
        Write-Host -ForegroundColor Green "Installing Steam..."
        winget install --id "Valve.Steam"
    }
    if ($SelectedApps.Discord) {
        Write-Host -ForegroundColor Green "Installing Discord..."
        winget install --id "Discord.Discord"
    }
    if ($SelectedApps.EpicGamesLauncher) {
        Write-Host -ForegroundColor Green "Installing Epic Games Launcher..."
        winget install --id "EpicGames.EpicGamesLauncher"
    }
    if ($SelectedApps.OpenRGB) {
        Write-Host -ForegroundColor Green "Downloading OpenRGB Version 0.9..."
        Invoke-WebRequest -Uri "https://openrgb.org/releases/release_0.9/OpenRGB_0.9_Windows_64_b5f46e3.zip" -OutFile "$env:Temp\openrgb-installer.exe"
        Write-Host -ForegroundColor Green "Installing OpenRGB..."
        Start-Process "$env:Temp\openrgb-installer.exe"
    }
    if ($SelectedApps.SignalRGB) {
        Write-Host -ForegroundColor Green "Downloading SignalRGB..."
        Invoke-WebRequest -Uri "https://release.signalrgb.com/Install_SignalRgb.exe" -OutFile "$env:Temp\signalrgb-installer.exe"
        Write-Host -ForegroundColor Green "Installing SignalRGB..."
        Start-Process "$env:Temp\signalrgb-installer.exe"
    }
    if ($SelectedApps.VLC) {
        Write-Host -ForegroundColor Green "Installing VLC media player..."
        winget install --id "VideoLAN.VLC"
    }
    if ($SelectedApps.SevenZip) {
        Write-Host -ForegroundColor Green "Installing 7-Zip..."
        winget install --id "7zip.7zip"
    }
    if ($SelectedApps.Malwarebytes) {
        Write-Host -ForegroundColor Green "Installing Malwarebytes Anti-Malware..."
        winget install --id "Malwarebytes.Malwarebytes"
    }
    if ($SelectedApps.HWMonitor) {
        Write-Host -ForegroundColor Green "Installing CPUID HWMonitor..."
        winget install --id "CPUID.HWMonitor"
    }
    if ($SelectedApps.MSIAfterburner) {
        Write-Host -ForegroundColor Green "Installing MSI Afterburner and RivaTuner Statistics Server..."
        winget install --id "Guru3D.Afterburner"
        winget install --id "Guru3D.RTSS"
    }
    if ($SelectedApps.FurMark) {
        Write-Host -ForegroundColor Green "Downloading FurMark..."
        $furmarkInstaller = "$env:TEMP\FurMarkInstaller.exe"
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://geeks3d.com/dl/get/738" -OutFile $furmarkInstaller
        Write-Host -ForegroundColor Green "Installing FurMark..."
        Start-Process -FilePath $furmarkInstaller -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
        
        $script:furmarkInstalled = $true
    }
    if ($SelectedApps.OCCT) {
        Write-Host -ForegroundColor Green "Installing OCCT..."
        winget install --id "OCBase.OCCT.Personal"
    }
    if ($SelectedApps.Cinebench) {
        Write-Host -ForegroundColor Green "Installing Cinebench R23..."
        winget install --id "Maxon.CinebenchR23"
    }
    if ($SelectedApps.CrystalDiskMark) {
        Write-Host -ForegroundColor Green "Installing CrystalDiskMark..."
        winget install --id "CrystalDewWorld.CrystalDiskMark"
    }
    if ($SelectedApps.CrystalDiskInfo) {
        Write-Host -ForegroundColor Green "Installing CrystalDiskInfo..."
        winget install --id "CrystalDewWorld.CrystalDiskInfo"
    }
}

function Install-Prerequisites {
    # WinGet
    try {
        winget --version
    } catch {
        Write-Host -ForegroundColor Red "Winget not present / outdated. Installing Winget..."
        # Get the download URL of the latest winget installer from GitHub:
        $API_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
        $DOWNLOAD_URL = $(Invoke-RestMethod $API_URL).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}

        $installerName = "winget.msixbundle"

        # Download the installer:
        Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $installerName -UseBasicParsing

        # Install winget:
        Add-AppxPackage $installerName

        # Remove the installer:
        Remove-IfExists -Path $installerName
    }


    # NuGet

    # old code
    # Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Force -Confirm

    if (-not (Get-PackageProvider -Name NuGet -ListAvailable | Where-Object { [version]$_.Version -ge [version]'2.8.5.201' })) {
        Write-Host "NuGet 2.8.5.201 or higher is not installed. Installing now..."
        Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Force -Confirm:$false
    } else {
        Write-Host "NuGet 2.8.5.201 or higher is already installed."
    }

    # anybox
    Install-PSModule -ModuleName 'AnyBox' -RequiredVersion '0.5.1'
}

function Restart-WindowsExplorer {
    TASKKILL.exe /F /IM explorer.exe
    Start-Process "$env:WinDir\explorer.exe"
}

function Test-AdminPrivileges {
    # Check if the script is running as an administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Clear-Host
        Write-Host -ForegroundColor Red "============================================================================="
        Write-Host -ForegroundColor Red "Failure: Current permissions inadequate: Script not running as administrator."
        Write-Host -ForegroundColor Red "============================================================================="
        Get-UserChoice -readHostMessage "[R] Relaunch as administrator [E] Exit" -choicePrompt "Please select an action:" -keys "R", "E" -choiceActions @{
            choiceIsR = { Start-Process -Verb RunAs -FilePath "powershell.exe" -ArgumentList "-Command", "Invoke-RestMethod -Uri 'https://bit.ly/pcflipperwindowsscript' | Invoke-Expression" }
            choiceIsE = { exit }
        }
    }
}

function Show-ScriptCompleteBox {
    Show-AnyBox -Title 'Script complete' -Message 'The script has finished running!', 'Please give it a star on GitHub!', 'Created by PowerPCFan' -Buttons 'Ok' -MinWidth 325 -MinHeight 150 -WindowStyle ToolWindow
}

function Install-WindowsRedists {
    # make directory for redists
    New-Item -ItemType Directory -Path "visual-cpp-redist-runtimes"
    
    # set vars
    $redistFolderPath = "visual-cpp-redist-runtimes"
    $redistZipPath = "$redistFolderPath\runtimes.zip"

    # download redists
    Invoke-WebRequest -Uri "https://us4-dl.techpowerup.com/files/ZO-0JHgWSloWz5sDWbea9Q/1743849848/Visual-C-Runtimes-All-in-One-Mar-2025.zip" -OutFile "$redistZipPath"
    
    # expand zip archive
    Expand-Archive -Path "$redistZipPath" -DestinationPath "$redistFolderPath"

    # remove zip archive (it's expanded now)
    Remove-IfExists -Path "$redistZipPath" -Force

    # detect if PC is 64-bit or 32-bit and set var
    $64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem

    if ($64BitOperatingSystem) {
        Write-Host -ForegroundColor Green "64-bit OS detected. 32-bit and 64-bit redistributables will be installed."
    } else {
        Write-Host -ForegroundColor Green "32-bit OS detected. 32-bit redistributables will be installed."
    }
    
    # 32-bit (installs no matter what)
    Write-Host "Installing 32-bit redistributables..." -ForegroundColor Green
    Start-Process -FilePath "$redistFolderPath\vcredist2005_x86.exe" -ArgumentList "/q" -Wait
    Start-Process -FilePath "$redistFolderPath\vcredist2008_x86.exe" -ArgumentList "/qb" -Wait
    Start-Process -FilePath "$redistFolderPath\vcredist2010_x86.exe" -ArgumentList "/passive", "/norestart" -Wait
    Start-Process -FilePath "$redistFolderPath\vcredist2012_x86.exe" -ArgumentList "/passive", "/norestart" -Wait
    Start-Process -FilePath "$redistFolderPath\vcredist2013_x86.exe" -ArgumentList "/passive", "/norestart" -Wait
    Start-Process -FilePath "$redistFolderPath\vcredist2015_2017_2019_2022_x86.exe" -ArgumentList "/passive", "/norestart" -Wait

    # 64-bit (only installs if $64BitOperatingSystem is $true)
    if ($64BitOperatingSystem) {
        Write-Host "Installing 64-bit redistributables..." -ForegroundColor Green
        Start-Process -FilePath "$redistFolderPath\vcredist2005_x64.exe" -ArgumentList "/q" -Wait
        Start-Process -FilePath "$redistFolderPath\vcredist2008_x64.exe" -ArgumentList "/qb" -Wait
        Start-Process -FilePath "$redistFolderPath\vcredist2010_x64.exe" -ArgumentList "/passive", "/norestart" -Wait
        Start-Process -FilePath "$redistFolderPath\vcredist2012_x64.exe" -ArgumentList "/passive", "/norestart" -Wait
        Start-Process -FilePath "$redistFolderPath\vcredist2013_x64.exe" -ArgumentList "/passive", "/norestart" -Wait
        Start-Process -FilePath "$redistFolderPath\vcredist2015_2017_2019_2022_x64.exe" -ArgumentList "/passive", "/norestart" -Wait
    }

    if ($64BitOperatingSystem) {
        Write-Host -ForegroundColor Green "32-bit and 64-bit redistributables successfully installed."
    } else {
        Write-Host -ForegroundColor Green "32-bit redistributables successfully installed."
    }
    Write-Host -ForegroundColor Yellow "A system reboot is advised to ensure all changes take effect."
}