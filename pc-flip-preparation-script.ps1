function Remove-IfExists { # Approved Verb ("Deletes a resource from a container")
    param (
        [string] $Path,
        [switch] $Recurse,
        [switch] $Force
    )

    $params = @{ Path = $Path }

    if ($Recurse) { $params["Recurse"] = $true }
    if ($Force) { $params["Force"] = $true }

    if (Test-Path -Path $Path) {
        Remove-Item @params
    }
}

function Clear-ScrollDown {
    $emptyLines = [string]::new("`n", [console]::WindowHeight)
    Write-Host $emptyLines
}

function Install-PSModule { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    param (
        [string]$moduleName,        
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

function Start-Logging {
    if (-not (Test-Path "logs")) {
        New-Item -Path "logs" -ItemType Directory | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $fileName = "transcript_$timestamp.log"
    Start-Transcript -Path "logs\$fileName"
}

function Get-UserChoice { # Approved Verb ("Specifies an action that retrieves a resource")
    param (
        [Parameter(Mandatory=$true)]
        [string]$readHostMessage,
        [string]$choicePrompt,
        [string[]]$keys,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$choiceActions
    )
    
    # Validate that there's an action for each key
    foreach ($key in $keys) {
        $actionKey = "choiceIs$key"
    }
    
    # Check if "Default" is defined as a key
    $hasDefaultAction = $keys -contains "Default"
    
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
        elseif ($hasDefaultAction) {
            # If "Default" is defined and user pressed an undefined key, use the default action
            $validInput = $true
            $actionKey = "choiceIsDefault"
            
            if ($choiceActions.ContainsKey($actionKey) -and $null -ne $choiceActions[$actionKey]) {
                & $choiceActions[$actionKey]
            }
            
            # Return the actual key pressed when using default action
            return $upperKey
        }
        else {
            Write-Host -ForegroundColor Red "Invalid input. Please try again"
            $key = Read-Host "$readHostMessage"
        }
    }
    
    return $upperKey
}

function Start-FurmarkTest { # Approved Verb ("Initiates an operation")
    param (
        [int]$Duration,
        [string]$Resolution,
        [string]$AntiAliasing
    )
    
    $durationMinutes = $Duration
    $resolution = $Resolution
    $antiAliasing = $AntiAliasing
    
    $resMap = @{
        "*720p*"  = @{ Width = "1280"; Height = "720" }
        "*1080p*" = @{ Width = "1920"; Height = "1080" }
        "*1440p*" = @{ Width = "2560"; Height = "1440" }
    }

    $aliasingMap = @{
        "*None*" = "none"
        "*2x*"   = "2x"
        "*4x*"   = "4x"
        "*8x*"   = "8x"
    }

    # resolution
    $furmarkTestWidth = $null
    $furmarkTestHeight = $null
    foreach ($key in $resMap.Keys) {
        if ($resolution -like $key) {
            $furmarkTestWidth = $resMap[$key].Width
            $furmarkTestHeight = $resMap[$key].Height
            break
        }
    }
    
    # anti-aliasing
    $furmarkAntiAliasing = $null
    foreach ($key in $aliasingMap.Keys) {
        if ($antiAliasing -like $key) {
            $furmarkAntiAliasing = $aliasingMap[$key]
            break
        }
    }
    
    # Convert duration to milliseconds
    $furmarkTestDuration = [int]$durationMinutes * 60 * 1000

    # Run FurMark with parameters
    $furmarkPath = "${env:ProgramFiles(x86)}\Geeks3D\Benchmarks\FurMark\FurMark.exe"

    if (-not (Test-Path -Path $furmarkPath)) {
        Write-Host -ForegroundColor Red "Error: FurMark.exe executable not found at $furmarkPath"
        return
    }

    $arguments = @(
        "/nogui", 
        "/width=$furmarkTestWidth", 
        "/height=$furmarkTestHeight", 
        "/msaa=$furmarkAntiAliasing", 
        "/max_time=$furmarkTestDuration"
    )

    Write-Host "Starting FurMark stress test with the following settings:`nResolution: $furmarkTestWidth x $furmarkTestHeight ($resolution)`nAnti-aliasing: $furmarkAntiAliasing`nDuration: $durationMinutes minutes"
    
    try {
        Start-Process -FilePath $furmarkPath -ArgumentList $arguments
    } catch {
        Write-Error "Failed to start FurMark: $_"
    }
}

function Install-GPUDrivers { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    if ($gpu -like "*NVIDIA*" -or $gpu -like "*GeForce*") {
        Install-NvidiaDrivers
    } elseif ($gpu -like "*AMD*" -or $gpu -like "*Radeon*") {
        Install-AMDDrivers
    } elseif ($gpu -like "*Intel*") {
        
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
            Install-AMDDrivers
        } elseif ($response['nvidia'] -eq $true) {
            Install-NvidiaDrivers
        } elseif ($response['other'] -eq $true) {
            Write-Host "You selected other, which means your GPU is not from AMD or Nvidia and it is currently unsupported. Please download drivers manually."
            Read-Host "Press any key to continue"
        }
    }
}

function Install-NvidiaDrivers { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    # Write-Host "Nvidia GPU detected. Drivers downloading and installing..."
    # New-Item -Type Directory -Path "Nvidia-Drivers" | Out-Null
    # $nvidiaDrivers = "Nvidia-Drivers\setup.exe"
    # $ProgressPreference = 'SilentlyContinue'
    # Invoke-WebRequest -Uri "https://us.download.nvidia.com/nvapp/client/11.0.3.218/NVIDIA_app_v11.0.3.218.exe" -OutFile "$nvidiaDrivers"
    # if (Test-Path -Path "$nvidiaDrivers") {
    #     Start-Process $nvidiaDrivers
    # } else {
    #     Write-Host -ForegroundColor Red "Error: Nvidia driver installer not found at $nvidiaDrivers."
    # }

    $nvcleanstallPath = "$env:ProgramFiles\NVCleanstall\NVCleanstall.exe"
    Write-Host "Nvidia GPU detected, installing NVCleanstall..."
    winget install --id TechPowerUp.NVCleanstall @wingetArgs
    Write-Host -ForegroundColor Green "NVCleanstall installed. Running app..."
    if (Test-Path -Path "$nvcleanstallPath") {
        Start-Process -Path "$nvcleanstallPath" -Wait
        $msgBoxText = 'In the GUI that just opened, select the proper driver and install it.'
        [System.Windows.MessageBox]::Show("$msgBoxText", "Nvidia Drivers", "Ok", "Information")
    } else {
        Write-Host -ForegroundColor Red "Error: NVCleanstall not found at $nvcleanstallPath. Please install drivers manually."
    }
}

function Install-AMDDrivers { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    Write-Host "AMD GPU detected. Drivers downloading and installing..."
    New-Item -ItemType Directory -Path "AMD-Drivers" | Out-Null
    $amdDrivers = "AMD-Drivers\setup.exe"
    $adrenalinDriverLink = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/refs/heads/main/configs/config.json" | Select-Object -ExpandProperty driver_links | Select-Object -ExpandProperty stable
    curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $adrenalinDriverLink -o $amdDrivers
    if (Test-Path -Path "$amdDrivers") {
        Start-Process $amdDrivers -Wait
    } else {
        Write-Host -ForegroundColor Red "Error: AMD driver installer not found at $amdDrivers."
    }
}

function Install-ChipsetDrivers { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    New-Item -Type Directory -Path "chipset" | Out-Null
    if ($cpu -like "*AMD*") {
        $chipsetDriverPath = "chipset\ChipsetDrivers_AMD.exe"
        $chipsetDriverLink = (curl.exe "https://raw.githubusercontent.com/notFoxils/AMD-Chipset-Drivers/refs/heads/main/configs/link.txt")
        curl.exe -e "https://www.amd.com/en/support/download/drivers.html" $chipsetDriverLink -o "$chipsetDriverPath"
        Write-Host -ForegroundColor Green "AMD chipset drivers successfully downloaded."
        Write-Host "Installing drivers..."
        Start-Process "$chipsetDriverPath" -Wait
    } elseif ($cpu -like "*Intel*") {
        $chipsetDriverPath = "chipset\ChipsetDrivers_Intel.exe"
        Invoke-WebRequest -Uri "https://downloadmirror.intel.com/843223/SetupChipset.exe" -OutFile "$chipsetDriverPath"
        Write-Host -ForegroundColor Green "Intel chipset drivers successfully downloaded."
        Write-Host "Installing drivers..."
        Start-Process $chipsetDriverPath -Wait
    }
    Write-Host -ForegroundColor Green "Chipset drivers have finished installing."
}

function Install-VCPPRedists {
    $VCRedistYears = @("2005", "2008", "2010", "2012", "2013", "2015+")

    if ($64BitOperatingSystem) {
        Write-Host "64-bit OS detected. 32-bit and 64-bit redistributables will be installed."
    } else {
        Write-Host "32-bit OS detected. 32-bit redistributables will be installed."
    }
    
    foreach ($year in $VCRedistYears) {
        winget install --id "Microsoft.VCRedist.$year.x86" @wingetArgs
        if ($64BitOperatingSystem) {
            winget install --id "Microsoft.VCRedist.$year.x64" @wingetArgs
        }
    }

    if ($64BitOperatingSystem) {
        Write-Host -ForegroundColor Green "32-bit and 64-bit redistributables successfully installed."
    } else {
        Write-Host -ForegroundColor Green "32-bit redistributables successfully installed."
    }
    Write-Host -ForegroundColor Yellow "A system reboot is advised to ensure all changes take effect."
}

function Show-MotherboardDriverPage { # Approved Verb ("Makes a resource visible to the user")
    $searchUrl = "https://duckduckgo.com/?q=motherboard+drivers+for+$($fullMotherboardName -replace ' ', '+')"
    Start-Process $searchUrl
}

# I plan on converting this to use New-Item and New-ItemProperty soon :)
function Start-WindowsTweaks { # Approved Verb ("Initiates an operation")
 	Write-Host "--- Windows Tweaks ---"
	
	Write-Host "Disabling Location Services..."
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f | Out-Null
	
	Write-Host "Disabling Windows Error Reporting..."
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f | Out-Null
	
	Write-Host "Enabling Long File Paths..."
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f | Out-Null

    Write-Host "Disabling WiFi-Sense..."
    reg.exe add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f | Out-Null

    Write-Host "Disabling Location Services..."
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f | Out-Null

    Write-Host "Disabling Windows Error Reporting..."
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f | Out-Null

    Write-Host "Enabling Long File Paths..."
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f | Out-Null

    Write-Host "Enabling Verbose Mode..."
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f | Out-Null

    Write-Host "Disabling Cortana..."
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f | Out-Null

    Write-Host "Disabling Telemetry..."
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "0" /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f | Out-Null

    Write-Host "Disabling Advertising ID..."
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f | Out-Null
	
	Write-Host -ForegroundColor Green "Windows tweaks complete."
}

function Install-SelectedApps { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$SelectedApps,
        [string]$DownloadPath = "app-installers"
    )
    
    New-Item -ItemType Directory -Path $DownloadPath | Out-Null
    $furmarkInstalled = $false

    if ($SelectedApps.redist) {
        Write-Host "Installing Visual C++ Redist Runtimes..."
        Install-VCPPRedists
    }
    if ($SelectedApps.dotnet) {
        $dotnetRuntimeVersions = @("3_1", "5", "6", "7", "8", "9")
        Write-Host "Installing .NET Runtimes..."
        foreach ($version in $dotnetRuntimeVersions) {
            winget install --id "Microsoft.DotNet.Runtime.$version" @wingetArgs
        }
    }
    if ($SelectedApps.Firefox) {
        Write-Host "Installing Mozilla Firefox..."
        winget install --id "Mozilla.Firefox" @wingetArgs
    }
    if ($SelectedApps.Chrome) {
        Write-Host "Installing Google Chrome..."
        winget install --id "Google.Chrome.EXE" @wingetArgs
    }
    if ($SelectedApps.Steam) {
        Write-Host "Installing Steam..."
        winget install --id "Valve.Steam" @wingetArgs
    }
    if ($SelectedApps.Discord) {
        Write-Host "Installing Discord..."
        winget install --id "Discord.Discord" @wingetArgs
    }
    if ($SelectedApps.EpicGamesLauncher) {
        Write-Host "Installing Epic Games Launcher..."
        winget install --id "EpicGames.EpicGamesLauncher" @wingetArgs
    }
    if ($SelectedApps.OpenRGB) {
        Write-Host "Installing OpenRGB..."
        winget install --id "CalcProgrammer1.OpenRGB" @wingetArgs
    }
    if ($SelectedApps.SignalRGB) {
        Write-Host "Installing SignalRGB..."
        winget install --id "WhirlwindFX.SignalRgb" @wingetArgs
    }
    if ($SelectedApps.VLC) {
        Write-Host "Installing VLC media player..."
        winget install --id "VideoLAN.VLC" @wingetArgs
    }
    if ($SelectedApps.SevenZip) {
        Write-Host "Installing 7-Zip..."
        winget install --id "7zip.7zip" @wingetArgs
    }
    if ($SelectedApps.Malwarebytes) {
        Write-Host "Installing Malwarebytes Anti-Malware..."
        winget install --id "Malwarebytes.Malwarebytes" @wingetArgs
    }
    if ($SelectedApps.HWMonitor) {
        Write-Host "Installing CPUID HWMonitor..."
        winget install --id "CPUID.HWMonitor" @wingetArgs
    }
    if ($SelectedApps.MSIAfterburner) {
        Write-Host "Installing MSI Afterburner and RivaTuner Statistics Server..."
        winget install --id "Guru3D.Afterburner" @wingetArgs
        winget install --id "Guru3D.RTSS" @wingetArgs
    }
    if ($SelectedApps.FurMark) {
        Write-Host "Installing FurMark..."
        winget install --id "Geeks3D.FurMark" @wingetArgs

        $furmarkInstalled = $true
    }
    if ($SelectedApps.OCCT) {
        Write-Host "Installing OCCT..."
        winget install --id "OCBase.OCCT.Personal" @wingetArgs
    }
    if ($SelectedApps.Cinebench) {
        Write-Host "Installing Cinebench R23..."
        winget install --id "Maxon.CinebenchR23" @wingetArgs
    }
    if ($SelectedApps.CrystalDiskMark) {
        Write-Host "Installing CrystalDiskMark..."
        winget install --id "CrystalDewWorld.CrystalDiskMark" @wingetArgs
    }
    if ($SelectedApps.CrystalDiskInfo) {
        Write-Host "Installing CrystalDiskInfo..."
        winget install --id "CrystalDewWorld.CrystalDiskInfo" @wingetArgs
    }
    if ($SelectedApps.aida64) {
        Write-Host "Installing AIDA64..."
        winget install --id "FinalWire.AIDA64.Extreme" @wingetArgs
    }
    if ($SelectedApps.fancontrol) {
        Write-Host "Installing FanControl..."

        if (Test-DotNet8Support) { $dotnetVersion = "8_0" } else { $dotnetVersion = "4_8" }
        
        $api = "https://api.github.com/repos/Rem0o/FanControl.Releases/releases/latest"
        $uri = $(Invoke-RestMethod $api).assets.browser_download_url | Where-Object {$_.EndsWith("8_0_Installer.exe")}
        $outfile = "$DownloadPath\fancontrol_dotnet$dotnetVersion.exe"
        Invoke-WebRequest -Uri $uri -OutFile $outfile
        Start-Process -FilePath $outfile -ArgumentList "/silent /norestart"
    }
    if ($SelectedApps.cpuz) {
        Write-Host "Installing CPU-Z..."
        winget install --id "CPUID.CPU-Z" @wingetArgs
    }
    if ($SelectedApps.gpuz) {
        Write-Host "Installing GPU-Z..."
        winget install --id "TechPowerUp.GPU-Z" @wingetArgs
    }
    if ($SelectedApps.heaven) {
        Write-Host "Installing Unigine Heaven Benchmark..."
        winget install --id "Unigine.HeavenBenchmark" @wingetArgs
    }
    if ($SelectedApps.valley) {
        Write-Host "Installing Unigine Valley Benchmark..."
        winget install --id "Unigine.ValleyBenchmark" @wingetArgs
    }
    if ($SelectedApps.superposition) {
        Write-Host "Installing Unigine Superposition Benchmark..."
        winget install --id "Unigine.SuperpositionBenchmark" @wingetArgs
    }
    if ($SelectedApps.revo) {
        Write-Host "Installing Revo Uninstaller..."
        winget install --id "RevoUninstaller.RevoUninstaller" @wingetArgs
    }

    return $furmarkInstalled
}

function Set-ScriptVariables {
    # Define standard winget parameters
    $script:wingetArgs = @(
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--silent"
    )

    $script:windowsOSVersion = (systeminfo | findstr /B /C:"OS Name")
    $script:64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem

    $script:Board = (Get-CimInstance Win32_BaseBoard -Property Product).Product
    $script:Manufacturer = (Get-CimInstance Win32_BaseBoard -property Manufacturer).Manufacturer
    $script:fullMotherboardName = "$Manufacturer $Board"

    $script:gpu = (Get-CimInstance Win32_VideoController | Where-Object { $_.Status -eq 'OK' -and $_.Availability -eq 3 }).Name

    $script:cpu = (Get-CimInstance Win32_Processor).Name

    $gb = (((Get-CimInstance -ClassName Win32_PhysicalMemory) | Measure-Object -Property Capacity -Sum).Sum) / 1GB
    $script:ramCapacity = if ($gb -eq [math]::Truncate($gb)) { "$([int]$gb) GB" } else { "{0:N2} GB" -f $gb }
}

function Install-WinGetFresh {
    $url = "https://aka.ms/getwinget"
    $path = "$env:temp\packages"
    $filePath = "$path\Microsoft.DesktopInstaller.msixbundle"
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory "$path" | Out-Null
    }
    Invoke-WebRequest -Uri $url -OutFile $filePath
    Add-AppxPackage $filePath
}

function Start-WinGetSourcesFix {
    winget source remove -n "winget"
    winget source add -n "winget" -a "https://cdn.winget.microsoft.com/cache"
}

function Install-Prerequisites { # Approved Verb ("Places a resource in a location, and optionally initializes it")
    # NuGet
    try {
        $null = Get-PackageProvider -Name NuGet -ErrorAction Stop -ListAvailable | Where-Object { [version]$_.Version -ge [version]'2.8.5.201' }

        Write-Host "NuGet 2.8.5.201 or higher is already installed." -ForegroundColor Green
    } catch {
        Write-Host "NuGet 2.8.5.201 or higher is not installed. Installing now..." -ForegroundColor Yellow
        try {
            Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Force -Confirm:$false
            Write-Host "NuGet installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error installing NuGet: $_" -ForegroundColor Red
        }
    }

    # anybox
    Install-PSModule -ModuleName 'AnyBox' -RequiredVersion '0.5.1'

    # winget powershell module
    Install-PSModule -ModuleName 'Microsoft.WinGet.Client' -RequiredVersion '1.10.340'

    # WinGet
    try {
        $wingetVersionOutput = winget --version
        Write-Host "WinGet is already installed." -ForegroundColor Green
        
        # Check if version is less than 1.6
        if ($wingetVersionOutput -match "v(\d+)\.(\d+)") {
            $majorVersion = [int]$Matches[1]
            $minorVersion = [int]$Matches[2]
            
            if ($majorVersion -lt 1 -or ($majorVersion -eq 1 -and $minorVersion -lt 6)) {
                Write-Host "WinGet version $wingetVersionOutput is outdated. Installing latest version..." -ForegroundColor Yellow
                Write-Host "This can take a while. Please be patient." -ForegroundColor DarkCyan
                try {
                    Install-WinGetFresh
                    Write-Host "WinGet updated successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error updating WinGet: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "WinGet version $wingetVersionOutput is sufficient." -ForegroundColor Green
            }
        } else {
            Write-Host "Could not determine WinGet version from: $wingetVersionOutput" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "WinGet not installed. Installing WinGet..." -ForegroundColor Yellow
        try { 
            # Repair-WinGetPackageManager -AllUsers *>&1 | Out-Null
            # $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            # if ($userPath -notlike '*\Microsoft\WindowsApps*') { [Environment]::SetEnvironmentVariable('Path', $userPath + ";%LOCALAPPDATA%\Microsoft\WindowsApps", 'User') }
            # Add-AppxPackage -RegisterByFamilyName -MainPackage "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
            Install-WinGetFresh
            Write-Host "WinGet installed successfully." -ForegroundColor Green
        } catch { 
            Write-Host "Error installing WinGet: $_" -ForegroundColor Red
        }
    }

    # Helper function to test WinGet and return error information
    function Test-WinGet {
        $wingetError = winget search notepad --source winget 2>&1
        $isSuccess = $LASTEXITCODE -eq 0
        $isWingetSourceBug = ($wingetError -match "0x8a15000f" -and $wingetError -match "Data required by the source is missing")
        
        return @{
            Success = $isSuccess
            WingetSourceBug = $isWingetSourceBug
            ErrorMessage = $wingetError
        }
    }

    Write-Host "Checking WinGet functionality..."
    $testResult = Test-WinGet

    # WinGet working normally - exit early
    if ($testResult.Success) {
        Write-Host -ForegroundColor Green "WinGet is functioning correctly."
        return
    }

    # Check for the specific error we know how to fix
    if ($testResult.WingetSourceBug) {
        Write-Host "Known Error Detected! Running first fix..."
        Start-WinGetSourcesFix
        Write-Host -ForegroundColor Green "Fix applied. Testing WinGet..."
        
        $testResult = Test-WinGet
        if ($testResult.Success) {
            Write-Host -ForegroundColor Green "Fix was successful!"
            return
        }
        
        # If first fix failed, try the second fix
        if ($testResult.WingetSourceBug) {
            Write-Host "Error detected again. Applying alternative fix..."
            Install-WinGetFresh
            Write-Host -ForegroundColor Green "Alternative fix applied. Testing WinGet..."
            
            $testResult = Test-WinGet
            if ($testResult.Success) {
                Write-Host -ForegroundColor Green "Alternative fix was successful!"
                return
            }
            
            # If second fix also failed
            if ($testResult.WingetSourceBug) {
                Write-Host -ForegroundColor Red "All repair attempts failed. Apps may not install properly."
                return
            }
        }
        
        Write-Host -ForegroundColor Red "Unexpected error after repair attempt: $($testResult.ErrorMessage)"
        return
    } else {
        Write-Host -ForegroundColor Red "Unknown WinGet error occurred: $($testResult.ErrorMessage)"
    }
}

function Restart-WindowsExplorer { # Approved Verb ("Stops an operation and then starts it again")
    TASKKILL.exe /F /IM explorer.exe
    Start-Process "$env:WinDir\explorer.exe"
}

function Test-AdminPrivileges { # Approved Verb ("Verifies the operation or consistency of a resource")
    # Check if the script is running as an administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Clear-Host
        Write-Host -ForegroundColor Red "============================================================================="
        Write-Host -ForegroundColor Red "Failure: Current permissions inadequate: Script not running as administrator."
        Write-Host -ForegroundColor Red "============================================================================="
        Get-UserChoice -readHostMessage "[R] Relaunch as administrator [E] Exit" -choicePrompt "Please select an action:" -keys "R", "E" -choiceActions @{
            choiceIsR = { 
                Start-Process `
                -Verb RunAs `
                -FilePath "powershell.exe" `
                -ArgumentList "-Command", "Invoke-RestMethod -Uri 'https://bit.ly/pcflipperwindowsscript' | Invoke-Expression"
                
                Stop-Transcript
                exit
            }
            choiceIsE = { exit }
        }
    }
}

function Test-NetworkConnection {
    param (
        [string[]]$IPs,
        [switch] $showError,
        [switch] $showSuccess,
        [int] $count = 1
    )

    foreach ($ip in $IPs) {
        if (Test-Connection -ComputerName $ip -Count $count -Quiet) {
            if ($showSuccess) {
                Write-Host "Network is up." -ForegroundColor Green
            }
            return $true
        }
    }
    if ($showError) {
        Write-Host "No internet (failed to access all IPs)" -ForegroundColor Red
    }
    return $false
}

function Test-DNSResolver {
    param (
        [string[]] $Domains,
        [switch] $showError,
        [switch] $showSuccess
    )

    foreach ($domain in $Domains) {
        try {
            $result = Resolve-DnsName -Name $domain -ErrorAction Stop
            if ($result) {
                if ($showSuccess) {
                    Write-Host "DNS resolved successfully." -ForegroundColor Green
                }
                return $true
            }
        } catch {
            if ($showError) {
                Write-Host "Failed to resolve $domain." -ForegroundColor Yellow
            }
        }
    }
    if ($showError) {
        Write-Host "DNS resolution failed for all domains." -ForegroundColor Red
    }
    return $false
}
function Test-Internet { # "container" for Test-NetworkConnection and Test-DNSResolver
    $myIps = @("8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1")
    $myDomains = @("www.github.com", "www.google.com", "www.cloudflare.com", "www.microsoft.com")
    $hasInternet = Test-NetworkConnection -ShowError:$false -ShowSuccess:$false -IPs $myIps -Count 2
    $hasDns = Test-DNSResolver -ShowError:$false -ShowSuccess:$false -Domains $myDomains

    if (-not $hasInternet) {
        Clear-Host
        Write-Host -ForegroundColor Red "========================================================"
        Write-Host                      "        Failure: Internet Connection Test Failed.       "
        Write-Host                      "Please make sure that you are connected to the Internet."
        Write-Host -ForegroundColor Red "========================================================"
        Write-Host -ForegroundColor Green "`nPress any key to exit..."
        Read-Host
        exit
    }

    if (-not $hasDns) {
        Clear-Host
        Write-Host -ForegroundColor Red "========================================================"
        Write-Host                      "             Failure: DNS Resolution Failed.            "
        Write-Host                      "Please make sure that you are connected to the Internet."
        Write-Host -ForegroundColor Red "========================================================"
        Write-Host -ForegroundColor Green "`nPress any key to exit..."
        Read-Host
        exit
    }
}

function Test-DotNet8Support {
    try {
        $runtimes = & dotnet --list-runtimes 2>$null
        return [bool]($runtimes -match '^Microsoft\.NETCore\.App 8\.')
    } catch {
        return $false
    }
}

function Show-ScriptCompleteBox { # Approved Verb ("Makes a resource visible to the user")
    $null = Show-AnyBox `
    -Title 'Script complete' `
    -Message 'The script has finished running!', 'Please give it a star on GitHub!', 'Created by PowerPCFan' `
    -Buttons 'Ok' `
    -MinWidth 325 `
    -MinHeight 150
}

function Show-ScriptOptionsWindow {
    param(
        [string] $font = "Segoe UI, Arial",
        [string] $height = "650",
        [string] $width = "850"
    )

    # Add WPF and Windows.Forms assemblies
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName System.Windows.Forms

    [xml] $xaml = @"
    <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Script Options" Height="$height" Width="$width" FontFamily="$font">
        <Window.Resources>
            <Style TargetType="{x:Type Control}">
                <Setter Property="FontFamily" Value="$font" />
            </Style>
            <Style TargetType="{x:Type TextBlock}">
                <Setter Property="FontFamily" Value="$font" />
            </Style>
        </Window.Resources>
        <Grid Margin="10">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <TextBlock Grid.Row="0" Text="Script Options" FontSize='22' FontWeight='Bold' Margin='0,0,0,8' />
            <TextBlock Grid.Row="1" Text="Select the tasks you would like to run." FontWeight='Bold' Margin='0,0,0,8' />
            <Separator Grid.Row="2" Margin="0,10,0,10" />
            <Border Grid.Row="3" Padding="10,10,10,10" BorderBrush="Gainsboro" BorderThickness="1">
                <ScrollViewer Name="MainScrollViewer" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <TextBlock Text="Driver Installation" FontWeight="Bold" Margin='0,0,0,8' />
                        
                        <CheckBox Name="InstallGpuDrivers" Content="Install GPU Drivers" IsChecked="True" />
                        <TextBlock Text="Detects your GPU and installs the appropriate drivers" Margin="25,0,0,15" TextWrapping="Wrap" Opacity="0.7" />
                        
                        <CheckBox Name="InstallChipsetDrivers" Content="Install Chipset Drivers" IsChecked="True" />
                        <TextBlock Text="Installs the appropriate chipset drivers for your CPU" Margin="25,0,0,15" TextWrapping="Wrap" Opacity="0.7" />
                        
                        <CheckBox Name="ShowMotherboardDriverPage" Content="Open Motherboard Driver Page" IsChecked="True" />
                        <TextBlock Text="Opens your motherboard's driver page to download additional drivers or software" Margin="25,0,0,15" TextWrapping="Wrap" Opacity="0.7" />
                        
                        <TextBlock Text="System Configuration" FontWeight="Bold" Margin='0,0,0,8' />
                        
                        <CheckBox Name="RunWindowsTweaks" Content="Tweak Windows" IsChecked="False" />
                        <TextBlock Text="Applies basic Windows tweaks such as disabling location services or disabling telemetry" Margin="25,0,0,15" TextWrapping="Wrap" Opacity="0.7" />
                        
                        <CheckBox Name="ActivateWindows" Content="Activate Windows" IsChecked="False" />
                        <TextBlock Text="Activate your Windows installation" Margin="25,0,0,5" TextWrapping="Wrap" Opacity="0.7" />
                                                
                        <StackPanel Name="ActivateWindowsPanel" Margin="25,0,0,15" Visibility="Collapsed">
                            <RadioButton Name="ActivateWindowsMassgrave" Content="Massgrave (Free Activation Tool)" IsChecked="True" GroupName="ActivationMethod" Margin="0,5,0,5" />
                            <RadioButton Name="ActivateWindowsKey" Content="Authentic Key" GroupName="ActivationMethod" Margin="0,5,0,5" />
                            
                            <StackPanel Name="AuthenticKeyPanel" Margin="25,5,0,0" Visibility="Collapsed">
                                <TextBlock Text="Enter your Windows Product Key:" Margin="0,5,0,5" />
                                <TextBox Name="WindowsProductKey" Width="300" HorizontalAlignment="Left" />
                            </StackPanel>
                        </StackPanel>

                        <TextBlock Text="Application Management" FontWeight="Bold" Margin='0,0,0,8' />
                        
                        <CheckBox Name="RunAppInstaller" Content="Install Applications" IsChecked="True" />
                        <TextBlock Text="Choose applications to install on this system" Margin="25,0,0,0" TextWrapping="Wrap" Opacity="0.7" />
                        
                        <StackPanel Name="AppInstallerPanel" Margin="25,0,0,15" Visibility="Visible">
                            <TextBlock Text="Available Applications" FontWeight="Bold" Margin='5,5,0,5' />
                        
                            <CheckBox Name="redist" Content="Visual C++ Redist Runtimes (Recommended)" Margin='0,0,0,8' IsChecked="True" />
                            <CheckBox Name="dotnet" Content="Microsoft .NET Runtimes (Recommended)" Margin='0,0,0,8' IsChecked="True" />
                            <CheckBox Name="SevenZip" Content="7-Zip (Recommended)" Margin='0,0,0,8' IsChecked="True" />
                            <CheckBox Name="FurMark" Content="FurMark (Recommended)" Margin='0,0,0,8' IsChecked="True" />
                            <StackPanel Name="FurMarkSubOptions" Margin="25,0,0,0">
                                <CheckBox Name="RunFurmarkTest" Content="Run FurMark Stress Test after installation" IsChecked="True" />
                                <TextBlock Text="Runs a GPU stress test using FurMark" Margin="25,0,0,5" TextWrapping="Wrap" Opacity="0.7" />
                                
                                <StackPanel Name="FurMarkTestOptions" Margin="25,0,0,10">
                                    <TextBlock Text="Test Duration (minutes):" Margin="0,5,0,2" />
                                    <TextBox Name="FurMarkDuration" Width="100" HorizontalAlignment="Left" Text="5" />
                                    
                                    <TextBlock Text="Resolution:" Margin="0,10,0,2" />
                                    <ComboBox Name="FurMarkResolution" Width="150" HorizontalAlignment="Left" SelectedIndex="1">
                                        <ComboBoxItem Content="720p (1280x720)" />
                                        <ComboBoxItem Content="1080p (1920x1080)" />
                                        <ComboBoxItem Content="1440p (2560x1440)" />
                                    </ComboBox>
                                    
                                    <TextBlock Text="Anti-Aliasing:" Margin="0,10,0,2" />
                                    <ComboBox Name="FurMarkAntiAliasing" Width="150" HorizontalAlignment="Left" SelectedIndex="2">
                                        <ComboBoxItem Content="None" />
                                        <ComboBoxItem Content="MSAA 2x" />
                                        <ComboBoxItem Content="MSAA 4x" />
                                        <ComboBoxItem Content="MSAA 8x" />
                                    </ComboBox>
                                </StackPanel>
                            </StackPanel>
                            <CheckBox Name="Firefox" Content="Firefox" Margin='0,0,0,8' />
                            <CheckBox Name="Chrome" Content="Chrome" Margin='0,0,0,8' />
                            <CheckBox Name="Steam" Content="Steam" Margin='0,0,0,8' />
                            <CheckBox Name="Discord" Content="Discord" Margin='0,0,0,8' />
                            <CheckBox Name="EpicGamesLauncher" Content="Epic Games Launcher" Margin='0,0,0,8' />
                            <CheckBox Name="OpenRGB" Content="OpenRGB" Margin='0,0,0,8' />
                            <CheckBox Name="SignalRGB" Content="SignalRGB" Margin='0,0,0,8' />
                            <CheckBox Name="VLC" Content="VLC Media Player" Margin='0,0,0,8' />
                            <CheckBox Name="Malwarebytes" Content="Malwarebytes" Margin='0,0,0,8' />
                            <CheckBox Name="HWMonitor" Content="HWMonitor" Margin='0,0,0,8' />
                            <CheckBox Name="MSIAfterburner" Content="MSI Afterburner" Margin='0,0,0,8' />
                            <CheckBox Name="OCCT" Content="OCCT" Margin='0,0,0,8' />
                            <CheckBox Name="Cinebench" Content="Cinebench R23" Margin='0,0,0,8' />
                            <CheckBox Name="CrystalDiskMark" Content="CrystalDiskMark" Margin='0,0,0,8' />
                            <CheckBox Name="CrystalDiskInfo" Content="CrystalDiskInfo" Margin='0,0,0,8' />
                            <CheckBox Name="aida64" Content="AIDA64" Margin='0,0,0,8' />
                            <CheckBox Name="fancontrol" Content="FanControl" Margin='0,0,0,8' />
                            <CheckBox Name="cpuz" Content="CPU-Z" Margin='0,0,0,8' />
                            <CheckBox Name="gpuz" Content="GPU-Z" Margin='0,0,0,8' />
                            <CheckBox Name="heaven" Content="Unigine Heaven Benchmark" Margin='0,0,0,8' />
                            <CheckBox Name="valley" Content="Unigine Valley Benchmark" Margin='0,0,0,8' />
                            <CheckBox Name="superposition" Content="Unigine Superposition Benchmark" Margin='0,0,0,8' />
                            <CheckBox Name="revo" Content="Revo Uninstaller" Margin='0,0,0,8' />
                        </StackPanel>
                    </StackPanel>
                </ScrollViewer>
            </Border>
            <Button Grid.Row="4" Content="Start Script" Name="ContinueButton" HorizontalAlignment="Right" Margin="0,10,0,0" Padding="15,5" />
        </Grid>
    </Window> 
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    
    # Get the ScrollViewer and add the event handler
    $scrollViewer = $window.FindName("MainScrollViewer")
    $scrollViewer.Add_PreviewMouseWheel({
        param($senderVar, $e)
        
        try {
            if ([System.Windows.Forms.SystemInformation]::MouseWheelScrollLines -eq -1) {
                $e.Handled = $false 
            } else {
                try {
                    $scrollViewer = [System.Windows.Controls.ScrollViewer]$senderVar
                    $newOffset = $scrollViewer.VerticalOffset - ($e.Delta * 10 * [System.Windows.Forms.SystemInformation]::MouseWheelScrollLines / 120)
                    $scrollViewer.ScrollToVerticalOffset($newOffset)
                    $e.Handled = $true
                } catch {
                    # fall back to default scrolling
                }
            }
        } catch {
            # fall back to default scrolling
        }
    })

    # Initialize options as local variable
    $taskOptions = @{} 

    # Get checkboxes and panels
    $runAppInstaller = $window.FindName("RunAppInstaller")
    $appInstallerPanel = $window.FindName("AppInstallerPanel")
    $furMarkSubOptions = $window.FindName("FurMarkSubOptions")
    $runFurmarkTest = $window.FindName("RunFurmarkTest")
    $furMarkCheckbox = $window.FindName("FurMark")
    
    # Toggle visibility of app installer panel based on RunAppInstaller checkbox
    $runAppInstaller.Add_Checked({
        $appInstallerPanel.Visibility = [System.Windows.Visibility]::Visible
    })
    
    $runAppInstaller.Add_Unchecked({
        $appInstallerPanel.Visibility = [System.Windows.Visibility]::Collapsed
    })

    # Toggle visibility of FurMark sub-options based on FurMark checkbox
    $furMarkCheckbox.Add_Checked({
        $furMarkSubOptions.Visibility = [System.Windows.Visibility]::Visible
        $runFurmarkTest.IsEnabled = $true
        $runFurmarkTest.ToolTip = $null
    })
    
    $furMarkCheckbox.Add_Unchecked({
        $furMarkSubOptions.Visibility = [System.Windows.Visibility]::Collapsed
        $runFurmarkTest.IsChecked = $false
        $runFurmarkTest.IsEnabled = $false  
        $runFurmarkTest.ToolTip = "Enable FurMark installation to enable stress testing"
    })

    # Get FurMark test options panel
    $furMarkTestOptions = $window.FindName("FurMarkTestOptions")
    
    # Toggle visibility of FurMark test options based on RunFurmarkTest checkbox
    $runFurmarkTest.Add_Checked({
        $furMarkTestOptions.Visibility = [System.Windows.Visibility]::Visible
    })
    
    $runFurmarkTest.Add_Unchecked({
        $furMarkTestOptions.Visibility = [System.Windows.Visibility]::Collapsed
    })

    # activate windows checkbox stuff
    # Get Activate Windows panel and controls
    $activateWindows = $window.FindName("ActivateWindows")
    $activateWindowsPanel = $window.FindName("ActivateWindowsPanel")
    $activateWindowsKey = $window.FindName("ActivateWindowsKey")
    $authenticKeyPanel = $window.FindName("AuthenticKeyPanel")
    
    
    $keyInput = $window.FindName("WindowsProductKey")

    $keyInput.Add_TextChanged({
        $raw = ($keyInput.Text -replace '[^A-Za-z0-9]', '').ToUpper()
        $raw = $raw.Substring(0, [Math]::Min(25, $raw.Length))
        $chunks = ($raw -split '(.{5})' | Where-Object { $_ -ne '' })
        $formatted = ($chunks -join '-')
        $keyInput.Text = $formatted
        $keyInput.CaretIndex = $keyInput.Text.Length
    })
    


    # Toggle visibility of Windows activation panel based on checkbox
    $activateWindows.Add_Checked({
        $activateWindowsPanel.Visibility = [System.Windows.Visibility]::Visible
    })

    $activateWindows.Add_Unchecked({
        $activateWindowsPanel.Visibility = [System.Windows.Visibility]::Collapsed
    })

    # Toggle visibility of product key textbox based on radio button
    $activateWindowsKey.Add_Checked({
        $authenticKeyPanel.Visibility = [System.Windows.Visibility]::Visible
    })

    $activateWindowsKey.Add_Unchecked({
        $authenticKeyPanel.Visibility = [System.Windows.Visibility]::Collapsed
    })

    # Function to get all checkboxes in the window - simplified approach
    function Get-AllCheckboxes {
        $allCheckboxes = New-Object System.Collections.ArrayList
        
        # Find all elements in the window recursively
        function Find-AllElements {
            param([object]$element)
            
            # If this element is a checkbox, add it
            if ($element -is [System.Windows.Controls.CheckBox]) {
                $null = $allCheckboxes.Add($element)
            }
            
            # For ContentControls like ScrollViewer, Border, etc., get their content
            if ($element -is [System.Windows.Controls.ContentControl]) {
                if ($null -ne $element.Content) {
                    Find-AllElements -element $element.Content
                }
            }
            
            # For panels like StackPanel, Grid, etc., check all their children
            if ($element -is [System.Windows.Controls.Panel]) {
                foreach ($child in $element.Children) {
                    Find-AllElements -element $child
                }
            }
            
            # Special case for ItemsControl like ComboBox
            if ($element -is [System.Windows.Controls.ItemsControl]) {
                foreach ($item in $element.Items) {
                    Find-AllElements -element $item
                }
            }
        }
        
        # Start searching from the window itself
        Find-AllElements -element $window
        
        return $allCheckboxes
    }

    # Continue button
    $continueButton = $window.FindName("ContinueButton")
    $continueButton.Add_Click({
        # Get main section checkboxes first
        $taskOptions["InstallGpuDrivers"] = $window.FindName("InstallGpuDrivers").IsChecked
        $taskOptions["InstallChipsetDrivers"] = $window.FindName("InstallChipsetDrivers").IsChecked
        $taskOptions["ShowMotherboardDriverPage"] = $window.FindName("ShowMotherboardDriverPage").IsChecked
        $taskOptions["RunWindowsTweaks"] = $window.FindName("RunWindowsTweaks").IsChecked
        $taskOptions["RunAppInstaller"] = $window.FindName("RunAppInstaller").IsChecked
        $taskOptions["ActivateWindows"] = $window.FindName("ActivateWindows").IsChecked

        # Handle Windows Activation nested options
        if ($window.FindName("ActivateWindows").IsChecked) {
            $taskOptions["ActivateWindowsMassgrave"] = $window.FindName("ActivateWindowsMassgrave").IsChecked
            $taskOptions["ActivateWindowsKey"] = $window.FindName("ActivateWindowsKey").IsChecked
            if ($window.FindName("ActivateWindowsKey").IsChecked) {
                $taskOptions["WindowsProductKey"] = $window.FindName("WindowsProductKey").Text
            }
        } else {
            $taskOptions["ActivateWindowsMassgrave"] = $false
            $taskOptions["ActivateWindowsKey"] = $false
            $taskOptions["WindowsProductKey"] = ""
        }

        # Handle Application Installation nested options
        if ($window.FindName("RunAppInstaller").IsChecked) {
            # Get all app checkboxes
            $appPanel = $window.FindName("AppInstallerPanel")
            $appCheckboxes = $appPanel.Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
            foreach ($checkbox in $appCheckboxes) {
                $taskOptions[$checkbox.Name] = $checkbox.IsChecked
            }

            # Handle FurMark nested options
            if ($window.FindName("FurMark").IsChecked) {
                $taskOptions["RunFurmarkTest"] = $window.FindName("RunFurmarkTest").IsChecked
                if ($window.FindName("RunFurmarkTest").IsChecked) {
                    $taskOptions["FurMarkDuration"] = $window.FindName("FurMarkDuration").Text
                    $taskOptions["FurMarkResolution"] = $window.FindName("FurMarkResolution").SelectedItem.Content.ToString()
                    $taskOptions["FurMarkAntiAliasing"] = $window.FindName("FurMarkAntiAliasing").SelectedItem.Content.ToString()
                }
            } else {
                $taskOptions["RunFurmarkTest"] = $false
                $taskOptions["FurMarkDuration"] = ""
                $taskOptions["FurMarkResolution"] = ""
                $taskOptions["FurMarkAntiAliasing"] = ""
            }
        } else {
            # If app installer is unchecked, clear all app-related options
            $appPanel = $window.FindName("AppInstallerPanel")
            $appCheckboxes = $appPanel.Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
            foreach ($checkbox in $appCheckboxes) {
                $taskOptions[$checkbox.Name] = $false
            }
            $taskOptions["RunFurmarkTest"] = $false
            $taskOptions["FurMarkDuration"] = ""
            $taskOptions["FurMarkResolution"] = ""
            $taskOptions["FurMarkAntiAliasing"] = ""
        }

        # Always store FurMark installation state
        $taskOptions["FurmarkInstalled"] = $furmarkInstalled

        $window.DialogResult = $true
        $window.Close()
    })

    # Show window and return options
    $null = $window.ShowDialog()
    return $taskOptions
}

function Invoke-SelectedScriptTasks {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Tasks
    )

    if ($Tasks.InstallGpuDrivers) {
        Install-GPUDrivers
    }

    if ($Tasks.InstallChipsetDrivers) {
        Install-ChipsetDrivers
    }

    if ($Tasks.ShowMotherboardDriverPage) {
        Show-MotherboardDriverPage
    }

    if ($Tasks.RunWindowsTweaks) {
        Start-WindowsTweaks
        Restart-WindowsExplorer
    }

    if ($Tasks.ActivateWindows) {
        $activationParams = @{
            UseMassgrave = $Tasks.ActivateWindowsMassgrave
            UseKey = $Tasks.ActivateWindowsKey
            ProductKey = $Tasks.WindowsProductKey
        }
        Start-WindowsActivation @activationParams
    }

    if ($Tasks.RunAppInstaller) {
        $selectedApps = @{}

        $apps = @(
            'redist', 'dotnet', 'Firefox', 'Chrome', 'Steam', 'Discord', 
            'EpicGamesLauncher', 'OpenRGB', 'SignalRGB', 'VLC', 'SevenZip',
            'Malwarebytes', 'HWMonitor', 'MSIAfterburner', 'FurMark', 'OCCT',
            'Cinebench', 'CrystalDiskMark', 'CrystalDiskInfo', 'aida64', 'fancontrol', 
            'cpuz', 'gpuz', 'heaven', 'valley', 'superposition', 'revo'
        )

        foreach ($app in $apps) {
            if ($null -ne $Tasks.$app) {
                $selectedApps[$app] = $Tasks.$app
            }
        }

        Install-SelectedApps -SelectedApps $selectedApps 
    }

    if ($Tasks.RunFurmarkTest -and $Tasks.FurmarkInstalled) {
        $furmarkParams = @{
            Duration = $Tasks.FurMarkDuration
            Resolution = $Tasks.FurMarkResolution  
            AntiAliasing = $Tasks.FurMarkAntiAliasing
        }
        Start-FurmarkTest @furmarkParams
    }
}

function Start-WindowsActivation {
    param (
        [bool]$UseMassgrave,
        [bool]$UseKey,
        [string]$ProductKey
    )

    function Start-MassgraveScript {
        if (-not $PSScriptRoot) {
            Write-Host -ForegroundColor Red "Error: variable `$PSScriptRoot does not exist. Massgrave not started."
            return
        }
        # Download massgrave script
        # this code does the following:
        # Converts line endings from LF to CRLF if it has LF endings
        # Also saves the file as UTF-8 without BOM
        Write-Host "Downloading Massgrave script..."
        New-Item -Type Directory -Path "bin\mas" | Out-Null
        $masUrl = "https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/refs/heads/master/MAS/Separate-Files-Version/Activators/HWID_Activation.cmd"
        $masOutFilePath = Join-Path -Path $PSScriptRoot -ChildPath "\mas\hwid.cmd"
        $lfcontent = (Invoke-WebRequest -UseBasicParsing -Uri $masUrl).Content
        $crlfContent = $lfcontent -replace "`r?`n", "`r`n"
        $utf8nobom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($masOutFilePath, $crlfContent, $utf8nobom)

        Write-Host "Starting Massgrave script..."
        Start-Process -Verb runAs -FilePath "cmd.exe" -ArgumentList "/c", "`"$masOutFilePath`"", "/HWID"
    }

    function Start-WindowsActivationProcessWithKey {
        param (
            [string]$ProductKey
        )

        if (-not [string]::IsNullOrWhiteSpace($ProductKey)) {
            Write-Host "Activating Windows using product key..."
            try {
                # Get Service
                $service = Get-CimInstance -ClassName "SoftwareLicensingService"

                # Get Product
                $splat = @{
                    ClassName = 'SoftwareLicensingProduct'
                    Filter = "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
                }
                $product = Get-CimInstance @splat

                # Install Product Key
                $service | Invoke-CimMethod -MethodName InstallProductKey -Arguments @{ ProductKey = $ProductKey } | Out-Null
                
                # Activate with product key
                $product | Invoke-CimMethod -MethodName Activate | Out-Null
                
                # Refresh license status
                $service | Invoke-CimMethod -MethodName RefreshLicenseStatus | Out-Null

                Write-Host -ForegroundColor Green "Success! Windows is activated."
            } catch {
                Write-Host -ForegroundColor Red "Error activating Windows."
            }
        } else {
            Write-Host -ForegroundColor Yellow "No product key was entered, skipping activation..."
        }
    }
    
    if ($UseMassgrave) {
        Start-MassgraveScript
    } elseif ($UseKey) {
        Start-WindowsActivationProcessWithKey -ProductKey $ProductKey
    }
}



































$ProgressPreference = 'SilentlyContinue' # for commands like invoke-webrequest/invoke-restmethod

Set-ScriptVariables

# Start Transcript
Start-Logging

Write-Host "Checking for administrator privileges..."
Test-AdminPrivileges
Write-Host "Checking internet connectivity..."
Test-Internet
# unless I overlooked something, this will only print when the checks are successful since both functions interrupt the script if they fail
Write-Host -ForegroundColor Green "Success"

# Install prerequisites and import modules
Write-Host "Installing prerequisites..."
Install-Prerequisites
Import-Module -Name "AnyBox"
Import-Module -Name "Microsoft.WinGet.Client"

# Show the main window and run selected tasks
$selectedTasks = Show-ScriptOptionsWindow
Invoke-SelectedScriptTasks -Tasks $selectedTasks

# Show completion dialog and stop transcript
Show-ScriptCompleteBox
Stop-Transcript
