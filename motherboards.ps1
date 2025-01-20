function MotherboardDriverAutoDownloader {
    # Disables the Invoke-WebRequest progressbar to make downloads significantly faster
    $ProgressPreference = 'SilentlyContinue'

    if ($fullMotherboardName -like "*Micro-Star International Co., Ltd. MPG B550 GAMING PLUS*") {
    
                # MSI MPG B550 Gaming Plus    
        
        prep

        # AMD Chipset Drivers
        Invoke-WebRequest -Uri "https://download.msi.com/dvr_exe/mb/amd_chipset_drivers_am4_am5.zip" -OutFile "$dLocation\chipsetdrivers.zip"
        # Ethernet Drivers
        Invoke-WebRequest -Uri "https://download.msi.com/dvr_exe/mb/realtek_pcielan_w10.zip" -OutFile "$dLocation\ethernetdrivers.zip"
        # Onboard Audio Drivers
        Invoke-WebRequest -Uri "https://download.msi.com/dvr_exe/mb/realtek_audio_R.zip" -OutFile "$dLocation\audiodrivers.zip"

        AnyBoxForExplorerConfirmation
    } elseif ($fullMotherboardName -like "*Gigabyte Technology Co., Ltd. B650 AORUS ELITE AX*") {
        
                # Gigabyte B650 Aorus Elite AX
        
        prep

        # Realtek HD Audio Drivers
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_612_realtekdch_6.0.9733.1.zip?v=a79ab3a90ffe8f85d84e4bff8f115c03" -OutFile "$dLocation\audiodrivers.zip"

        # AMD Chipset Drivers
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_597_chipset_6.10.22.027.zip?v=07fc68085b5e1334e08275050c15ef84" -OutFile "$dLocation\chipsetdrivers.zip"

        # Realtek LAN drivers - Check for Windows 10 or 11 to download appropriate driver
        $windowsOSVersion = (systeminfo | findstr /B /C:"OS Name")
        if ($windowsOSVersion -like "*Windows 10*") {
            Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_542_w10_10.072.0524.2024.zip?v=819e6069b2900cff29488ad99bfa2b3f" -OutFile "$dLocation\win10landriver.zip"
        } elseif ($windowsOSVersion -like "*Windows 11*") {
            Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_654_w11_11.21.0903.2024.zip?v=30104525c049ad94a405ce5806521e5c" -OutFile "$dLocation\win11landriver.zip"
        }

        do {
            Write-Host "Your motherboard has multiple Wi-Fi and Bluetooth driver versions. Please select the proper version - this cannot be autodetected."
            $key = Read-Host "[1] Intel Drivers [2] Intel Drivers- for Board Revision 1.1 [3] AMD Drivers - for Board Revision 1.0"
            switch ($key.ToUpper()) {
                '1' {
                    $validInput = $true
                    # Intel Wi-FI and Bluetooth drivers
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_607_win10_23.90.0.8.zip?v=fe56d0602a898aaaddce770b50896acf" -OutFile "$dLocation\1-BT.zip"
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_630_dchsetup_23.100.0.4.zip?v=572bfe7993fb24700f2295b6296d5b50" -OutFile "$dLocation\1-WIFI.zip"
                }
                '2' {
                    $validInput = $true
                    # Intel Wi-FI and Bluetooth drivers (PCB rev 1.1)
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_607_win10_22.170.0.2.zip?v=c01afa425dbbb8595e341b5c7d39386d" -OutFile "$dLocation\2-BT.zip"
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_630_dchsetup_22.200.0.6.zip?v=0981fe7e5384f7d322e9db2300199467" -OutFile "$dLocation\2-WIFI.zip"
                }
                '3' {
                    $validInput = $true
                    # AMD Wi-FI and Bluetooth drivers (PCB rev 1.0)
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_645_amd_1.8240.169.zip?v=7c339188261781a80a60607e4e0ec9e1" -OutFile "$dLocation\3-BT.zip"
                    Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_644_amdwifi_3.3.0.496.zip?v=7f9b9bdf8dc259889b72a0bfd0899712" -OutFile "$dLocation\3-WIFI.zip"
                }
                default {
                    $validInput = $false
                    Write-Host "Invalid input. Please try again"
                }
            }
        } while (-not $validInput)
        
        # Check for Ryzen 8000 APU
        $cpu = (Get-WmiObject Win32_Processor).Name
        if ($cpu -like "*AMD Ryzen*8*G*Radeon*") {
            # Ryzen 8000 series NPU drivers
            Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_2691_npu_10.1109.0008.128.zip?v=08292688ce74e1ad499426858f0404e9" -OutFile "$dLocation\8000NPUdrivers.zip"
        }

        AnyBoxForExplorerConfirmation
    } elseif ($fullMotherboardName -like "*Gigabyte Technology Co., Ltd. B650 GAMING X AX*") {
                
                # Gigabyte B650 Aorus Elite AX
        
        Write-Host "This board has many revisions so it is hard to fully automate the driver download process."
        Write-Host -ForegroundColor Green "Press any key to visit the driver download page."
        Read-Host
        $DriversURL = "https://www.gigabyte.com/Motherboard/B650-GAMING-X-AX-rev-10-11-12/support#support-dl-driver"
        Start-Process $DriversURL
    
    } elseif ($fullMotherboardName -like "*Gigabyte Technology Co., Ltd. B560M D3H*") {
    
                # Gigabyte B560M D3H   

        prep

        # Intel Chipset Drivers
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_infupdate_10.1.18836.8283_n.zip?v=5449db0c9a1cc7ca06306bf7c96fb3ed" -OutFile "$dLocation\inf.zip"
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_653_serialio_30.100.2129.8.zip?v=d1e7cae2f9bedecc6dcd3546b7dccb83" -OutFile "$dLocation\serialio.zip"
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_642_consumer_2129.62.62.0.zip?v=c2585340f6087fce02291f5eb43e03f1" -OutFile "$dLocation\maneng.zip"
        # LAN Drivers
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_61_intel_26.2.zip?v=5b58acc44a7c8a843a2723733da82211" -OutFile "$dLocation\landrivers.zip"
        # Realtek HD Audio Drivers
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_612_realtekdch_6.0.9235.1.zip?v=7fe824bcf96330be2c702339349d216d" -OutFile "$dLocation\audiodrivers.zip"

        AnyBoxForExplorerConfirmation
    } elseif ($fullMotherboardName -like "*ASUSTeK COMPUTER INC. H81M-D*") {
    
                # ASUS H81M-D

        prep

        # bruh this h81 chipset is from like 2013 idk what these drivers are, but it's all the ones required ¯\_(ツ)_/¯
        Invoke-WebRequest -Uri "https://dlcdnets.asus.com/pub/ASUS/misc/vga/Intel_Graphics_Win7-8-81-10_V1018144170_2019154377.zip?model=H81M-D" -OutFile "$dLocation\gpuaccel.zip"
        Invoke-WebRequest -Uri "https://dlcdnets.asus.com/pub/ASUS/misc/utils/MEI-Win7-8-81-10_V11001172_857.zip?model=H81M-D" -OutFile "$dLocation\maneng.zip"
        Invoke-WebRequest -Uri "https://dlcdnets.asus.com/pub/ASUS/lan/Realtek_LAN_Win7-8-81-10_V787529_838115_102703_535.zip?model=H81M-D" -OutFile "$dLocation\landrivers.zip"
        Invoke-WebRequest -Uri "https://dlcdnets.asus.com/pub/ASUS/misc/audio/Realtek_Audio_Win7-8-81-10_V6017770.zip?model=H81M-D" -OutFile "$dLocation\audiodrivers.zip"

        AnyBoxForExplorerConfirmation
    } elseif ($fullMotherboardName -like "*GA-H61M-S1*") {
                # Gigabyte GA-H61M-S1
        
        prep

        # another old motherboard lmao here are the driversssssss (specifically board revision 2.1 drivers if that matters)
        # btw these are the windows 10 drivers cuz windows 7 is out of support and the drivers for windows 7 are ancient
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_audio_realtek_w10.zip?v=5ff6e24528d607bc834fae72952133e1" -OutFile "$dLocation\audio.zip"
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_chipset_intel_w10.zip?v=a2d69b2e001945fcd145567baff9969b" -OutFile "$dLocation\inf.zip"
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_intel_me_w10.zip?v=65c1460d48ea7081992bdacfde1dae41" -OutFile "$dLocation\maneng.zip"
        Invoke-WebRequest -Uri "https://download.gigabyte.com/FileList/Driver/mb_driver_lan_realtek_w10.zip?v=06f40daf5559a0692eb2f2a2e5350bce" -OutFile "$dLocation\lan.zip"
        # left out vga drivers because it differs between cpu generations and nobody is probably gonna be running this script on this board anyways so it doesnt really matter xd

    } elseif ($fullMotherboardName -like "*ASRock B450M/ac*") {
    
                # ASRock B450M/ac 

        prep

        # AMD Chipset Drivers
        Invoke-WebRequest -Uri "https://download.asrock.com/Drivers/CPU/Chipset(v3.10.22.706).zip" -OutFile "$dLocation\inf.zip"
        # LAN Drivers
        Invoke-WebRequest -Uri "https://download.asrock.com/Drivers/All/LAN/Realtek_LAN(v1.00.0037).zip" -OutFile "$dLocation\landrivers.zip"
        # Realtek HD Audio Drivers
        Invoke-WebRequest -Uri "https://download.asrock.com/Drivers/All/Audio/Realtek_Audio(v6.0.9231.1).zip" -OutFile "$dLocation\audiodrivers.zip"
        # BT + WiFi drivers
        Invoke-WebRequest -Uri "https://download.asrock.com/Drivers/Intel/Bluetooth/Intel_Bluetooth(v21.10.1.1).zip" -OutFile "$dLocation\bt.zip"
        Invoke-WebRequest -Uri "https://download.asrock.com/Drivers/Intel/WLAN/Intel_WLAN(v21.10.1.2).zip" -OutFile "$dLocation\wifi.zip"

        AnyBoxForExplorerConfirmation
    } else {
        BoardNotInDatabase
    }
}

# Add gigabyte b660m ds3h ax ddr4 (my motherboard) at some point
# also add "Gigabyte Technology Co., Ltd. B650 GAMING X AX V2" (v1 is done already - same drivers applicable??)











function AnyBoxForExplorerConfirmation {
    # Open a dialog box using AnyBox to ask the user for confirmation to open File Explorer to the $dLocation folder
    $anybox = New-Object AnyBox.AnyBox
		
    $anybox.Message = 'Drivers successfully downloaded! Press "Yes" to open Windows Explorer to the folder that the drivers are located in.'

    $anybox.Buttons = @(
        New-AnyBoxButton -Name 'cancel' -Text 'Cancel'
        New-AnyBoxButton -Name 'oexp' -Text 'Open Explorer'
    )

    # Show the AnyBox; collect responses.
    $response = $anybox | Show-AnyBox

    if ($response['oexp'] -eq $true) {
        Start-Process $env:WinDir\explorer.exe $dLocation
    }
}

function BoardNotInDatabase {
    Write-Host "Unfortunately, your motherboard is currently unsupported by the automatic driver downloader."
    $searchUrl = "https://duckduckgo.com/?q=motherboard+drivers+for+$($fullMotherboardName -replace ' ', '+')"
	Write-Output "Press ENTER to open your default browser and display the search results for your motherboard drivers, so you can install them manually."
	Read-Host
    Start-Process $searchUrl
}

function prep {
    # Make directory to download drivers to, and "cd" the directory
    New-Item -Directory "C:\DownloadedDrivers"
    Set-Location "C:\DownloadedDrivers"

    # Set variable for driver download location
    $Script:dLocation = "C:\DownloadedDrivers"
}