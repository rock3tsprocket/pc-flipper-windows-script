import os
import shutil
import time
#import GPUtil
import requests
import sys
from datetime import datetime

RED = "\033[0;31m"
RESET = "\033[0m"
CYAN = "\033[0;36m"

def init():
	if sys.platform == "win32":
		mainFolderPath = os.getenv("TEMP")+"\\pc-flipper-script"
	else:
		print("No.")
		exit("1")

	scriptDownloadPath = "bin"

	# Deletes old files to avoid conflicts if you've run the script before.
	if os.path.isdir(mainFolderPath): 
		shutil.rmtree(mainFolderPath)

	# Creates new directory for files and scripts
	os.mkdir(mainFolderPath)

	# Sets location to the script folder
	os.chdir(mainFolderPath)

	# SCRIPT DOWNLOADS
	os.mkdir(scriptDownloadPath)
init()
def Remove_IfExists(path): # Approved Verb ("Deletes a resource from a container")
	if os.is_dir(path):
		shutil.rmtree(path)

# can't be bothered to implement logging (i already did most of the work, i don't know an alternative to Start-Transcript)
'''def Start_Logging {

    logsPath = "$env:temp\pc-flipper-windows-script-logs"
    if (-not (Test-Path $logsPath)) {
	os.mkdir(logsPath)
    }
    timestamp = datetime.today().strftime('%Y-%m-%d_%H:%M:%S')
    fileName = f"transcript_{timestamp}.log"
    Start-Transcript -Path f"{logsPath}\\fileName"
}'''

# how am i supposed to do this
'''function Start-FurmarkTest { # Approved Verb ("Initiates an operation")
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
}'''

def Install_GPUDrivers(): # Approved Verb ("Places a resource in a location, and optionally initializes it")
	def Install_NvidiaDrivers():
		# Write-Host "Nvidia GPU detected. Drivers downloading and installing..."
		# New-Item -ItemType Directory -Path "Nvidia-Drivers" | Out-Null
		# $nvidiaDrivers = "Nvidia-Drivers\setup.exe"
		# $downloadLink = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/PowerPCFan/Nvidia-GPU-Drivers/refs/heads/main/configs/link.txt").Trim()
		# Invoke-WebRequest -Uri $downloadLink -OutFile $nvidiaDrivers
		# if (Test-Path -Path "$nvidiaDrivers") {
		#     Start-Process $nvidiaDrivers -Wait
		# } else {
		#     Write-Host -ForegroundColor Red "Error: Nvidia driver installer not found at $nvidiaDrivers."
		# }
		print(f"{CYAN}I am currently working on a better solution for Nvidia drivers, but it is not production ready yet.\n Please download the latest drivers from the Nvidia website.{RESET}")

	def Install_AMDDrivers():
		print("AMD GPU detected. Drivers downloading and installing...")
		os.mkdir("AMD-Drivers")
		amdDrivers = "AMD-Drivers\\setup.exe"
		adrenalinDriverLink = requests.get("https://raw.githubusercontent.com/nunodxxd/AMD-Software-Adrenalin/refs/heads/main/configs/config.json")
		adrenalinDriverLink1 = adrenalinDriverLink["driver_link"]
		adrenalinDriverLink2 = adrenalinDriverLink1["stable"]
		driver = requests.get(adrenalinDriverLink, headers={'referer': "https://www.amd.com/en/support/download/drivers.html"})
		open(amdDrivers, wb).write(driver.content)
		if os.is_file(amdDrivers):
			os.system(amdDrivers)
		else:
			print(f"{RED}Error: AMD driver installer not found at {amdDrivers}.{RESET}")
			exit(1)
	def Install_IntelDrivers():
		print("Intel Arc GPU detected. Drivers downloading and installing...")
		os.mkdir("Intel-Arc-Drivers")
		intelDrivers = "Intel-Arc-Drivers\\setup.exe"
		downloadLink = requests.get("https://raw.githubusercontent.com/PowerPCFan/Intel-Arc-GPU-Drivers/refs/heads/main/configs/link.txt".rstrip())
		driver = requests.get(downloadLink)	
		open(intelDrivers, wb).write(driver.content)	
		if os.is_file(intelDrivers):
			os.system(intelDrivers)
		else:
			print(f"{RED}Error: Intel driver installer not found at {intelDrivers}.{RESET}")
			exit(1)


	# I had to comment out this whole part because
	# I don't know how to detect GPUs in Python so
	# the user will need to specify the GPU manually.

#    if (($gpu -like "*NVIDIA*") -or ($gpu -like "*GeForce*")) {
#	Install-NvidiaDrivers
#    } elseif (($gpu -like "*AMD*") -or ($gpu -like "*Radeon*")) {
#	Install-AMDDrivers
#    } elseif (($gpu -like "*Intel*") -and ($gpu -like "*Arc*")) {
#	Install-IntelDrivers
#    } else {
#	$anybox = New-Object AnyBox.AnyBox
#		
#	$anybox.Message = 'Error detecting. What brand is your GPU?'
	response = input("GPU auto-detection is not working at the moment. What brand is your GPU?\n Options are: AMD, nVidia, Intel and Other (case-sensitive).\n")

	# Act on responses.
	if response == 'AMD':
	    Install_AMDDrivers()
	elif response == 'nVidia':
	    Install_NvidiaDrivers()
	elif response == 'Intel':
	    Install_IntelDrivers()
	elif response == 'Other':
	    print("You selected Other, which means your GPU is currently unsupported. Please download drivers manually.")
	    exit(1)

while True:
	question = input("What would you like to do?\n(Options: Run Furmark tests (not working right now), triggered by responding with 'furmark'; install GPU drivers, which can be triggered with 'GPU'; or 'exit' to exit. (case-sensitive)\n")
	if question == "GPU":
		Install_GPUDrivers()
	elif question == "furmark":
		print("Furmark tests are currently incomplete and do not work.")
	elif question == "exit":
		print("Quitting...")
		exit(1)
	else:
		print("Invalid input! Reasking question.\n")


