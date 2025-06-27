import os
import shutil
import sys
import requests

mainFolderPath = os.getenv("TEMP")+"\\pc-flipper-script"
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

# Downloads main script
r = requests.get("https://raw.githubusercontent.com/PowerPCFan/pc-flipper-windows-script/refs/heads/main/pc-flip-preparation-script.ps1")
with open(".\\bin\\pc-flip-preparation-script.ps1", "w") as ps1:
	ps1.write(r.text)
