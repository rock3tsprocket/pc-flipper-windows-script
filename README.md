# pc-flipper-windows-script
I made this script to make it easier for PC flippers to prepare Windows on builds being prepared for sale.

# What it does:
- Detects graphics card and downloads the appropriate drivers
- Detects motherboard and searches for chipset drivers
- Installs Firefox
- Installs FurMark and runs a system stress test
- Opens Sysprep

# Execution
You can run the script using the command `irm bit.ly/pcflipperwindowsscript | iex`. 

# Issues
If you have any issues, please make an issue on the [Issues page](https://github.com/PowerPCFan/pc-flipper-windows-script/issues). 

# Upcoming Updates
Within the next week - more apps, more stress testing, and "yes/no confirmations" for app and driver installations

# Branches
Main - **you should always use this branch, since it will always be working**
Testing-Unstable - **DO NOT USE THIS.** It is just for me to test things and new releases, it is most likely very broken, behind on updates, and could possibly break your system. I was too lazy to create a private repo to test stuff on, that's why this exists
Legacy - I would not recommend using this, it's basically just a saved copy of an ancient version that lacks bug fixes, updates, and support

# Contributing
If you want to contribute please follow the normal procedure for doing this - fork the repo, clone it, edit/modify it to your liking, and make a [pull request](https://github.com/PowerPCFan/pc-flipper-windows-script/pulls) where I can review the code and choose to add it to the main script or not. 
