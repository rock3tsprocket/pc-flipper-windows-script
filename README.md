# pc-flipper-windows-script
I made this script to make it easier for PC flippers to prepare Windows on builds being prepared for sale.

# What it does:
- Detects graphics card and downloads the appropriate drivers
- Detects motherboard and searches for chipset drivers
- Installs Firefox
- Installs FurMark and runs a system stress test
- Opens Sysprep
- **More features coming soon! (Scroll down to "Upcoming Updates" for info)**

# Execution
Recommended: You can run the script using the quick run command `irm bit.ly/pcflipperwindowsscript | iex`. \
Alternatively you can download the "run.ps1" file and open it in PowerShell. **Not recommended for novice users**

# Issues
If you have any issues, please create an "issue" on the [Issues page](https://github.com/PowerPCFan/pc-flipper-windows-script/issues). 

# Upcoming Updates
Within the next week:\
More app installation options, more automatic stress testing, and yes/no prompts for every app and driver installation instead of "Press enter to continue"

# Branches
- Main - **you should always use this branch, since it will always be working**
- Testing-Unstable - **DO NOT USE THIS.** It is just for me to test things and new releases, it is most likely very broken, behind on updates, and could possibly break your system. I was too lazy to create a private repo to test stuff on, that's why this exists
- Legacy - I would not recommend using this, it's basically just a saved copy of an ancient version that lacks bug fixes, updates, and support

# Contributing
If you want to contribute, please fork the repo, clone it, edit/modify it to your liking, and make a [pull request](https://github.com/PowerPCFan/pc-flipper-windows-script/pulls) where I can review the code and choose to add it to the main script or not. Your contributions are greatly appreciated.
