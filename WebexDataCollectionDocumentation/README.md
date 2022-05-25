### Tools we used

[VirtualBox](https://www.virtualbox.org): creating virtual environment instance using VirtualBox and Windows10 iso file.
[Windows10 developmenet environment](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/): we used windows 10 development environment for testing, however, Microsoft now changes it to Windows 11. Basically, any Windows 10 image should work. 
[API Monitor](http://www.rohitab.com/apimonitor): including 64-bit and 32-bit versions, for monitoring usages (including input and output) of API calls when attached to certain process
[x64dbg](https://x64dbg.com/): assitant tools
[Webex 41.12.3.11](https://community.chocolatey.org/packages/webex-meetings/41.12.3.11): currently Cisco Webex already fixed the bug in their [January 2022 release](https://blog.webex.com/uncategorized/webex-audio-mute/). You can find the previous version of Webex download link from a third party [here](https://community.chocolatey.org/packages/webex-meetings/41.12.3.11).


### Filter

As processes may call tremendous amount of libraries and APIs, we selected certain filters as `Filter_for_APIMonitor`. Please install API monitor and import this filter file.


### Running 

- First, install virtualbox, download Windows 10 iso, and create a Windows 10 virtual machine instance.
- Install Webex, APIMonitor, and x64dbg inside your virtual machine instance.
- Run APIMonitor (64-bit version) in administrator mode, start Webex and attach to process.
