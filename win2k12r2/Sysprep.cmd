@echo off

REM Much of this pulled from https://forums.fogproject.org/topic/9877/windows-10-pro-oem-sysprep-imaging/2

rem disable win store auto updates which can break sysprep
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f

wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset set InitialSize=8192,MaximumSize=8192

wget --no-check-certificate -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/Unattend.xml
wget --no-check-certificate -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/UpdateAndSysprep.ps1
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f

rem remove ansible user profile
echo removing ansible user profile...
wmic /node:localhost path win32_UserProfile where LocalPath="c:\\users\\ansible" Delete 2>>C:\ansible\wmic.err

echo uninstalling apps we don't want...

SET keep_apps="appconnector", "appinstaller", "alarms", "communicationsapps", "feedback", "getstarted", "skypeapp", "zunemusic", "zune", "maps", "messaging", "wallet", "connectivitystore", "bing", "zunevideo", "onenote", "oneconnect", "people", "commsphone", "windowsphone", "phone", "sticky", "sway", "xboxcomp", "calculator", "solitaire", "mspaint", "photos", "3d", "soundrecorder", "holographic", "windowsstore"

SET uninstall_apps="3dbuilder", "alarms", "camera", "officehub", "bingfinance", "bingnews", "bingsports", "bingweather"

(FOR %%A IN (%uninstall_apps%) DO (
    echo Uninstalling %%~A
    
    powershell -Command "get-appxpackage *%%~A* | remove-appxpackage"
    powershell -Command "Get-appxprovisionedpackage -online | where-object {$_.packagename -like '*%%~A*' } | Remove-AppxProvisionedPackage -online"
    
))

::powershell Get-AppxPackage -AllUsers *store* | Remove-AppxPackage

rem disable windows installing these apps
reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

echo Disable fast boot...
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f

rem echo Compact OS files...
rem compact /CompactOS:always

echo Clean update files - shrink winsxs...
Dism.exe /online /Cleanup-Image /StartComponentCleanup
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Dism.exe /online /Cleanup-Image /SPSuperseded

echo "Clear software distribution..."
net stop wuauserv
net stop bits
del /F /S /Q c:\windows\SoftwareDistribution\*
net start wuauserv
net start bits

rem sdelete -z c:

echo Enabling Chkdsk on reboot...
rem chkdsk /f c:
rem use chkntfs to schedule the check on reboot
rem chkntfs /C c:

echo Time to reboot. Run PatchCleaner before reboot to trim installer folder
REM SHUTDOWN
REM Hold SHIFT when selecting shutdown to not do fastboot.
rem shutdown /r /t 0
