@echo off

REM Much of this pulled from https://forums.fogproject.org/topic/9877/windows-10-pro-oem-sysprep-imaging/2

reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f

rem remove ansible user profile
echo removing ansible user profile...
wmic /node:localhost path win32_UserProfile where LocalPath="c:\\users\\ansible" Delete 2>>C:\ansible\wmic.err

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
chkdsk /f c:
rem use chkntfs to schedule the check on reboot
chkntfs /C c:

echo Time to reboot. Run PatchCleaner before reboot to trim installer folder
REM SHUTDOWN
REM Hold SHIFT when selecting shutdown to not do fastboot.
rem shutdown /r /t 0
wget --no-certificate-check -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/Unattend.xml
wget --no-certificate-check -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/UpdateAndSysprep.ps1
REM cd "c:/gProgram Files\Cloudbase Solutions\Cloudbase-init\conf" && c:\windows\system32\sysprep\sysprep.exe /generalize /oobe /unattend:Unattend.xml /shutdown
