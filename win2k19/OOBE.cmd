cscript //B C:\Windows\System32\slmgr.vbs /ipk WMDGN-G9PQG-XVVXX-R3X43-63DFG
cscript //B C:\Windows\System32\slmgr.vbs /skms kms.catqu.com
cscript //B C:\Windows\System32\slmgr.vbs /ato

REM REG ADD "HKLM\System\CurrentControlSet\Control\Network\NewNetworkWindowOff"
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /t REG_DWORD /d 0 /f
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f

REM hide Computer icon on the desktop
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f

REM hide Control Panel icon on the desktop
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0 /f

REM hide User's Files icon on the desktop
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f

REM hide Network icon on the desktop
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f

REM hide recycle bin from desktop
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 0 /f

powercfg /setactive "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
powercfg -change -monitor-timeout-ac 0
powercfg -change -monitor-timeout-dc 0
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -hibernate OFF

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
REM ref: https://github.com/operepo/sysprep_scripts/blob/master/Step1.cmd
rem disable win store auto updates which can break sysprep
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
reg add "HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ¡°PreInstalledAppsEnabled" /t REG_DWORD /d 0x00000000 /f
reg add "HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ¡°OemPreInstalledAppsEnabled" /t REG_DWORD /d 0x00000000 /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\ /v HibernateFileSizePercent /t REG_DWORD /d 0 /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Power\ /v HibernateEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DisplayVersion /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DisplayVersion /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system /v shutdownWithoutLogon /t REG_DWORD /d  1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f
regedit /s A:\Add_Open_command_window_here_as_administrator.reg

NetSh Advfirewall set allprofiles state off
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset set InitialSize=8192,MaximumSize=8192

dism /online /Enable-Feature /FeatureName:ClientForNFS-Infrastructure /FeatureName:NFS-Administration /NoRestart /FeatureName:ServicesForNFS-ServerAndClient
dism /Online /Enable-Feature /FeatureName:"TelnetClient" /NoRestart

powershell -NoProfile -ExecutionPolicy Bypass -Command "& 'A:\ConfigureRemotingForAnsible.ps1'"
wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/ImDiskTk-x64.exe -O c:\ansible\ImDiskTk-x64.exe
C:\ansible\ImDiskTk-x64.exe /fullsilent
wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/7z1900-x64.msi -O C:\ansible\7z1900-x64.msi
msiexec /I C:\ansible\7z1900-x64.msi /quiet

wget --no-check-certificate  https://github.com/OpenSCAP/openscap/releases/download/1.3.1/OpenSCAP-1.3.1-win32.msi -O C:\ansible\OpenSCAP-1.3.1-win32.msi
cmd.exe /c msiexec /I C:\ansible\OpenSCAP-1.3.1-win32.msi /quiet

wget --no-check-certificate  https://github.com/cloudbase/cloudbase-init/releases/download/0.9.11/CloudbaseInitSetup_0_9_11_x64.msi -O C:\ansible\CloudbaseInitSetup_0_9_11_x64.msi
cmd.exe /c msiexec /i C:\ansible\CloudbaseInitSetup_0_9_11_x64.msi /qn /l*v C:\ansible\CloudbaseInitSetup_0_9_11_x64.log
wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/cloudbase-init.conf -O "c:\Program Files\Cloudbase Solutions\Cloudbase-init\conf\cloudbase-init.conf"
wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/cloudbase-init-unattend.conf -O "c:\Program Files\Cloudbase Solutions\Cloudbase-init\conf\cloudbase-init-unattend.conf"

wget --no-check-certificate -P C:\ansible https://ecs-instance-driver.obs.myhwclouds.com/vmtools-WIN2016-x64.zip
7za x -oC:\ansible\ C:\ansible\vmtools-WIN2016-x64.zip
C:\ansible\vmtools-WIN2016-x64.exe /quiet /norestart /passive

wget --no-check-certificate  https://github.com/Huawei/CloudResetPwdAgent/archive/master.zip -O C:\ansible\CloudResetPwdAgent.zip
7za x -oC:\ansible C:\ansible\CloudResetPwdAgent.zip
cd C:\ansible\CloudResetPwdAgent\CloudResetPwdAgent.Windows && START /MIN CMD.EXE /C setup.bat

REM install zabbix agent
wget --no-check-certificate -P C:\ansible https://www.zabbix.com/downloads/3.4.6/zabbix_agents_3.4.6.win.zip
7za x -o"C:\Program files\Zabbix Agent" C:\ansible\zabbix_agents_3.4.6.win.zip
"C:\Program files\Zabbix Agent\bin\win64\zabbix_agentd.exe" -i -c "C:\Program files\Zabbix Agent\conf\zabbix_agentd.win.conf"
"C:\Program files\Zabbix Agent\bin\win64\zabbix_agentd.exe" -s

REM wget --no-check-certificate -P C:\ansible http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc/file/41459/25/PSWindowsUpdate.zip

REM wget --no-check-certificate -P C:\ansible http://slproweb.com/download/Win32OpenSSL_Light-1_0_1h.exe
REM C:\ansible Win32OpenSSL_Light-1_0_1h.exe /silent /verysilent /sp- /suppressmsgboxes
REM wget --no-check-certificate -P C:\ansible http://download.tuxfamily.org/notepadplus/6.4.5/npp.6.4.5.Installer.exe
REM C:\ansible npp.6.4.5.Installer.exe /S

REM wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/windows10.0-kb4533002-x64.msu -O C:\ansible\windows10.0-kb4533002-x64.msu
REM wusa C:\ansible\windows10.0-kb4533002-x64.msu /quiet /norestart

REM run choco installer
wget --no-check-certificate -P C:\ansible https://chocolatey.org/install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\ansible\install.ps1'"
C:\ProgramData\chocolatey\bin\refreshenv.cmd
C:\ProgramData\chocolatey\choco.exe feature enable -n=allowGlobalConfirmation
C:\ProgramData\chocolatey\choco.exe install notepadplusplus googlechrome openssh putty
#choco install saltminion
#choco install freerdp

REM wget --no-check-certificate -P C:\ansible http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe
REM wget --no-check-certificate -P C:\ansible http://the.earth.li/~sgtatham/putty/latest/x86/pscp.exe

REM Dism++
wget --no-check-certificate  https://raw.githubusercontent.com/xtha/Windows/master/Dism++10.1.1000.100_2d2bf466baca088c4b35248f5a7316f4e00cac0b.zip -O C:\ansible\Dism++10.1.1000.100.zip
7za x -oc:\ansible\Dism++10.1.1000.100 C:\ansible\Dism++10.1.1000.100.zip
cmd.exe /c control system
cmd.exe /c sysdm.cpl
cmd.exe /c ncpa.cpl
cmd.exe /c lusrmgr.msc
cmd.exe /c timedate.cpl
cmd.exe /c msinfo32
