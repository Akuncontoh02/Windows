REM ignore error continue: cmd.exe /C
tzutil.exe /s "China Standard Time"
w32tm.exe /config /syncfromflags:manual /manualpeerlist:"ntp1.aliyun.com ntp2.aliyun.com"
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset set InitialSize=8192,MaximumSize=8192
powercfg /H off

mkdir C:\ansible
echo %date% %time%: Windows 10 Config Starting>>C:\ansible\Windows-Config.log

powershell -command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
dism /online /Enable-Feature /FeatureName:ServicesForNFS-ClientOnly /FeatureName:ClientForNFS-Infrastructure /FeatureName:NFS-Administration /NoRestart
dism /Online /Enable-Feature /FeatureName:"TelnetClient" /NoRestart
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset set InitialSize=8192,MaximumSize=8192
regedit /s A:\Add_Open_command_window_here_as_administrator.reg

echo %date% %time%: copy 7za.exe Starting>>C:\ansible\Windows-Config.log
copy A:\7za.exe C:\Windows\System32\7za.exe

echo %date% %time%: copy wget.exe Starting>>C:\ansible\Windows-Config.log
powershell Invoke-WebRequest -Uri http://10.144.152.235/nfs/isos/sysprep/wget.exe -OutFile  c:\Windows\System32\wget.exe

copy A:\ConfigureRemotingForAnsible.ps1 -O c:\ansible\ConfigureRemotingForAnsible.ps1
powershell C:\ansible\ConfigureRemotingForAnsible.ps1

echo %date% %time%: copy imdisk Starting>>C:\ansible\Windows-Config.log
wget http://10.144.152.235/nfs/packages/windows/ImDiskTk-x64.exe -O c:\ansible\ImDiskTk-x64.exe
C:\ansible\ImDiskTk-x64.exe /fullsilent

echo %date% %time%: Set Power Mode Starting>>C:\ansible\Windows-Config.log
powercfg /setactive "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
powercfg -change -monitor-timeout-ac 0
powercfg -change -monitor-timeout-dc 0
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -hibernate OFF

echo %date% %time%: Set RDP Starting>>C:\ansible\Windows-Config.log
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
rem ref: https://github.com/operepo/sysprep_scripts/blob/master/Step1.cmd

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

echo %date% %time%: Set Firewall Starting>>C:\ansible\Windows-Config.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DisplayVersion /t REG_DWORD /d 1 /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system /v shutdownWithoutLogon /t REG_DWORD /d  1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f

net user Administrator /active:yes
net user Administrator /logonpasswordchg:no
wmic useraccount where "name='Administrator'" set PasswordExpires=FALSE

NetSh Advfirewall set allprofiles state off
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset set InitialSize=8192,MaximumSize=8192

wget http://10.144.152.235/nfs/packages/windows/7z1900-x64.msi -O C:\ansible\7z1900-x64.msi
msiexec /I C:\ansible\7z1900-x64.msi /quiet

wget http://10.144.152.235/nfs/packages/windows/OpenSCAP-1.3.1-win32.msi -O C:\ansible\OpenSCAP-1.3.1-win32.msi
msiexec /I C:\ansible\OpenSCAP-1.3.1-win32.msi /quiet

wget http://10.144.152.235/nfs/isos/cloudbase/CloudbaseInitSetup_0_9_11_x64.msi -O C:\ansible\CloudbaseInitSetup_0_9_11_x64.msi
msiexec /i C:\ansible\CloudbaseInitSetup_0_9_11_x64.msi /qn /l*v C:\ansible\CloudbaseInitSetup_0_9_11_x64.log
wget http://10.144.152.235/nfs/isos/sysprep/cloudbase-init.conf -O "c:\Program Files\Cloudbase Solutions\Cloudbase-init\conf\cloudbase-init.conf"
wget http://10.144.152.235/nfs/isos/sysprep/cloudbase-init-unattend.conf -O "c:\Program Files\Cloudbase Solutions\Cloudbase-init\conf\cloudbase-init-unattend.conf"

rem install vmtools
wget http://10.144.152.235/nfs/isos/vmtools/vmtools-windows.iso -O c:\ansible\vmtools-windows.iso
ImDisk.exe -D -m x:
ImDisk.exe -a -f "c:\ansible\vmtools-windows.iso" -m x:
x:\vmtools\vmtools-WIN2012R2-x64.exe /quiet /norestart /passive
ImDisk.exe -D -m x:

wget http://10.144.152.235/nfs/packages/CloudResetPwdAgent.zip -O C:\ansible\CloudResetPwdAgent.zip
7za x -oC:\ansible C:\ansible\CloudResetPwdAgent.zip
cd C:\ansible\CloudResetPwdAgent\CloudResetPwdAgent.Windows && START /MIN CMD.EXE /C setup.bat

REM install zabbix agent
wget -P C:\ansible http://10.144.152.235/nfs/packages/windows/zabbix_agents_3.4.6.win.zip
7za x -o"C:\Program files\Zabbix Agent" C:\ansible\zabbix_agents_3.4.6.win.zip
"C:\Program files\Zabbix Agent\bin\win64\zabbix_agentd.exe" -i -c "C:\Program files\Zabbix Agent\conf\zabbix_agentd.win.conf"
"C:\Program files\Zabbix Agent\bin\win64\zabbix_agentd.exe" -s

remwget -P C:\ansible http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc/file/41459/25/PSWindowsUpdate.zip

remwget -P C:\ansible http://slproweb.com/download/Win32OpenSSL_Light-1_0_1h.exe
remC:\ansible Win32OpenSSL_Light-1_0_1h.exe /silent /verysilent /sp- /suppressmsgboxes

remwget -P C:\ansible http://download.tuxfamily.org/notepadplus/6.4.5/npp.6.4.5.Installer.exe
remC:\ansible npp.6.4.5.Installer.exe /S

remwget http://10.144.152.235/nfs/isos/sysprep/windows10.0-kb4533002-x64.msu -O C:\ansible\windows10.0-kb4533002-x64.msu
remwusa C:\ansible\windows10.0-kb4533002-x64.msu /quiet /norestart

remrun choco installer
wget -p C:\ansible https://chocolatey.org/install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\ansible\install.ps1'"
choco feature enable -n=allowGlobalConfirmation
choco install notepadplusplus googlechrome openssh putty
#choco install saltminion
#choco install freerdp

wget -P C:\ansible http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe
wget -P C:\ansible http://the.earth.li/~sgtatham/putty/latest/x86/pscp.exe

remDism++
remwget http://10.144.152.235/nfs/isos/sysprep/Dism++10.1.1000.100_2d2bf466baca088c4b35248f5a7316f4e00cac0b.zip -O C:\ansible\Dism++10.1.1000.100.zip
rem7za x -oc:\ansible C:\ansible\Dism++10.1.1000.100.zip
cscript C:\Windows\System32\slmgr.vbs /ipk W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9
cscript C:\Windows\System32\slmgr.vbs /skms kms.catqu.com
cscript C:\Windows\System32\slmgr.vbs /ato
