wget -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/Unattend.xml
wget -P C:\ansible https://raw.github.com/cloudbase/unattended-setup-scripts/master/UpdateAndSysprep.ps1
::C:\ansible npp.6.4.5.Installer.exe /S
::Salt-Minion-2019.2.2-Py3-AMD64-Setup.exe /S /master=10.144.152.235
::netsh winhttp set proxy proxy-server="http=10.144.152.107:3142;https=10.144.152.107:3142" bypass-list="*.windowsupdate.com;*.microsoft.com"

::cd "c:/gProgram Files\Cloudbase Solutions\Cloudbase-init\conf" && c:\windows\system32\sysprep\sysprep.exe /generalize /oobe /unattend:Unattend.xml /shutdown
