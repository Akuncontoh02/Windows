@echo off

REM  ignore error continue: cmd.exe /C
tzutil.exe /s "China Standard Time"
w32tm.exe /config /syncfromflags:manual /manualpeerlist:"ntp1.aliyun.com ntp2.aliyun.com"

mkdir C:\ansible
powershell -command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
copy A:\7za.exe C:\Windows\System32\7za.exe
REM powershell Invoke-WebRequest -Uri http://10.144.152.235/nfs/isos/sysprep/wget.exe -OutFile  c:\Windows\System32\wget.exe
powershell -Command "((New-Object System.Net.Webclient).DownloadFile('http://10.144.152.235/nfs/isos/sysprep/wget.exe', 'C:\Windows\System32\wget.exe'))"
cmd.exe /c reg add "HKLM\System\CurrentControlSet\Control\Network\NewNetworkWindowOff"

net user Administrator /active:yes
net user Administrator /logonpasswordchg:no
wmic useraccount where "name='Administrator'" set PasswordExpires=FALSE
wmic useraccount where "name='{{ CreateUser }}'" set PasswordExpires=FALSE
