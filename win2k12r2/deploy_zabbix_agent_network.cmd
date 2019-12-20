@echo off
echo Starting Zabbix agent installation and configuration script

:CheckOS
echo Detecting OS processor type
IF EXIST "%PROGRAMFILES(X86)%" (GOTO 64BIT) ELSE (GOTO 32BIT)

:64BIT
echo 64-bit system detected
net use y: "\\HOSTNAME\Zabbix$\64bit_Agent_208"
xcopy y:\ "C:\Program Files\Zabbix\" /y
net use /delete /y y:
GOTO CONFIG_AGENT

:32BIT
echo 32-bit system detected
net use y: "\\HOSTNAME\Zabbix$\32bit_Agent_208"
xcopy y:\ "C:\Program Files\Zabbix\" /y
net use /delete /y y:
GOTO CONFIG_AGENT

:CONFIG_AGENT
echo Configuring Zabbix agent
echo Server=ZABBIXSERVERIP > "C:\Program Files\Zabbix\zabbix_agentd.conf"
echo Hostname=%COMPUTERNAME% >> "C:\Program Files\Zabbix\zabbix_agentd.conf"
echo StartAgents=10 >> "C:\Program Files\Zabbix\zabbix_agentd.conf"
echo ServerActive=ZABBIXSERVERIP >> "C:\Program Files\Zabbix\zabbix_agentd.conf"
echo LogFile=C:\Program Files\Zabbix\zabbix_agentd.log >> "C:\Program Files\Zabbix\zabbix_agentd.conf"
echo Timeout=5 >> "C:\Program Files\Zabbix\zabbix_agentd.conf"
GOTO INSTALL_AGENT

:INSTALL_AGENT
echo Installing Zabbix agent service
cd c:\Program Files\Zabbix
zabbix_agentd.exe --config "C:\Program Files\Zabbix\zabbix_agentd.conf" --install
GOTO START_AGENT

:START_AGENT
echo Starting Zabbix agent
net start "Zabbix agent"

echo Starting Zabbix agent installation and configuration script - FINISHED
pause
