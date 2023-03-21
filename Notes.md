# Basic Steps
## Automatic web enum
- dirb | dirsearch
- linpeas
- wpsscan -U user -P password

## Basic network
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
- nmap Scrips
  - locate -r nse$ | grep mysql = nmap script

## Linux
- sudo -l
- find / -perm -u=s -type f 2>/dev/null
- find / -type f -perm -04000 -ls 2>/dev/null 
- psexec.py
  
- Shell stabilize
  -  python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - export TERM=xterm

## Payloads
- msfvenom - reverse -f aspx -o app.aspx

## Windows
- /priv
- smb read/write
- browser cache
- scheduled task
- UAC
- 

