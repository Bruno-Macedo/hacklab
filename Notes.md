# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg)
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
- lscpu
- lsblk -a
- lsusb -v
- lspci -t -v
- fidlist -l
  
- Shell stabilize
  -  python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - export TERM=xterm

## Payloads
- msfvenom - reverse -f aspx -o app.aspx

## Windows
- /priv
- systeminfo
- smb read/write
- browser cache
- scheduled task
- UAC
- Check loggings
  - sysmon enable / powershell loggging enabled ?
- echo %VARIABLE%

