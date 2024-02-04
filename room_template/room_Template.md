## Basic commands

```
# Extract VPN IP - $attack
attack=$(ip a show dev tun1 | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# Config TMUX
tmux setenv TARGET $TARGET && export TARGET=$TARGET
tmux setenv DOMAIN $DOMAIN && export DOMAIN=$DOMAIN
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
sudo sed -i "/$TARGET      $DOMAIN/d" /etc/hosts
echo "$TARGET      $DOMAIN" | sudo tee -a /etc/hosts
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


<!DOCTYPE html><html lang=""><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/favicon.ico"><title>horizontall</title><link href="/css/app.0f40a091.css" rel="preload" as="style"><link href="/css/chunk-vendors.55204a1e.css" rel="preload" as="style"><link href="/js/app.c68eb462.js" rel="preload" as="script"><link href="/js/chunk-vendors.0e02b89e.js" rel="preload" as="script"><link href="/css/chunk-vendors.55204a1e.css" rel="stylesheet"><link href="/css/app.0f40a091.css" rel="stylesheet"></head><body><noscript><strong>We're sorry but horizontall doesn't work properly without JavaScript enabled. Please enable it to continue.</strong></noscript><div id="app"></div><script src="/js/chunk-vendors.0e02b89e.js"></script><script src="/js/app.c68eb462.js"></script></body></html>

┌──(kalilearn㉿kalilearn)-[~/git/hacklab/hori/nmap]
└─$













