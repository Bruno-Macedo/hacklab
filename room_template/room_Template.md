## Basic commands

- Disable iptable: 
```
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

reverse:
/DROP

sudo systemctl restart networking.service
```

```
# Extract VPN IP - $attack
attack=$(ip a show dev tun1 | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

# Config TMUX
tmux setenv TARGET $TARGET && export TARGET=$TARGET
tmux setenv DOMAIN $DOMAIN && export DOMAIN=$DOMAIN
tmux setenv attack $attack && export attack=$attack

# Scan open ports
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:2.1.1'

TCPports=$(sudo nmap -Pn -p- -T4 $TARGET -oA nmap/TCPports -v | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $TCPports
nmap  -p$TCPports

TCPports=$(rustscan -a $TARGET -r 1-65535 > nmap/TCPports.txt | egrep  "^Open.*$" | sed -e 's/\x1b\[[0-9;]*m//g' | sed -e 's/^Open.*://g;s/\r$//g;s/\[m//g' | tr "\n" "," | sed 's/,$//' ) && echo $TCPports

UDPports=$(sudo nmap -T5 -Pn -sU $TARGET -oA nmap/UDPports.txt -v | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') && echo $UDPports

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

