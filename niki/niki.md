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
rustscan 192.168.1.0/24 -t 500 -b 1500 -- -A

TCPports=$(sudo nmap -Pn -n -p- -T4 $TARGET -oA nmap/TCPports -v --disable-arp-ping | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') | sudo chown -R $USER:$(id -gn) nmap && echo $TCPports

# Faster
TCPports=$(sudo nmap -Pn -p- -T4 $TARGET -oA nmap/TCPports -v --disable-arp-ping | egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') | sudo chown -R $USER:$(id -gn) nmap && echo $TCPports

TCPports=$(rustscan -a $TARGET -r 1-65535 > nmap/TCPports.txt | egrep  "^Open.*$" | sed -e 's/\x1b\[[0-9;]*m//g' | sed -e 's/^Open.*://g;s/\r$//g;s/\[m//g' | tr "\n" "," | sed 's/,$//' ) && echo $TCPports

UDPports=$(sudo nmap --min-rate 5000 -T5 -Pn -sU $TARGET -oA nmap/UDPports.txt -v --disable-arp-ping| egrep "^[0-9]{2,5}" | sed -E "s#/.*##g" | tr "\n" "," | sed 's/.$//') | sudo chown -R $USER:$(id -gn) nmap && echo $UDPports

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

[] WEB
    [] folders 
    [] files -x txt,php,html
    [] DNS + subdomain
    [] Banner (curl -IL | whatweb)
    [] Certificate
    [] Source code
    [] SQL injection
[] Mount points
[] SMB
[] DNS
[] ftp
[] run as admin
[] cron jobs

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



curl 'http://18.195.214.137/' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: connect.sid=s%3AQb_r443oXweXGULkzMWwRqX1OvkXLIWI.ba9XS3KAiz%2FlAyAmt%2BvlfjN%2FO%2B%2FwFuLb3uAjCcsztNs' \
  -H 'Origin: http://18.195.214.137' \
  -H 'Referer: http://18.195.214.137/' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' \
  --data-raw 'username=admin&password=root' \
  --insecure ;
curl 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css' \
  -H 'sec-ch-ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"' \
  -H 'Referer: http://18.195.214.137/' \
  -H 'Origin: http://18.195.214.137' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua-platform: "Linux"' ;
curl 'https://cyber-security-cluster.eu/wp-content/uploads/2022/02/Cloudyrion-GmbH.png' \
  -H 'sec-ch-ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"' \
  -H 'Referer: http://18.195.214.137/' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' \
  -H 'sec-ch-ua-platform: "Linux"'

  --data-raw 'username=admin&password=root'