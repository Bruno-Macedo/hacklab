# LPIC 102 - Cheat Sheet

## 105.2 Bash Scrippting
- #!/bin/bash = shebang,hashpling,hashbang
  - scripts are executed in bash process (sub-shell)
- Running
  - same path: bash script.sh
  - exec perm: chmod u+x script.sh + ./script.sh
  - diff loct: /path/to/script.sh
  - set $PATH: script on $PATH
  - sourcing:  source script.sh | . script.sh = same shell
  - Exec cmd:ex  exec ./script
- Build commands
  - $()
  - ``
  - xargs
  - cmd=Substitution

- Chaining = both executed, no matter error
  - ;  = both executed
  - && = both must be true
  - || = either other true

- Success
  - ?!
    - 0  = successfull
    - !0 =  failed = 0-255

- Flow control
  - if
```
if CONDITION
    then DO this
    else DO that
    elsif do this
fi
```
  - test: file exist/directory/empty/etc
    - test = [ -f /etc/passwd ]
    - echo $? = save results in the exit
    - 0 = true
    - 1 = false
    - 2 = error
  - Mail
    - echo "message" | mail -s "Subject" TARGET
  
  - FOR-Loop
    - seq START STOP | seq START path STOp

```
for var in a b c d e f g
do
    echo "The letter is: " $var
    sleep 1
done


for var in $(seq 1 100)
do
    echo "The letter is: " $var
    sleep 1
done
```

  - WHILE-Loop
    - always, until false
```
while [ $test ]
do
    action
done
```
  - UNTIL-Loop = if true not run
```
until COND
do
    runs while it is false
done
```

- User input/file
  - read
    - -p = prompt
    - -s = hide
  - cat file | while read LineFile do dasdada done
  - Parameters
    - $0 = name of the script
    - $1...n
    - $*.$@ = all arguments
    - $# = total of arguments
    - $! = last pid
    - $$ = current shell
    - $? = exit status
  - Arrays: 
    - declare -a SIZES
    - SIZES=(a,b,c)
  - echo
  - printf = more controlle to display

## 105.1 Shell Enviromnment
- bash
  - -l login
  - -i interactive
  - --noprofile 
  - --norc = no profile (system-wide and user)
  - --rcfile = use custom file
  - interactive login: -bash,-su
  - non-login: bash, zsh
- SKEL
  - template 
- global:
  - /etc/profile
  - /etc/profile.d
  - /etc/bashrc (ubuntu)
  - /etc/bash.bashrc (ubuntu)
- local: 
  - ~/.bash_profile
  - ~/.bash_login
  - ~/.profile
  - ~/.bashrc
  - ~/.bash_logout
- Priority: only one is runed
  - local > global
  - ~/.bash_profile, ~/.bash_login, ~/.profile
- What to do?
  - set env variables + alias + change appearance

- Alias: modifed command
  - alias -p
  - unalias CMD
  - Where set
  - alias name="script to be run"

- Functions = group of commands that runs several time
```
function func_name {
    commands    
}

func_name () {
    commands
}
```

- Env/user variables
  - set,env,printev = only env variable
  - unset variable | better change than unset
  - export PATH=$PATH:/path/to/my/target = make all available
  - set
    - echo $- = how {} works
    - set +a = turn off flag
    - set -a = turn on flag
      - -u = error/blank for non existent varaibles

## 107.1 Users and Groups
- DAC: Discretionary Access COntrol
- MAC: Mandatory Access Control
- DAC
  - Owner + Group + World
  - --- --- ---
  - getent = entries of adm db
    - /etc/nsswitch.conf = list files for getet
    - passwd username
  - groups
  - Primary group in /etc/passwd
  
- useradd | adduser = create user
  - -D = files used to create user (default)
  - -d = home directory
  - -e YYYY-MM-DD = expire
  - -f 1 = secure account, after this amount of day the account is disabled
  - /etc/passwd = account info
    - username:X password in shadow:ID:group ID:Comment:
  - /etc/shadow = password information
    - userame:password(hash):last changed:minimum days to change:days until change:warning:account deactaive:exp date
    - !! or ! = no password
    - ! or * = cannot log in
    - ! = account locked
  - /etc/group  = group information
  - /etc/gshadow = password group
  - 
- usermod: modify account
  - -c comment "blabla" username
- userdel: delete user
  - -r = also file
- groupadd (not remove from primary)
  - -g 
- references
  - /etc/default/useradd = , when shell, location of $HOME
  - /etc/login.defs = $HOME yes or no, password change, user id, group id
  - /etc/skel (skeleton) files are copied to $HOME

- passwords
  - passwd = my own change
  - sudo passwd username
    - -d = delete
    - -e = force change
  - -S = status
    - -1 = inactive disabled
    - 99999 = not change nedded
  - -l = lock account
  - -u = enable
- chage
  - -l aging info

- Groups
  - current group
  - primary: etc/passwd
  - newgrp = change group
  - /etc/group
    - name:password(X):ID:member
  - groupadd Name_Group
    - usermod -aG Name_Group New_user
    - groupmod -n NewName OldName
    - groupdel NameGroup
  - If you dont belong to group: u need password
    - gpasswd: better to add user to group
    - 

## Jobs 107.2
- at
  - now (when), HH:MM, noon,midnight,teatime(4:00 PM)
    - June 24, MMDDYY, offset: today + 3 hours/day/months,  
  - ctr+d
  - location: sent mail message
  - -l = list
  - -d = delete
  - -c = print command of job id
  - -f = read job from file
  - -m = mail
  - -q = queue
- atq = see jobs
- atrm ID = remove jobs
- /etc/at.allow = not default
  - users allowed to use
- /etc/at.deny
  - deny at

- crontab: backgroun
  - -e =create
  - -l = list
  - -r = remove
  - Minute Hour Day Month Day(Monday-Sunday) Command
  -   \-    \-  \-   \-         \-   
  - \* = every  
  - 15,45 = multiple time
  - 0 8-17/2 * * *  = every two hours between 8 and 17

- Schedule - System Cronjobs
  - /etc/crontab = system cronjobs
  - Min Hour Day Month DayWeek Account Commando
  - run-parts = run all scripts in the script
    - cron.* = scripts that will be runned
  - anacron: = not assume system, checks jobs + ensure run
    - Period Dely JobId Command
  - /etc/cron.allow = allow to run
  - /etc/cron.deny = not allowed
  
- Schedule with systemd
  - systemctl list-units --type=timer
    - config files schedule is runned
  - systemctl list-timer
  - systemctl cat systemd-tmpfiles-clean.timer
    - UNIT = documentation
    - TIMER = time to rn job
      - Monotonic (depends on other) or Real (calender)
        - unit: ms,s,h,month,y...
        - OnBootSec = post boot
        - OnUnitActiveSec = since last job
    - Real: Day-of-Week YYYY-MM-DD HH:MM:SS
    - man systemd.time
    - Not service file = same as unit file
  - Unit Files
    - UNIT: Description
    - SERVICE: control jobs, process  handling
    - EXECStart: command to run

- Services
  - NAME.timer
  - NAME.service

- Transient time
  - User | System time user
  - sudo systemd-run --on-calender="*-*-*08:16:00" bash /home/kaliwork/workspace/hacklab/lpci script3.sh
    - systemctl cat run-ID.service
    - systemctl cat run-ID.timer
  - /run/systemd/transient/run.* = remain even after reboot
  - Delete
    - sudo rm -i $(ls /run/sytemd/transient/run-*.*)
  - Reload systemd
    - sudo systemctl daemon-reload

## Time Management 108.1
- UTC: Coordinate Universal Time x Local Time
  - UTC: always same = 24 hours 
  - Local Time: current location, utc on basis - timezone
- Hardware = real time, firmware
- Software = system clock, does not run on shutdown

- Commands: hwclock, date, timedatectl
- hwclock (UTC, --localtime, --utc|-u|--universal)
  - --show
  - -r = read
  - -w = write
  - --systohc = softare to hardware
  - /etc/adjtime = used to adjust
  - --adjust
  - --hctosys = to system
- timedatectl = software + local time
  - status
  - set-time "CCYY-MM-DD HH:MM"
  - list-timezones
  - set-ntp no
- date --UTC MMDDHHmmCCYY.SS
  - -u UTC
  - -I ISO
  - -R RFC
  - +%s = unix time

- Timezone
  - /etc/localtime -f /usr/share/zonefine
  - /etc/timezone (ubuntu)
  - ln -sf /usr/share/zoneinfo/Europe/london /etc/localtime = change timezone
  - For user:
    - tzselect + select = tell how to set

- NTP (Network Time Protocol)
  - servers around the world
  - Stratum 16 = not synchronized
  - ntpd = daemon
  - Implement
    - Select pool zone
    - config file /etc/ntp.conf
      - server ==> iburst = first correction fast
    - insane time = more 17 minutes different
      - ntpdate pool.net.org
    - start ntpd
    - netpstat
    - netpq -o = pool

- Definition
  - provider = pc that share network zimr
  - Stratum = distance from reference clockin hops/step
  - Offset = difference system and network time
  - Jitter = diff system network time from last NTP pool
  - Pool = group of servers that provide network time

- Chrony = daemon to keep sync
  - Steps
    - Select pool zone
    - config file /etc/chrony.conf | /etc/chrony/chrony.conf
      - pool = server in ntpd
      - maxsources = rotate
      - rtcsync = update hardware clock
    - start + enable
    - tracking = show saerver
    - sources -v = show servers
    - sourcestats
    - Check of NP pool 


## Locale Management 107.3
- locale = language + culture role (currency, numbers)
  - Category="Lang_Terrt.CharctSet@Modifier"
    - en_us.UTF-8
  - -ck = category name(value) + keyword
  - -a = all installed
  - -m = all possibles
- localectl
- /etc/locale.conf = global
- /etc/default/locale

- Characters Set
  - ASCII: older + 128 englisch characters
  - UNICODE: modern and historical + over 143.000 UTF (unicde transformation format)
    - UTF-8 = 1 byte
    - UTF-16 = 2 bytes
    - UTF-32 = 32 bytes
  - ISO/IEC 8859 = 8 bits iso 1-15

- iconv = convert enconding
  - -f from type
  - -t = to type
  - -l = list supported encoding
  
- Manage locale
  - LC_ADDRESS
  - LC_COLLATE: alphabetical order
  - LC_TYPE
  - LC_IDENTIFICATION
  - LC_MEASUREMT
  - LC_TIME
  - LANGUAGE
  - ...
  - LC_ALL = override all
    - not change language
  - C/POSIX = 
  - export LC_NAME=lang_ca.UTF-8
    - fr_FR.UTF-8
    - hi_IN.UTF-8

## IP fundamentals 109.1
- OSI: Application, Presentation, Session, Transport, Network, Data Link, Physical
- TCP/IP: Application, Transport (TCP/UDP), Network (IP/ICMP), Link
- TCP: Connection ==> 3-way handshake ==> SYN - SYN/ACK - ACK
- UDP: no 3-way-handshake
- IP: no 3-way handshake
- ICMP: connection-less, no 3-way.handshake

- IPv4 / IPv6
  - loopback:127.0.0.1 / ::1
  - subnets for IPv4
  - Mask: which part is host and network
    - ipv6: half
  - multicast: several location
  - NAT: only IPv4
  - IPv4
    - 32 Bits/4 Bytes
    - ARP: convert MAC and IP
  - IPv6
    - 3.4x10^38
    - :: == 0000:0000
    - NDP: Neighbor Discovery Protocol
    - subnets not needed

- TCP/UDP ports/services
  - /etc/services = map of ports:services
    - 20/21 = ftp
    - 22 = ssh
    - 23 = telnet
    - 25 = smtp
    - 53 = dns
    - 80 = http
    - 110 = pop3 - 995 pop3 ssl
    - 123 = ntp
    - 143 = IMAP - 993 imap ssl
    - 161 = SNMTP
    - 162 = SNMP
    - 289 = LDAP - 636 LDAP SSL
    - 465 = SMTP over sSL/TLS
    - 54 = shell cmd

- Network Mask
  - ifconfig
  - ip addr show INTERFACE
  - 142.250.72.MASK
  - IPv6
    - 4 first segments = 64 bits: Network = Routing
    - 4 last segments  = 64 bits: Host     = Interface ID
  - IPv4
    - A
      - 255.0.0.0 Netmakst
      - Network first quad + host last
    - B
      - 255.255.0.0
    - C
      - 255.255.255.0 = netmask
    - CIDR
      - /# bits in the network
        - 8bits.8bits.8bits.8bits
  
- NAT = network address Translation
  - convert ip private and public
  - Private
    - 10.0.0.0 - 10.255.255.255
    - 172.16.0.0 - 172.31.255.255
    - 192.168.0.0 - 192.168.255.255
  - IPv6
    - private = site local
      - fec, fed, fee, fef
  - Link local: not routed outside
    - Range: dynamic | mailed
      - Range v4: 192.254.0.0
      - Range v6: fe80::

- Subneting
  - CIDR => subnet =>  divide IP address space + control net traffic
    - number of  in the networt
    - 11111111.11111111.11111111.11110000 = /28
  - IPv6
    - /64, /48, /80 = divide 16

## Config Network 109.2 and 109.3
- hostnamectl = hostname = /etc/hostname
  - --static
  - status
  - set-hostname
  - echo $HOSTNAME
- APIPA = Automatic Private IP Addressing
- dhclient  
  - -r IF
  - -v verbose
- Ethernet
  - wire, IEEE 802.3, RJ56
- Wi-Fi
  - Service Set Identifier (SSID)
  - Access point, 802.11
- Network Interface Card (NIC)
  - Older
    - wired: ethn
    - wireless: wlann
  - New
    - tyL = type + location
      - en = ethernet
      - wl = wireless LAN
      - ww= wireles WAN
      - L = port and slot on pci bus
      - enp0s3 = ethernet p0 slot 3
      - wwp0s1
      - wlp0s2
- ip 
  - -br addr show
  - route = route

- Change hostname
  - /etc/sysconfig/network | /etc/hostname
  - hostnamectl set-hostname new.name.com
  - $HOSTNAME = set by logging

- Network Manager
  - nmcli =network manager command line interface
    - general status
    - -p pretty
    - -c n -p connection show id "name"
    - connection modify id 'IF' ipv4.method manual
    - connection modify id 'IF' ipv4.method new.address
    - connection up id 'IF'
    - general hostname 'NewName'
  - interface= hostanme + ip dyn|sta + ip/dhcp + netmask + default gateway

- iproute2
  - ip options object command
  - ip   -br   address show
    - -b =brief
    - -r = 
    - address
    - link: manage interface
    - route: routing table
  - Modify
    - ip address add ip.ip/CIDRF dev IF
    - ip -br link show dev IF
    - ip link set IF down
    - ip route delete default
    - ip route add via ip.ip = default gateway
  - systemd-networkd
    - ls /lib/systemd/network/

- Legacy network configuration
  - /etc/sysconfig/network-scripts/IF = redhat
  - /etc/network/interfaces = debian
  - /etc/netplan = ubuntu
  - /etc/sysconfig/network
  - Settings
    - DEVICE=interface
    - ONBOOT=
    - BOOTPROTO=dhcp
    - static settings
  - Legacy
    - IPADDR
    - NETMASK
    - NETWORK
    - BRODCAST
  - Modern
    - ipv4=CIDR
    - ipv6nit
    - ipv6=name
- ifconfig
  - ifdown IF
  - ifup

- DNS
  - resolver: define FQDN
  - sends query to nameserver
    - answer or forward to a server
    - /etc/resolv.conf
      - until 3 name servers
    - nmcli connection show
  - /etc/nsswitch.conf
    - Position: file first, before asking server
      - /etc/hosts
- systemd-resolved
  - #DNS=IP
  - systemd-resolve www.domain.ip
  - --statitcs