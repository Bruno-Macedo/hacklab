# LPIC 102 - Cheat Sheet

## 105.2 Bash Scrippting
- #!/bin/bash = shebang,hashpling,hashbang
  - scripts are executed in bash process (sub-shell)
- Running
  - same path: bash script.sh
  - exec perm: chmod u+x script.sh + ./script.sh
  - diff loct: /path/to/script.sh
  - set $PATH: script on $PATH
  - sourcing:  source script.sh | . script.sh | exec ./script.sh = same shell
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
  - ~/.bash_logout
  - Interactive Non-Login Shell
    - /etc/bash.bashrc
    - ~/.bashrc
- Priority: only one is runed
  - local > global
  - ~/.bash_profile, ~/.bash_login, ~/.profile
- What to do?
  - set env variables + alias + change appearance

- Alias: modifed command
  - alias -p && alias = show all alias
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
  - env,printev = only env variable
  - unset variable | better change than unset
  - export PATH=$PATH:/path/to/my/target = make all available
  - set = alll env (user system)
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
  - now (when), HH:MM,now,noon,midnight,teatime(4:00 PM)
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
  - anacron: = not assume system, checks jobs + ensure run + NO HOUR
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
  - --systohc = softare to hardware (real)
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
    - cronyc = NTP source status/performance
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
    - prefix/routing:host

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
  - no address from DCHP
  - range: 169.254.0.0 - 169.254.255.255
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
  - /sys/class/net = interfaces
  - link set dev IF down/up

- Change hostname
  - /etc/sysconfig/network | /etc/hostname
  - hostnamectl set-hostname new.name.com
  - $HOSTNAME = set by logging

- Network Manager
  - nmtui = ui
  - nmcli =network manager command line interface
    - general status (status = default)
    - -p pretty
    - -c n -p connection show id "name"
    - connection modify id 'IF' ipv4.method manual
    - connection modify id 'IF' ipv4.method new.address
    - connection up id 'IF'
    - radio wifi on/off
    - general hostname 'NewName'
    - device wifi connect NAME
    - device wifi list | device wifi rescan
      - device wifi connect NAME pass 1234 hidden yes
        - ifname
  - interface= hostanme + ip dyn|sta + ip/dhcp + netmask + default gateway

- systemd
  - /lib/systemd/network: system network (+)
  - /run/systemd/network: volatile runtime (++)
  - /etc/systemd/network: local admi (+++)
    - .netdev = systemd-networkd to create virtual devices (bridges,tun)
    - .link = low-level config
    - .network = setup network

- Password wireless
  - wpa supplicant = 
  - wpa_passphrase File > /etc/wpa_supplicant/wpa_supplicant-wlo1.conf

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
    - NETWORK=ip
    - ONBOOT=starts on boot
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


## Troubleshooting networking 109.2, 109.3
- Legacy
  - ifconfig
  - route
  - netstat -r
  - arp
  - netstat -a
  - -6 = ipv6
- New
  - ip address | ip link
  - ip neigh|neighbor|neighbour
  - ip route
  - nc
- ss = socket
  - -s statistic

- Troubeshooting Packet transmission
  - ping -c 3
    - time= round trip (req-rep)
  - traceroute
    - -n no name
    - -I ICMP
  - tracepath
    - mtu provided

- DNS Troubleshooting
  - hostnamectl | getent hosts | hostname
  - host www.name.de
    - -a all
    - check name resolution speed
  - nslookup
  - dig: FQDN records
    - IN = internet Class
    - A = ipv4
    - AAAA = ipv6
    - SEVER = which name server provided the anser
    - @NAMESEVER www.name.de
  - systemd-resolve www.name.de

## Emails 108.3
- Message User Agent: MUA
  - create message
  - KMAIL,Evolution,Thunderbird
- Message Delivery Agent
  - binmain,procmail
- Message Submission Agent: MSA
- Messate Tranfer Agent: MTA
  - get message to remote system + sent to internal Message Delivery Agent (MDA)
  - **Exim,Postfix,Sendmail** (also submission)

- MTA Programs
  - mail.mailutils
  - Exim
    - popular
  - Postfix
    - still developed
    - emulation sendmail
  - Sendmail
    - difficult
    - 1980
    - sendmail target, Message blabla bla
  - mail -s "Subject" target_username + write message + ctr+d (send)
    - n 1 = message
    - d 1 = delete
  - mail -s "Subject remote" user@Hostname_remote + write message + ctr+d
  - Commands
    - mailq = view
    - sendmail -bp  = view
    - newaliases = update
    - sendmail -l = update

- Local Email
  - mailq = list emails
  - sendmail -bp = list emails
  - mail -s "subject" target@remote_host
  - postqueue -p = shows list o email = postfix
    - mailq (no super user)
  - postsuder -d Message = delete from id
  - Forwarding
    - echo WhoShouldReceiveMessage > .forward (~/.forward) = inside folder of absent user
    - 644

- Email Aliases
  - /etc/aliases* = alternative name for user
    - alias: original_user
  - /etc/aliases.db = modified by /etc/aliases
  - Update db:
    - sendmail -l
    - sendemail -I | -bi
    - newaliases

## Printer+Printing 108.4
- Steps: click print ==> print queue (directory) =>>
- cups = common unix printing system
  - /etc/cups/cupsd.conf (primary)
  - /etc/cups/printers.conf
  - IPP = internet printing protocol
  - PDP = printer daemon protocol
- LP = Line printer
  - legacy daemon
  - /etc/printcap = legacy file
  - Print
    - lp -d (designate printer)
    - lpr -P (printer)
  - Status
    - lpstat
      - -p printers available
    - lpq -P (printer)
  - Remove
    - cancel
    - lprm -P (printer)

- New printer
  - /etc/cups/printers.conf = printers
  - lpoptions -d name = set default
  - lpadmin
    - -p PrinterName
    - -D Description
    - -L Location
    - -m PPD-file
      - everywhere = automatically determine ppd
    - -v device-URI lpd://URI
    - -o Options
    - -E enable
    - -x remove printer
  - lpinfo -m
    - --make-and-model "name" -m
  - lstat -a NAME
  - cupsrecject|accept = not to queue
  - cupsdisable|enable = not printer
    - -r "write reason"

- Troubleshooting
  - lpstat -P printer = queue status
  - lpstat -p printer = status to printer
  - lpinfo -m = info about ppd
  - Debugging
    - /etc/cup/cupsd.conf
    - cupsctl = info info info
      - debug logging
      - --debug-logging
      - --no-debug-logging
    - logs: /var/log/cups

## Logging Events 108.2
- text | binary
- Journal = db feature
  - utmpdump | last -f
- /etc/rsyslog.d/* | /etc/rsyslogd.conf
  - Date/Time - Event Type - Importance - Details
    - Rules: facilities, priority, actions
    - facility: i.e. auth 4 authentication, lpr 6 printer service
    - severity: 0 (emerg), 1 (alert), 2 (crt), 3 (err), 4 (warnung), 7 (debug)
  - facility.priority action
- systemd-journald
  - databse, binary
  - FSS = fowared secure sealing = avoid modification
  - etc/systemd/journald.conf
  - journactl
    - -r reverse
    - -e news at bottom

- Legacy methods
  - rsyslog
  - syslogd | sysklogd | syslog-ng
  - /etc/rsyslog.conf
    - facility.priority action
  - remote server
    - protocol(z#)
      - @ = TCP, @@=UDP
    - (z#) = compression
    - host:port
    - @(z2)localhost:1234
    - *.* = all facilities and emergency
  - Receive Logs
    - load modules
    - modify ports to listen
    - set up template definition
    - IP address or FQDN
    - adapt firewall rules
    - Template
      - $template AUthPrivLog, "/path/to/file"
      - authpriv.* ?AuthPrivLogFile

- Systemd-Journald
  - Database file 
  - binary
  - /etc/systemd/journald.conf
    - storage:
      - volatile = only during runing
      - auto =/var/log/journal (only)
      - /var/log/journal = persistent on disk 
      - /run/log/journal = volatile, in RAM
    - compress
    - Seal = protected with key or not
    - SplitMode =
      - uid = per user
      - none = all
    - ForwardToSyslog
    - Rotation
    - MaxFileSec = maximum time before rotation
    - MaxRetentionSec = maxium time before deletion
  - Location
    - /var/log/journal
  - journalctl
    - less
    - --no-pager
    - -e = pager end
    - -r =reverse
    - -k = kernel
    - -u = UnitName
    - -u = pattern
    - --facility
    - -p priority
    - -t identifier
    - -D directory
    - --file FileName
    - --file /path/to/file
    - --file fileNamePatter
  - ForwardToSysLog=
    - to rsyslogd
      - ModLoad = imusock imjournal
  - systemd-journal-remote = pull
  - systemd-journal-upload = send 

- Making Log/Journal entries
  - unit = resource
  - 
  - logger
    - -p facility.priority
    - -s standard error
    - -f FileName
    - -n IPAddress -n FQND
    - -T TCP, -p PORT
  - syslog
    - systemd-cat
    - echo "dasdasdasdas" | systemd-cat
    - systemd-cat echo "message"
      - -t facility -p priority echo "priority message"

- Manage log files
  - /var/log
  - rotation = messages in queue, new logfile started
  - /etc/logrotate.conf
    - hourly,daily, weekly,monthly,maxCapacitiy
  - /etc/logrotate.d
    - for each log
  - journald.conf
    - (persistent | volatiles) limits
      - System..- = persistent
      - Runtime.. = volatile
    - time limits
      - MaxFileSec = maximum time before rotation
      - MaxRetentionSec = maximum time beore deletion
  - Types
    - Active: current
    - archived: old rotated
    - journalctl
      - --disk-usage
      - --vacuum-size = delete until size
      - --vacuum-time = delete until datze
      - --flush = fljush to make persistent
      - --verify = check internal consistency
    - -D directory
    - --file FileName| /path/to/file | 
    - -m --merge = merge files


## Basic Sec Admin 110.2
- system account = nologin = so session
  - services, mail,printing,logging
- /etc/login.defs
- /etc/shadow
  - user:hash:lastchange:beforechange:passwordrequired:until deactivate:expirationdate:
    - !! ! = no password
    - * = cannot log
    - ! = locked
- /etc/nologin = nobody login, except root
  - PAM configuration for exception
- TCP wrappers
  - compiled with library
  - tcpwrapper = allow/deny access
  - /etc/hosts.allow | /etc/hosts.deny
    - no record anywhere = allow
    - 1o allow, 2o deny
  - /etc/hosts.allow
    - search for remote system records, not found goes to hosts.deny
    - servicename:FQDM
    - servicename:IP
  - /etc/hosts.deny
    - found = blocked, not found = allowed
    - PARANOID = nothing at allsyss

## More Basic Sec Adm 110.1
- Account Login Security
  - passwod
    - -S USERNAME = status
    - -e expire password
  - chage 
    - -l status
  - /etc/security/limits.conf
    - restrict configuration
    - maxlogins: max # login for this user
  - ulimit
    - set liits to uers
    - -a all settings
    - -H hard and soft 
  - su
    - su - username
    - su -c "command"

- Configureand Manage Sudo
  - super use do
  - /etc/sudoers OR group sudoers
  - as root
  - sudo -u USERNAME cmd
  - sudo -g GROUPNAME cmd
  - everything logged
  - user machine = (runasUser:Group) options: command
  - test          = (ALL:ALL) NOPASSWD: ll
  - root ALL=(ALL:ALL) ALL
  - %group ALL=(ALL) ALL
  - Alias
    - User_Alias ALIAS= user1, user2, user3
    - Host_Alias ALIAS=IP1,IP2,IP2
  - ALIAS ALIAS = ALL
  - VISUDO

- Audit
  - who = who are logged in
    - -b boot
    - -r runlevel
    - -H headers
  - w
    - Date from: /var/log/utmp + /proc/
    - current time on system + since last boot + number current ousers + cpu load 
  - last = listing last logged users
     - /var/log/wtmp*
     - -f alternative_file
   - lastb
     - failed attempts
     - /var/log/btmp
   - find /usr/*bin -perm /u=s|4000 -type = f
     - SUID = u=s = 4
     - SGID = g=s = 2
     - Both= /6000 | /u=s,g=s
     - -perm perissions
       - num or symb = only
       - -num or -symb = this and others
       - /num or /symb = either other
     - -cmin stats minutes ago
     - -mmin  change minute ago
     - -size
     - -group
     - -user

- Network Audits
  - socket = connection to an openned port
  - nmap
    - -sT = TCP
    - -sU = UDP
    - -l = service listen
    - -p = program+pid
    - -t = tcp
    - -u = udp
    - -a = all
    - --numeric-port
  - lsof = listen open files
    - -i = internet
    - -i4TCP, i6UDP
    - -s = select
    - -sTCP=LISTNEN
    - tcp:22
  - fuser = pricess using files/sockets
    - -v PORT/TCP
    - -n: file/udp/-k kill port/TCP
  - ss = check sockets
    - -u = udp
    - -t = tcl
    - -l = listening
  - systemctl list-unit-files --type=socket

- Turning off services
  - systemctl list-unit-files --type=service
    - enabled = start at boot
    - disabled = not start boot
    - static = cannot be disabled
    - systemctl stop service = until restarted/boot
  - SysVinit
    - service --status-all
    - service NAME stats
    - chkconfig --list
  - xinetd = super daemon, super server
    - listes for networkconnection
    - /etc/xinetd.conf | /etc/xinetd.conf 
    - bind | interface = prevent nework to service
    - only_from
    - access_time

## Encryption 110.3
- Concepts
  - message digest, fingerprint hast
  - collision free: not md5
  - symmetric = same key
  - assymetric = private & public key
  - Digital signature = integrity

- Encrypt files
  - gpg
    - -c file.txt symmetric
    - -d  (grep secret from paths)
    - .gnupg/ = all keys
    - --gen-key
    - --list-key
    - --export -a "ID" > file. ==> create public key
    - --import pub.key ==> import public key
    - --recipeint "KeyId" --out Secretfile --encrypt file.txt ==> encrypt with other people pubKey
    - --out File.txt --decrypt file. ==> decrypt with our privKey
    - Signing
      - --output "Signed_file" --sign EncryptedFile = Signing
      - gpg --out EncryptedFile --verify SignedFile = checking signature
    - Revoke
      - gpg --out KeyRevokeCertificate.asc --gen-revoke "UID" = revoke
      - gpg --import KeyRevokeCertificate.asc = import certification revocation into keyring + share certificate

- Encrypt connection
  - same username on client-server ssh IP
  - scp filetosend user@ip:/path/to/target
  - scp user@ip:/file/to/get /path/on/local
  - single comand ssh
    - ssh user@ip "command to send"
  - configs
    - ~/.ssh/config = overwrite,priority
    - /etc/ssh/ssh_config = all users
    - /etc/ssh/sshd_config = server config
      - ForwardX11: graphical interface
      - PermitRootLogin
      - Protocol 2
      - Port 22
    - known_hostos
      - client user remote open ssh keys: ~/.ssh/known_hosts
      - system wide: /etc/ssh/ssh_known_hosts