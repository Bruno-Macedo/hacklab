robin:robin

cto.dev@dev.inlanefreight.htb
dev.inlanefreight.htb

DEV2.DEPARTMENT.INT
iso.3.6.1.2.1.25.1.7.1.2.1.2.4.70.76.65.71 = STRING: "/usr/share/flag.sh"


PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute:
|_  XE + XEXDB + IN


PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null_user
|_  Level: 1.5, 2.0


## Assessment 1
ceil:qwer1234


dig axfr inlanefreight.htb @10.129.242.151

; <<>> DiG 9.19.21-1-Debian <<>> axfr inlanefreight.htb @10.129.242.151
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 16 msec
;; SERVER: 10.129.242.151#53(10.129.242.151) (TCP)
;; WHEN: Tue Apr 09 15:32:08 CEST 2024
;; XFR size: 10 records (messages 1, bytes 540)

rustscan -a 10.129.242.151 -t 500 -b 1500 -- -A
Open 10.129.242.151:2121


## Assessment 2
HTB

rustscan -a $TARGET -t 500 -b 1500 -- -A

Open 10.129.202.41:111
Open 10.129.202.41:135
Open 10.129.202.41:139
Open 10.129.202.41:445
Open 10.129.202.41:2049
Open 10.129.202.41:3389
Open 10.129.202.41:5985
Open 10.129.202.41:47001
Open 10.129.202.41:49664
Open 10.129.202.41:49665
Open 10.129.202.41:49667
Open 10.129.202.41:49668
Open 10.129.202.41:49666
Open 10.129.202.41:49679
Open 10.129.202.41:49680
Open 10.129.202.41:49681


PORT      STATE SERVICE       REASON  VERSION
111/tcp   open  rpcbind?      syn-ack
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
2049/tcp  open  mountd        syn-ack 1-3 (RPC #100005)
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WINMEDIUM
|   NetBIOS_Domain_Name: WINMEDIUM
|   NetBIOS_Computer_Name: WINMEDIUM
|   DNS_Domain_Name: WINMEDIUM
|   DNS_Computer_Name: WINMEDIUM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-09T17:14:19+00:00
| ssl-cert: Subject: commonName=WINMEDIUM
| Issuer: commonName=WINMEDIUM
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-04-08T17:12:28
| Not valid after:  2024-10-08T17:12:28
| MD5:   3af3 0fbb d510 d3d0 b48e 8cd1 2b89 38ae
| SHA-1: 3a1b 8195 72b7 cd6e 557f ca2d f4c3 a800 a380 0262
| -----BEGIN CERTIFICATE-----
| MIIC1jCCAb6gAwIBAgIQRCQC0CZxcKVNQ9277aC6ZDANBgkqhkiG9w0BAQsFADAU
| MRIwEAYDVQQDEwlXSU5NRURJVU0wHhcNMjQwNDA4MTcxMjI4WhcNMjQxMDA4MTcx
| MjI4WjAUMRIwEAYDVQQDEwlXSU5NRURJVU0wggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQCk8prDam13ehgzNgBeWp2vMmWFnEqpVDF37Q6zyDOw9tAPuBy6
| nCfAL9f5MGKRqYpJxNW3hLn96lq3mUpA3Ci/DwXDMqxm2IFeBhLw8mO/LpHqwQaE
| r+iRbswueP1C3RcwCiCpvB8BF56kBN6tVinchmemMLJvvG1fF89QrThqugres5GM
| ttD6aFYJHObitIWWrDRRWZdvi/5n3ntVlBOnAe1oNkB7bJlRfIlBusQQo+/SuzcF
| wrhnsZtiHFI5cek7Bhjq39Z84DivG0NTQwDEukNXlYxaQibKxvj7sxNV3r9pJaeW
| 2nAoeq3hXTntb+efVngIxAvXT1hDAdpz9xuZAgMBAAGjJDAiMBMGA1UdJQQMMAoG
| CCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAVcAB1zPs
| F79lGryzRQ3VGgdLldlnlbbE8Z8J9wqXVTt7+Mbs3sXWb+kDZCyuiWLJQAzi0k0x
| GDJkC3Y/MjBSVGKBcoi3PCfaFh9JajQYOqQaWxXSibF9Ac51fWWAAV8DmGhFmPPd
| ckA+L0dWMzwb7upsjaExEQFynluxgMO+IAP5Ts0Hk7CKKZy0a8T0Vtd8q629S6UB
| o0/VTvj8pNBBVJumnupzhsyDLA1oMUYfKZx3lrqsvC6X7dG9JcWeb8sNgKfXDWVO
| 6xs/HCfiq4BoSCtk5+yP+5bodA0giPwyG57l2o/A3oFBlaIk3H3NTf5KMoQ6OeUP
| N2KZs1ed/xEm6A==
|_-----END CERTIFICATE-----
|_ssl-date: 2024-04-09T17:14:30+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 62546/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 47689/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28088/udp): CLEAN (Failed to receive data)
|   Check 4 (port 10392/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-04-09T17:14:22
|_  start_date: N/A

- showmount -e $TARGET
- /TechSupport (everyone)

- sudo mount -t nfs $TARGET:/TechSupport ./mount2 -o nolock

File:

   host=smtp.web.dev.inlanefreight.htb
 3    #port=25
 4    ssl=true
 5    user="alex"
 6    password="lol123!mD"
 7    from="alex.g@web.dev.inlanefreight.htb"
 8}
28     cookie {
29     #       name=id
30     #       path=/login
31     #       domain="10.129.2.59:9500"
32            httpOnly=true
33            makeTransient=false
34            absoluteTimeoutInMinutes=1440
35            idleTimeoutInMinutes=1440
36    }

sa:87N1ns@slls83 

sqlcmd -S SERVERNAME\\accountname -U julio -P 'MyPassword!' -y 30 -Y 30
lnch7ehrdn43i7AoqVPK4zWRlnch7ehrdn43i7AoqVPK4zWR


password
lnch7ehrdn43i7AoqVPK4zWR