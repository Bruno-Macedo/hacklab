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



