TODOS:
- Attacking Common Services
- Footprinting
- Pivoting, Tunneling, and Port Forwarding
- AD
- AD Bloodhound


jason: 34c8zuNBo91!@28Bszh
robin:7iz4rnckjsduza7

mssqlsvc:princess1
MSSQLAccess01!

Domain:ATTCSVC-LINUX
10.129.62.226 

DB name

master
tempdb
model
msdb
hmaildb
flagDB


We found a hash from another machine Administrator account, we tried the hash in this computer but it didn't work, it doesn't have SMB or WinRM open, RDP Pass the Hash is not working.

User: Administrator
Hash: 0E14B9D6330BF16C30B1924111104824

10.129.203.6
inlanefreight.htb 
ns1.inlanefreight.htb 
hr.inlanefreight.htb 
helpdesk.inlanefreight.htb 
control.inlanefreight.htb

PORT    STATE    SERVICE VERSION
25/tcp  open     smtp    hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp open     pop3    hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
143/tcp open     imap    hMailServer imapd
|_imap-capabilities: CHILDREN IMAP4 SORT QUOTA OK RIGHTS=texkA0001 ACL NAMESPACE CAPABILITY IMAP4rev1 IDLE completed
587/tcp open     smtp    hMailServer smtpd
| smtp-commands: WIN-02, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
Service Info: Host: WIN-02; OS: Windows; CPE: cpe:/o:microsoft:windows

marlin:poohbear
marlin@inlanefreight.htb 