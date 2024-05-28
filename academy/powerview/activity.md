xfreerdp /f /u:"htb-student" /p:"Academy_student_AD!" /v:$TARGET +clipboard /workarea /drive:linux,/home/kaliwork/workspace/hacklab/academy/powerview


name    dnshostname                 operatingsystemversion                                        useraccountcontrol
----    -----------                 ----------------------                                        ------------------
DC01    DC01.INLANEFREIGHT.LOCAL    10.0 (14393)                        SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
EXCHG01 EXCHG01.INLANEFREIGHT.LOCAL 10.0 (14393)                                           WORKSTATION_TRUST_ACCOUNT
SQL01   SQL01.INLANEFREIGHT.LOCAL   10.0 (14393)           WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
WS01    WS01.INLANEFREIGHT.LOCAL    10.0 (14393)                                           WORKSTATION_TRUST_ACCOUNT
DC02    DC02.INLANEFREIGHT.LOCAL                                           ACCOUNTDISABLE, WORKSTATION_TRUST_ACCOUNT


DC01
EXCHG01
SQL01
WS01
DC02


S-1-5-18
S-1-5-21-2974783224-3764228556-2640795941-1883
S-1-5-21-2974783224-3764228556-2640795941-1916
S-1-5-21-2974783224-3764228556-2640795941-2601
S-1-5-21-2974783224-3764228556-2640795941-2616
S-1-5-21-2974783224-3764228556-2640795941-498
S-1-5-21-2974783224-3764228556-2640795941-516
S-1-5-21-2974783224-3764228556-2640795941-519
S-1-5-32-544
S-1-5-9

PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-1883
INLANEFREIGHT\frederick.walton
PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-1916
INLANEFREIGHT\gillian.fisher
PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-2601
INLANEFREIGHT\Organization Management
PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-2616
INLANEFREIGHT\Exchange Trusted Subsystem
PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-498
INLANEFREIGHT\Enterprise Read-only Domain Controllers
PS C:\Tools> ^C
PS C:\Tools> Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-498
INLANEFREIGHT\Enterprise Read-only Domain Controllers
PS C:\Tools>

----                  ---- ------        ------------
ADMIN$          2147483648 Remote Admin  Ws01
C$              2147483648 Default share Ws01
Client_Invoices          0               Ws01
Financials               0               Ws01
IPC$            2147483651 Remote IPC    Ws01
Old_reports              0               Ws01
