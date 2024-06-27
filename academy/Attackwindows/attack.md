- IPs
  - DC1: 172.16.18.3
  - DC2: 172.16.18.4
  - Server01: 172.16.18.10
  - PKI: 172.16.18.15
  - WS001: DHCP or 172.16.18.25 (depending on the section)
  - Kali Linux: DHCP or 172.16.18.20 (depending on the section)


- WS001
xfreerdp /v:$TARGET /u:eagle\\bob /p:Slavi123 +clipboard /dynamic-resolution /drive:linux,/home/kaliwork/workspace/hacklab/academy/Attackwindows 

xfreerdp /v:172.16.18.3 /u:htb-student /p:'HTB_@cademy_stdnt!'+clipboard /dynamic-resolution /drive:linux,/home/kaliwork/workspace/hacklab/academy/Attackwindows 

htb-student:HTB_@cademy_stdnt!

- Kali
ssh kali@$TARGET
xfreerdp /v:$TARGET /u:kali /p:kali +clipboard /dynamic-resolution /drive:linux,/home/kalilearn/workspace/hacklab/academy/Attackwindows 

- Moving files alternative
smbclient \\\\$TARGET \\Share -U eagle/administrator%Slavi123
put
get


```
Ich habe einen Termin für den 4.12.2024, aber da ich schon alle Unterlagen habe, versuche ich einen früheren zu bekommen. Falls ich einen früheren Termin bekommen, werde ich den für Dezember stornieren.
```