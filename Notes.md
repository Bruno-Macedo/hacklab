# Basic Steps
- nmap (all ports)
  - script: locate -r nse$ | grep NAME
- dirb | dirsearch
- linpeas
- sudo -l
- find / -perm -u=s -type f 2>/dev/null
- find / -type f -perm -04000 -ls 2>/dev/null 
- psexec.py
- locate -r nse$ | grep mysql = nmap script
- msfvenom - reverse -f aspx -o app.aspx
- wpsscan -U user -P password
- windows
  - /priv
  - smb read/write
  - browser cache
  - 
- stabilize
  -  python3 -c 'import pty;pty.spawn("/bin/bash")'
  - python3 -c  import pty;pty.spawn('/bin/bash') 
  - export TERM=xterm

# Brainpan 1

EIP Offset: 524
ESP Offset: 528


   : jmp esp |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\admin\Desktop\brainpan.exe)
0x

