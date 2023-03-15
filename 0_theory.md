# Theory

## Definitions
- **Attack Vector**: tool, technique method USED to attack
  - weapons, phishing, DOS, Web drive-by, Flaws in browser, unpachecksecd vulnerability
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

# Assembly in Windows
[Tryhackme - Windows x64 Assembly](https://tryhackme.com/room/win64assembly)

## Registers
- Variables
- Faster to access
- Bigger ones go to RAM = slower
- Also user Pointer
- General-Purposes Registers
  - RAX = accumulator register = store return value
    - R Register
    - E Extended
    - [Other registers](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture)
    - [ALL registers](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture)
  - RBX = base register = used as base pointer
  - RDX = data register
  - RCX = counter register = loop
  - RSI = source index = source pointer in string
  - RDI = destination index = destination pointer in string
  - RSP = stack pointer = holds address of the top of the stack
  - RBP = base pointer  = hold address of the bottom of the stack. To restore to the function
  - RIP = Instruction Pointer = address of **next line**

## Operations
- Around 1500 instructions
- Terms
  - immediate = IM = constant
  - register = RAX, RBX, AL
  - memory = location in memory
  
- Instruction
  - (Instruction/Opcode/Mnemonic) <Destination>, <Source>
  - mov RAX, 5

- Common Instructions
  - mov = move = store data
  - lea = load effective address = no dereference AND calculate addresses ONLY
  - push = push onto stack (put on top) ~= copy = save date inside register
  - pop = take from the stack and store in the destination
  
- Arithmetic
  - inc = increment
  - dec = decrement
  - add = add  (source to destinatination)
  - sub = subtract  
  - Multiplication
    - MUL (unsigned) / IMUL (signed) = 
      - RDX:RAX
    - DIV / IDIV
      - RBX:RAX
  - Flow Control:
    - cmp = compare
    - jcc = conditional jumps
      - JNE, JLE, JG = jump not equal, jump less then, jump greater
    - call = call
    - ret = return to caller
    - NOP = no operation = padding
  
- Pointers
  - [var] = &var = dereference 
  - LEA = ignores squars []

- jg (jump if greater) x ja (jumb if above)
  - JB/JNAE = jump if below | not above or equal
  - JAE/JNB = jump if above or equal / not below
  - JBE/JNA = jump if below or equal | not above
  - JA/JNBE = jump if above | not below or equal

## Flags
- Result of previous operation/comparison
- Register: EFLAGS / RFLAGS
- Status
  - Zero Flag =  result zero
  - Carry Flag = unsgined
  - Overflow Flag = signed too big
  - Sign Flag = result negative
  - Adjust/Auxiliary Flag = Carry = 
  - Parity Flag = 1 if last 8 bits = even
  - Trap Flag = single stepping

## Calling COnvention
- Several
- How parameters arge passed to functions
- Caller = making the call
- Calee = called function
- Types: syscakk, stdcall, fastcall, cdecl
- **Fastcall**
  - for windows x64
  - Application Binary Intercace (ABI)
  - First 4 Parameters: 
    - Left--to--Right
    - integer: RCX, RDX, R8, R9
    - floating: XMM0, XMM1, XMM2, XMM3
    - others go the stack = right to left
  - Too big = passed as referece = pointer to data in memory 
  - Caller allocates space for calee
  - RAX, RCX, RDX, R8, R9, R10, R11, and XMM0-XMM5 = volatile
  -  RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15, and XMM6-XMM15 = nonvolatile
- [More Info](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019) and [Here](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019)

- cdecl
  - C Declaration
  - parameters on stack: right to lefht
  - RBP saved
  - return via EAX
  - caller: cleans stack

## Memory Layout
- Segment
  - Stack = non-static local variable
  - Heap = dynamically allocated
  - .data = global and static data initialized not zero
  - .bss = global and static data, uninitialized or zeor
  - .text = source code
- TEP = Thread Environment Block = info about currently running thread
- PEB = Process Enviroment Block = info about the processes and loade modules
- Stack Frames
  - chuncks of data: local variables, saved base pointer, return address of the caller and parameters
  
| Lower Address  | Local var      | RBP - 8  |
| -------------- | -------------- | --------|
|                | Return Address | RBP + 0  |
|                | saved RBP      | RBP + 8  |
| Higher Address | Func Parameters| RBP + 16 |

- Endianness
  - big endian: most significant byte far left
  - little endien: most significant byte far right

# Firewalls
- Tools
  - Compressor
  - Emulator

- Detection
  - Static: signarute, pattern-matching
  - Dynamic: run time detection
  - Heuristic/Behavioral: source code compare; 

- Yara
  - rule-base detection

- Testing files
  - [AntiscanMe](https://antiscan.me/)
  - [Scan Jotti](https://virusscan.jotti.org/)