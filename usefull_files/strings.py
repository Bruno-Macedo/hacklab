for x in range(1, 256):
  #if "{:02x}".format(x) not in listRem:
    print("\\x" + "{:02x}".format(x), end='')
print()