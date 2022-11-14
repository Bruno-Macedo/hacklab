- [Passwords](#passwords)
- [Basics](#basics)
- [Hashcat](#hashcat)
- [John](#john)
- [Hydra](#hydra)
- [Creating Wordlists](#creating-wordlists)

# Passwords

# Basics
- cracking: from hash
- guessing: from dictionary (loud)
- dump = leaks of passwords/hash
- Combine
  - cat file1 file2 > file3
  - sort fil3 | uniq u > cleaned

# Hashcat
- Identify hash
  - hashid
  - hashidentifier

- hashcat
  - a 0 = dictionary attack
    - dictionary = list | brute-force = guessing
  - -m 0 = type of hash
  - -a 3 = brute force method
  - ?d = use digit for generating
  - TOTAL_CHARACTERS = generate list
  
# John
- Using rules
  - john --wordlist=existing_list --rules=pick_one --stdout
  - --format=ENCRYPTION
  - adding rule
    - conf file: [rule_name] Az"[0-9]" ^[!@#$]

# Hydra
- hydra -l username -P wordlist.txt server service
- hydra -l username -P wordlist.txt service://server
- -d = debug
- -v = verbose
- -V = show attempts
- -f = terminate if found
- -t = number threadlos

- web
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[inside_request]:username=^USER^&password=^PASS^:F=incorrect"** -v
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[request]:[body_request]"** -vV -f
  - hydra -l USERNAME -P wordlist.xt server *request* **"/[request]:username=^USER^&password=^PASS^:F=incorrect"** -v
    - Request: HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy
    - IP/URL http-get-form | http-post-form "/login-get/index.php:[BODY_CONTENT]&username=^USER^&PASSWORD=^PASS:S=logout.php" -f
    - for post: whole POST BODY
      - S= [message_for_success]
      - F= [message_for_failed]
      - -V Verbose
      - -f = stop attack after finding

- FTP
  - hydra -l [USERNAME] -P password.lst ftp://IP
    - -L = list of usernames

- SMPT
  - -l email@address.com -P [Password_List] smtp://IP -v

- SSH
  - -L [USER_LIST] -P [PASS_LIST] ssh://IP -v

# Creating Wordlists
- cewl URL
  - -w = output
  - -d 5 = depth
  - -m 5 = minimum
  
- username_gennerator.py

- crunch
  - combination of characters
  - crunch 2 2 123456abcd -o output
  - -t startpassword[symbol1][symbol2]
    - @ lower case
    - , upercase
    - % numeric
    - ^ special

- cupp
  - based on information of the target, birthdate, pet, etc
  - https://github.com/Mebus/cupp.git