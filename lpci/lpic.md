# LPIC 1 - Cheat Sheet

- [LPIC 1 - Cheat Sheet](#lpic-1---cheat-sheet)
  - [103](#103)
    - [Paths](#paths)
    - [103.1 Basic](#1031-basic)
    - [103.2 Text/Content](#1032-textcontent)
    - [103.4 Redirecting](#1034-redirecting)
  - [104](#104)
    - [104.7](#1047)
```
docker run \
    -itd \
    --name opensuse \
    --publish 2222:22 \
    alvistack/opensuse-leap-15.5

ssh root@localhost -p 2222
```

- Docker CentOS
```
docker run -it --rm adevur/centos-8:latest /bin/bash
```

- Ctrl + Alt + F2/3/4... = virtual terminal
  - Ctrl+Alt+F1 = return to orignal
- tty = which terminal

## 103
- Filesystem Hierarchy System (FHS)
  - /boot - /etc - /home - /media - /mtn - /opt - /tmp 
  - /usr
    - /usr/bin = user binaries
    - /usr/sbin = admin binaries
    - /usr/local = local installation
  - /var = logs (i.e.)

### Paths
- cd - = go to previous direcotry
- options = change behavior
- Paramenter = change on what operate


### 103.1 Basic
- uname
  -s = Distro
  -r = kernel
  -a = all
  -v = build date
- bash --version
- type CMD = builtin/external
  - external = /path/to/command
    - help CMD
  - hashed = recently used, in hash table
    - hash -d = clear table
- whereis
  -  -m man
  -  -b binary

- man = commands
  - /usr/share/man
  - man man
  - -k COMMAND = apropos
  - -k COMMAND | grep ^command
- info = system CMD
- help = built-in

- History
  - !#
  - .bash_history
  - -w = write  current history to file
  - -c = clear history

### 103.2 Text/Content
- ls 
  - -L = dereference, folders/executables/symbolic links
- more = forward
- less =  back/forward
  - / = forward search
  - ? = backward search
  
- head -n/-#
- tail -n/-#
  - -f = display new messages
- cat

- wc lines/words/bytes
  - -l lines
  - -w words
  - -c bytes
- nl = number line (not blank)

- uniq (not sort)
  - -c count ocurrences
  - -D show all duplicates
  - -d show duplicate once
  
- hash
  - md5sum | sha256sum | sha512sum

- od octal dump
- -x hex
- -c characters

- cut = chunks
  - -b bytes
  - -d DELIMETER -f FIELD
- tr
  - -s = squeeze, repeated

- sort
  - -n numerica
- paste = merge lines
  - file1.txt file2.txt
  - -d delimiter
- split = split file in pieces
  - split ORIGINAL filename
- grep
  - -i case insensitive
- find -regex
- REGEX
  - -d skip directory
  - + = 1..n
  - ? = 0..1
  - . = 1
  - -E + = one...
  - -f = pattern inside a file
- "" = shell coding
- egrep = deprected
- fgrep = grep -F
- sed
  - s//d = delete
  - s///g = replace global
  - s/^$/d = remove blank lines
  
### 103.4 Redirecting
- change behavior, SEND/RECIEVE different directions
  - >  add
  - >> append
  - | = stdout as stdin to next command
- tee
- STDERR
  - FD 2>
- & = STDOUT/STDERR
- 2>&1 = STDERR to STDOUT

- xargs = commands from STDIN
  - ls | xgars grep = the files are passed as argument to the next command
    - = grep 1.txt 2.txt 
  - -o: open tty for interactive
  - -i
- `` = ()

## 104
### 104.7
- locate: fast (not work for recently created/downloaded)
  - mlocalte.db
- find
  - -name, -empty, -cmin, -group, -mmin, -perm, -regex, -size, -user
  - -maxdepthgrep 
