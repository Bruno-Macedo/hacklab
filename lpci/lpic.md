# LPIC 1 - Cheat Sheet

- [LPIC 1 - Cheat Sheet](#lpic-1---cheat-sheet)
  - [103](#103)
    - [Paths](#paths)
    - [103.1 Basic](#1031-basic)
    - [103.2 Text/Content](#1032-textcontent)
    - [103.4 Redirecting](#1034-redirecting)
    - [103.8ee Text Editor](#1038ee-text-editor)
    - [103.5/103.6 Process](#10351036-process)
  - [104](#104)
    - [104.7](#1047)
    - [104.5 / 104.6 - Modifying files externally](#1045--1046---modifying-files-externally)
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

- * (Wilcard)
  - \*net\* = globing
  - ? = one minimum
  - []
    - range [a-zA-Z0-9]

- file = file type
- Create files
  - touch
    - update timestamp = touch file.txt
    - -m = modification time
    - -a = access time
  - echo "adsad" >> file.txt
- rm
  - -i = prompt before deletion
  - -R = recursve
- cp
  - -r = recursive
- mv
  - rename
  - -i = interactive

- mkdir
  - -p = parents directory
- rmdir
  - -p = parents


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
  
- Compression
  - gzip
    - gunzip
    - zccat
  - bzip
    - bunzip2
    - bzcat
  - xz 
    - unxz
    - xzcat
- tar: Backup = archive
  - -c = create
  - -u = update
  - -v = verbose
  - -f = name of archive
  - Read
    - -d = compare
    - -t = list
    - -w = verify
  - Unpack
    - -x = extract
    - -O = send to STDOU
  - Compress
    - -j = bzip2
    - -J = XZ
    - -z = zip
  
- cpio = copy files to/from archive
  - -o = create archivo
    - create = cpio -ov > arch.cpio
  - -i = read file
  - -t = only name
  - -I = file name
    - view = cpio -itl arch.cpio
  - --no-absolute-filenames
    - Extract: cpio -ivl
  
- lsblk = disks
- dd = create backup = convert+copy file
  - if= inputfile
  - of= outputfile
  - status=progress
  
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

### 103.8ee Text Editor
- emacs
- nano (default)
  - qqtzzg
- vi = vim (default)
  - Esc + : = 
  - modes
    - command
    - insert/enter/edit
    - EX = : = 
      - r /path/to/file = read
      - set number
  - Exit:
    - :wq | :wq! | q! | x! | shift + zz
  - Move J-UMP
  - Move K-up
  - Move H-right
  - Move L-eft
  - ^ beginn , $ less
  - / = search down
  - ? = search up
  - ctrl + u = up 
  - ctrl + d = down

- Commands
  - a = appends after the cursos 
  - u = undo
  - o = new line below current
  - dw = delete part
    - d#w = total words
    - dd = whole line
    - p = paste
    - shift+D
  - copy
    - yw = copy to buffer
    - y#w = copy # to buffer
    - yy = copy entiry line
    - y#y = copy # lines to buffer
- Convert ending
  - set ff=dos

### 103.5/103.6 Process 

## 104
### 104.7
- locate: fast (not work for recently created/downloaded)
  - mlocalte.db
- find
  - -name, -empty, -cmin, -group, -mmin, -perm, -regex, -size, -user
  - -maxdepthgrep 

### 104.5 / 104.6 - Modifying files externally
- File type codes
  - \- file
  - d directory
  - l simboly link
  - b block device
  - c character device
  
- Groups
  - id -Gn = allq
    - -gn = effective group
  - groupmens -g GROUP -l = which user belongs to a group
  
- Owner Group World
  - read
  - write
  - x execute
  - - none

- chgrp GROUP file
- chown = needs permission
  - owner:group file.txt
  
- Permisions
  - chmod
    - u, g, o, a (all)
    - + add
    - -remove
    - = set
    - r,w,x
    - u+x, o+r, g+r, a=rw
  - Octal
    - 0 = none
    - 1 = execute
    - 2 = write
    - 4 = read
    - Owner Group Other
  
  - Special permissions
    - SUID = user's own permision
      - u+s
        - S = not set, only for executated, fileneed to be changed to executables
    - SGID = groups permision
      - g+s
    - Sticky Bit = word level, allows sharing, only owner delete
      - o+t
  - Octal
    - 4 SUID
    - 2 SGID
    - 1 STICKY

- Creation mask
  - files 0666
  - dir   0777
  - umask
    - Special User Group World
    - subract to create permissions
    - -S = showdefaqult creation permission
    - 777 - 775 default = 002
    - umask u= g= o=

- Hardlinks
  - same inode
  - 
- Softlinks 
  - pointer to a file
  - ls -s