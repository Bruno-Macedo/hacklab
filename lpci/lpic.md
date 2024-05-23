# LPIC 1 - Cheat Sheet

- [LPIC 1 - Cheat Sheet](#lpic-1---cheat-sheet)
  - [103](#103)
    - [Paths](#paths)
    - [103.1 Basic](#1031-basic)
      - [ENV](#env)
    - [103.2 Text/Content](#1032-textcontent)
    - [103.4 Redirecting](#1034-redirecting)
    - [103.8ee Text Editor](#1038ee-text-editor)
    - [103.5/103.6 Process](#10351036-process)
  - [104](#104)
    - [104.7](#1047)
    - [104.5 / 104.6 - Modifying files externally](#1045--1046---modifying-files-externally)
  - [101.1, 102.1 104.1 Storage](#1011-1021-1041-storage)
  - [104.1 / 104.3 - Manage storager](#1041--1043---manage-storager)
  - [102.1 / 104.2 - Maintanng Storage Space](#1021--1042---maintanng-storage-space)
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

#### ENV
- not default
  - $EDITOR
  - $VISUAL
- $PWD
- $PS1
- $HISTSIZE
- $UID
- $GROUPS
- LC_ALL = local variable
  - LC_*
- LANG
  
- printenv
  - printenv VARIABLE

- set
- local: envs + settings
  - TZ = timezone
  - LD_LIBRARY_PATH: PAth directores
  - export PATH=$PATH:/path/to/exec
  - PATH=$PATH:/path/to/exec
- Invoking outside the path
  - ./script
- unset = remove variable

- Modfiy variables
  - $PS1 = prompt
  - $PS2 = appearance of secondiry prompt

- Subshell (set variables do not survive)
  - $SHLVL = level shell
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
  - ^F Columns header
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
  - read from /sys
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
- 

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
- ps
  - -efl = aux
  - GNU long
    - double dash
  - Unix: single das
    - -e all
    - -lf long format
  - BSD
    - aux
- pgrep
  - -u user
  - -a all
  - -t tty
- pidof CMD
- top
  - n = most cpu usage
  - shift+l = locate
  - r = new nice
- upime
  - system up,number users, ram
- free
  - -h
- watch
  - -n # CMD = interval

- Priority
  - /proc/1 = static

- Mutiplexer
  - tmux
  - screen
    - screen ls
  
- Jobs = process on the background
  - bg %
  - fg %j
  - jobs
    - list jobs
    - -l PID

- Signals: message to process
  - man -s 7 signal: list all
  - SIGHUP: terminate when logout
  - SIGKILL/KILL/9: kill
  - SIGTERM/TERM/15: default, terminate if possible
  - kill %JOB
  - killall 
  - nohup: ignores sighub, continues running after logout
    - nohup PROCESS PID&
    - dettach from section
  - pkill: signal to process
    - based on attributes

- Process Priority
  - NICE = -20(high)...19(low)
  - nice -n PRI CMD
  - renice +PRI
    - renice -VALUE -p PID
    - -g GROUP 
    - -u USER
  - top
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

## 101.1, 102.1 104.1 Storage
- ls /dev/sda?
- lsblk
  - lvm = logical volumes: single/multipla parti
  - part = partition
  - -f = file system
  - -o NAME,SIZE,FIELD
- cat  /proc/partitions = supported formats

- File System = partition after formatation
  - cat /proc/filesystems
  - swap = extension to memory
- Partition = logical subset of disk
- mount = attach the filesystem to a point in the system
  - existing files are unavaiblable until unmount + anywhere mount

- Partitions
  - /boot
  - GRUP2 + boot/grub + first parititon
  - EFI = Unified Extensibe Firmaware Interface + boot loaders + kernel images + FAT
  - /var = variable data
  - SWAP = swap memory disk<->RAM

- Mass Storage
  - hd* = old PATA
  - sd* = SATA, SCSI, USB
  - sr* = optical drive
  - fd* = floppy drive
  - NVMe = sshd connected to PCI Express Bus
  - mmclk0 = SD cards
  
- Logical Volumes Management
  - VG = volume group
  - VG are made of physical volumes
  - PV = disk designedte by LVM
  - pvcreate
  - vgcreate
  - vgextend
  - lvcreate
  - lvm --help
  
- Device mapper
  - /dev/mapper
  - lsblk -p
  - readlink -f /dev/mapper/DiskName

- btrfs
  - butters file system
  - B-Tree data strcuture to read/write
  - for large files
  - own RAID
  - strcutures and subvolumes
  - sublume = sub-section of btrfs parente
  - mounted separatley from other subvolumes
  - compression
    - LZO, ZLIB, ZSTD

- Device info
  - lsdev = low levle device info
    - mount pints to filesystem / RAM space
    - proc = process, hardware info
      - /dev/dma/ =  direct memory access
      - /proc/cpuinfo
      - /proc/interrupts = which hardware has data to cent
      - /proc/ioports = memory location in cpu that send data back<-> forth
      - /dev/disk/by-id = worl wide identifier wwid
        - by-label
        - by-uuid = Universally Unique Identifier 
        - by-path = how is connected to the system
    - /sys = devce, kernel info
    - /dev = system device, storage

- lspci: slot class vendor, device, rvision,. interface
  - -s HEX -
  - -k kernel drive
  - -t
- lsusb
  - -d ID
  - -t tree
  - -s BUS:DEV = which device is using module

- Hardware
  - MAJ(class/type):MIN()
  - proc/device
  - /proc/meminfo =
  - /sys/block
  - 512 * (size from /sys/block/dm-1/size)

- Transating between Linux and Hardware
  - drivers: tranlsate device linux
  - ls /lib/modules/xxxx/kernel/drivers
  - lsmod = modules loaded to kernell
  - modinfo 
  - kmod
  - modprobe = load/unload (also independences)
    - -r remove module name
  - rmmod = remove mode
  - insmod /path/to/md (not dependence)

- HotPlugs
  - while running (usb stick)
- Could plug = already plugged before boot + to plug shutdown = /dev/sd*
  - udevadm info /dev/path
  - udev = setting up files in the /devfor cold plug device + rules in sysf /sys
  - rules = /etc/udev/rules.
- DBous = Deamong + communication for other services


## 104.1 / 104.3 - Manage storager

- Partitions
  - /proc/partitions
  - Partition Table: data structure where/size partition
  - MBR: old - 2.2TB - 3 (primary, extended, logical)
  - GPT = Globally Uniy Identifier
    - > 2.2 TB, no types, portection, 
  - gdisk /path/to/disk
    - -l /path/to/disk = info
  - fdisk /path/to/disk = older (for MBR)
    - default MBR
  - parted /path/to/disk = not friendy
    - mkpart primary AFTER END

- Make File System
  - no supported: load module
  - mkfs
    - -t ext4
    - -/dev/path/to/disk
  - mkfs.ext4 /path/to/disk
  - Mount FS
    - blkid
    - mount -t ext4 /path/to/drive /path
    - umount /path = umount /path/to/drive
    - Automatically
      - /etc/fstab = file system table
        - 1 checked
        - options: auto (will mount), nouser (only su), rw (read write)
        - mount -a = mount all of the fstab

- Format swapp partion
  - sudo mkswap /dev/path/disk

## 102.1 / 104.2 - Maintanng Storage Space
- FHS: Hierarchy
  - Minimum: /boot, /, swap
  - Same FS: /etc,/sbin,/dev,/bin/,/lib = along with root
  - Separate FS: /var,/tmp,/usr/,/home,/opt,/boot,/usr/local
- system.d
  - mount file system by booting
  - .mount
  -  reads /etc/fstab
  -  systemctl -t mount list-units
     - -t = type
        - list-units, list-dependencies, show, status
      /etc/systemd/system 
  
- FS Consumption
  - df = diskspace available
    - -h human
    - -T type(ext4)
    - -i = inode
  - du = disk usage
    - -s summary
    - -s --inodes
    - -d deepth

- Tuning FS
  - adding label (i.e.)
  - mke2fs
    - -c create
    - -L label
  - tune2fs = update/adjust
    - -l = list content of fs block
    - UUID,Label;Mount-Count
  - xfs_fsr xfs_admin = for XSF
  - btrfs balance + btrfstune = for btrfs

- Repair
  - fsck -r (report) /dev/disk
    - /etc/fstab = check+repair unmounted fs
  - e2fsck
  - XFS
    - xfs_repart
    - xfs_db xfs_repair -n = check
  - btrfs
    - btfs check
    - btrfsck