# LPIC 101 - Cheat Sheet

- [LPIC 101 - Cheat Sheet](#lpic-101---cheat-sheet)
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
  - [101.2 Booting](#1012-booting)
    - [Bootloader menu](#bootloader-menu)
  - [101.3 Initialization](#1013-initialization)
  - [102.4 102.5 Manage Debian - Package Management](#1024-1025-manage-debian---package-management)
    - [RedHat](#redhat)
  - [102.3 Libraries](#1023-libraries)
  - [102.6 Virtualization](#1026-virtualization)
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
  - bzip (replaced)
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
  - a = appends after the cursor 
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
- 
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
  - ln File.txt LINK
- Softlinks 
  - pointer to a file
  - ls -s file.txt LINK

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
  - /proc + /sys = during runtime, pseudo fs, 
    - /proc = process, dma,ioports,interrupts,cpuinfo
    - /sys = kernel data
    - /dev/system device
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

## 101.2 Booting
- mount | grep boot
- Booting
  - Firmware -- bootloader -- kernel --- items --- sys init --- services
  - Classic: Firmware --- bootloader (first sectr mbr) - 
    - chainloading: point to secondary boot loader
    - LILO: old
    - GRUB Legacy
    - GRUB2: common
  - /boot/vmlinuz....z = compressed = kernel = programs to load

- System initialization = runs background
  - SysVinit: (scripts stored /etc/init.d)
  - Runlevels 0-6 (scripts stored /etc/rc.d/rc?.d)
    - 0 = shutdown
    - 1 = boot (root only) = rescue
    - 3 = all user, no net
    - 5 = graphical
    - 6 = reboot
  - default in /etc/inittab (now systemd)
  - Change with init/telinit

-  Legacy Bootloader = BIOS
   -  menu.lst
   -  grub.conf
      - timeout
      - title: start of configuration + info to display
      - root
      - kernel (ro by start)
      - initrd = load RAM disk to run drivers (virtual disk load into memory) = Point to FS or RAM disk
 - Install Grub
   - grub-install (legacy)
     - (hd0) = first hard drive
     - (hd0,0) = first drive + first partition
     - /dev/sda
     - /dev/sda1

- Modern boot
  - Chainloading = in MBR, bootloader in MRpoints to another bootloader
  - Firmware (UEFI) + mini-bootloader(boot manager) + Bootloader is in EFI system partition (ESP) + ESP mounted on /boot/efi + check sys/firmware/efi
  - UEFI = /boot/efi (mounted)
  - Initialization
    - systemd
      - parallel
      - group services = target = unit
      - systemctl = management

- GRUB2
  - grub.cfg = Modification /etc/default/grub
    - /boot/grub/grub.cfg
    - /boot/grub2/grub.cfg
    - /boot/efi/EFI/distro/grub.cf
  - /etc/grub.d = customize menu
    - **title + root + kernel (parameter) **+ initrd** = legacy
    - **menuentry + set root + linux?? (parameter) + initrd = new**
    - title = menuentry Kali
    - root = hd1,gp1 = second disk + first partition
    - linux = 
      - linux = BIOS
      - linux16 = BIOS
      - linuxuefi = UEFI
    - initrd = initial ram file dist = /boot/initrd
      - BIOS: initrd = 
      - UEFI: initrdefi =
- grub-mkconfig > /path/to/grub
- grub-mkconfig -o /path/to/grub
- grub2-mkconfig > /path/to/grub
- grub2,lcpmfog -o /path/to/grub
- update-grub

### Bootloader menu
- GRUB legacy
  - b = boot
  - c = command/edit
  - Command: i.e. displaymem
  - root + kernel + initrd
  - Kernel parameters
    - **kernel line:**
      - parameter: 1/single/s = only root (no password needed)
- GRUB2
  - boot config
  - Kernel parameters
    - linux16 | linux =
      - parameter: systemd.unit=emergency (password) | singles
      - Rescue:    root + no network + all FS mounted (read/write)
      - Emergency: root + no network + only / mounted (read-only)
  
- Messages
  - dmesg = Kernel Ring Buffer (FIFO)
    - -H
  - journalctl
    - -b = boot
    - -k = dmesg
  - /var/log/boot |bootstrap | boot.log (redhat)
  - 

## 101.3 Initialization
- Runlevels
  - **0: halted/stoppdes, shutdown**
  - **1: single user s/S**
  - **2: multiple users, no network**
  - 3: network
  - 4: customizable level
  - 5: multi user, network, gui
  - **6: reboot**
  - rc.d/rc?.d => symbolic link to script
    - K = kill
    - S = start
  - Change
    - (old): /etc/inittab: id: N (previous) 5 (level)
    - init LEVEL
    - telinit

- Modern initialization
  - targets = group of services to start
  - systemctl 
    - get-default 
    - set-default multi-user.target
    - cat service
      - UNIT: description/docssysss
      - SERVICE: start the service
      - INSTALL: what target install
    - list-unit-files
  - Status
    - enables: start
    - disabled: wont start
    - static: manually started
  - /etc/systemd/system/ =
  - /run/systemd/system  = override  /etc/systemd/system
  - /usr/lib/systemd     = override in /run /etc

- systemctl stats SERV= direct controls systemd
- service SERV status   = multiple init systems = high level

- Manage services
  - systemctl stats/stop/start/restart/ service
    - isolate (group) emergency.target, rescue.targe, runlevel#
  
- shutdown options time message 
  - systemctl = shutdown,halt,poweroff,reboot
    - isolate poweroff|halt|reboot
  - is-system-running
    - degraded = not all services
  - halt -p = shutdown --halt
  - poweroff = shutdown -p --poweroff
  - reboot
  - shutdown +10 "wallmesage" = 10 minutls
    - only to logged user in a tty#
    - hh:mm
    - +m
    - now +0
  - ACPI = Advanced Config and Power Interface
    - sends signal to hardware
  - wall = message
    - mesg


## 102.4 102.5 Manage Debian - Package Management
- Package: apps (files, binaries|source), bundle of softwares, man, copyright
  - Debian  = .deb
    - name_version_arch.deb
  - Red Hat = .rpm
- make = compile + install
- Download + install + update + remove + dependencies
  - apt (new), apt-get, apt-cache  = debian
  - yum, zypper                    = red hat
  
- dpkg (no network)
  - -c content
  - -I --info   version/info
  - -s --status  installed/not
  - -i install/upgrade
  - -V verify
  - -C audit (broken packages)
  - -r remove (not dependencies)
  - -S searchapp 
  - --get-selections
  - dpkg-reconfigure
- 

- apt (dpkg background)
  - /etc/apt/source.list = source/repository
  - apt-get update
  - apt-get upgrade  dont check dependencies
  - apt-get install PACKAGE
    - -f fix broken dependencies
  - apt-get remove PACKAGE
  - apt autoremove
  - apt-cache depends
- apt-file (shows uninstalled)
  - listing contents, finding

### RedHat

- rpm (not solve dependencies)
  - name.-version-Release-Arch.rpm
  - if not installed, update will install
  - -i install
  - -U upgrade
  - -q query
  - -qa list all
  - -qf which files owns
  - -e = remove (erase)
  - -V = installed/not
  - -qR = dependencies
  
- yum =handles dependencies
  - search
  - install
  - update
  - whatprovides
  - info
  - remove
  - yum/etc/yum.conf (configuration)
  - /etc/yum.repos.d
    - /etc/yum.repos 
  - yum-config-manager --add-repo
    - repolist all
    - clean packages|metadata
- dnf (fedora)
  - similar to yum
- zypper (opensuse)
  - similar apt yum
  - refresh | ref
  - search|se -i (installed)
  - in = install
  - se --provides = 
  - info
  - provides
  - verify = check dependencies
  - list-updated = show updates
  - addrepo
  - /etc/redhat-releaser
  - /etc/zypp/zzpper.conf


## 102.3 Libraries
- for LOADIN
- file with program code
- /lib/xxx/name.so.VERSION
- $LD_LIBRARY_PATH
- $PATH
- /etc/ld.so.conf
- @ = dynamic link load
- ldd /path/to/executable
- Developing
  - ldconfig = configure dynamic linker
    - list of varaibles directories
    - quick load program
    - runned by package managment
    - -v see
    - -N dont build
    - export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/our/folder

- Troubleshooting
  - ldd /path/to/exec
  - ldconfig (update)
    - -p print cacheq

## 102.6 Virtualization
- Phyisical --> Host OS --> Hypervisor (App) --> VMs
  - Hypervisor 1: replace OS on Host (windows)
  - Hypervisor 2: needs host OS (linux, vmware, dropbox)
  - network swtich
  - PV - paravirtualized = 
- Container => direkt to Host OS

- Creating VM
  - enough CPU,RAM,DU,NIC
  - grep ^flags /proc/cpuinfo | grep vmx = intel
  - grep ^flags /proc/cpuinfo | grep svm = amd
  - OVF (open virtualization format) OVA (open virtualization application)
  - /var/lib/dbus/machine-id (delete second)
  - /etc/machine-id (delete first)
  - Host name
  - NICMAC
  -  dbus-uuidgen

- Containers
  - Host System --> Host OS ---> Container Engine ==> share OS of host
  - Docker, LXD
  - Orchastration Tool: Kubernetes/k8s

- CSP = Cloud service provider
- Infrastucture as a Service (IaaS) - hardware
- Platform as a Servce (PaaS) - OS
- Software as a Service (SaaS) - Application 
- Management + Elasticity + Load Balancing + Block/object storage + networking