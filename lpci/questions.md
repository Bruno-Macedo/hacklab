

QUESTION 2
Which of the following information is stored within the BIOS? (Choose TWO correct answers.)
**A. Boot device order**
**B. Linux kernel version**
C. Timezone
D. Hardware configuration  xxxxxxxxxxxx
E. The system's hostname

QUESTION 3
Which of the following commands reboots the system when using SysV init? (Choose TWO correct answers.)
**A. shutdown -r now**
B. shutdown -r "rebooting"
C. telinit 6 xxxxxxxxxxxxx
**D. telinit 0**
E. shutdown -k now "rebooting"

QUESTION 4
Which of the following are init systems used within Linux systems? (Choose THREE correct answers.)
A. startd
**B. systemd**
**C. Upstart** 
**D. SysInit** 
E. SysV init xxxxxxxxxxx

QUESTION 5
SIMULATION
Which file in the /proc filesystem lists parameters passed from the bootloader to the kernel? (Specify the file name only without any path.)
**runlevel**

QUESTION 6
What information can the lspci command display about the system hardware? (Choose THREE correct answers.)
A. Device IRQ settings xxxxxxxxx
**B. PCI bus speed**
C. System battery type
**D. Device vendor identification** 
**E. Ethernet MAC address**



QUESTION 8
What is the first program that is usually started, at boot time, by the Linux kernel when using SysV init?
A. /lib/init.so
B. /sbin/init xxxxxxxxxxx
C. /etc/rc.d/rcinit
D. /proc/sys/kernel/init 
**E. /boot/init**



QUESTION 15
Which of the following commands can be used to download the RPM package kernel without installing it?
**A. yum download --no-install kernel** 
B. yumdownloader kernel xxxxxxxxxxx
C. rpm --download --package kernel
D. rpmdownload kernel


QUESTION 20
SIMULATION
Which world-writable directory should be placed on a separate partition in order to prevent users from being able to fill up the / filesystem? (Specify the full path to the directory.)
**/home**

QUESTION 21
Which RPM command will output the name of the package which supplied the file /etc/exports?
A. rpm -F /etc/exports 
B. rpm -qf /etc/exports  xxxxxxxxx
C. rpm -Kl /etc/exports 
D. rpm -qp /etc/exports 
**E. rpm -qi /etc/exports**

QUESTION 22
SIMULATION
In which directory must definition files be placed to add additional repositories to yum?
**/etc/yum/source.list.d**


QUESTION 28
SIMULATION
Which Debian package management tool asks the configuration questions for a specific already installed package just as if the package were being installed for the first time? (Specify ONLY the command without any path or parameters.)
**dpkg**

QUESTION 29
Which of the following commands overwrites the bootloader located on /dev/sda without overwriting the partition table or any data following it?
**A. dd if=/dev/zero of=/dev/sda bs=512**
B. dd if=/dev/zero of=/dev/sda bs=512 count=1 
C. dd if=/dev/zero of=/dev/sda bs=440 count=1
D. dd if=/dev/zero of=/dev/sda bs=440

QUESTION 30
Which of the following commands can be used to create a USB storage media from a disk image?
A. gdisk 
B. dd
C. cc
**D. fdisk**
E. mount


QUESTION 36
SIMULATION
Which signal is missing from the following command that is commonly used to instruct a daemon to reinitialize itself, including reading configuration files?


QUESTION 38
Immediately after deleting 3 lines of text in vi and moving the cursor to a different line, which single character command will insert the deleted content below the current line?
**A. i (lowercase)** 
B. P (uppercase) 
C. p (lowercase) 
D. U (uppercase) 
E. u (lowercase)




QUESTION 41
Which of the following commands will send output from the program myapp to both standard output (stdout) and the file file1.log?
A. cat < myapp | cat > file1.log 
B. myapp 0>&1 | cat > file1.log 
C. myapp | cat > file1.log
D. myapp | tee file1.log
**E. tee myapp file1.log**


QUESTION 47
What is the default action of the split command on an input file?
A. It will break the file into new files of 1,024 byte pieces each.
B. It will break the file into new files of 1,000 line pieces each.
C. It will break the file into new files of 1,024 kilobyte pieces each.
**D. It will break the file into new files that are no more than 5% of the **size of the original file.****



QUESTION 53
In the vi editor, how can commands such as moving the cursor or copying lines into the buffer be issued multiple times or applied to multiple rows? 
A. By using the command :repeat followed by the number and the command.
B. By specifying the number right in front of a command such as 4l or 2yj.
C. By selecting all affected lines using the shift and cursor keys before applying the command.
**D. By issuing a command such as :set repetition=4 which repeats every subsequent command 4 times.**


QUESTION 55
SIMULATION
Which Bash environment variable defines in which file the user history is stored when exiting a Bash process? (Specify ONLY the variable name.)
**$HIST_FILE**


QUESTION 60
From a Bash shell, which of the following commands directly executes the instruction from the file /usr/local/bin/runme.sh without starting a subshell? (Please select TWO answers.)
A. source /usr/local/bin/runme.sh 
B. . /usr/local/bin/runme.sh
**C. /bin/bash /usr/local/bin/runme.sh**
**D. /usr/local/bin/runme.sh**
E. run /usr/local/bin/runme.sh






QUESTION 63
Which of the following shell redirections will write standard output and standard error output to a file named filename?

**A. 2>&1 >filename** 
B. >filename 2>&1 
C. 1>&2>filename 
D. >>filename
E. 1&2>filename

QUESTION 64
In the vi editor, which of the following commands will copy the current line into the vi buffer?
A. c 
B. cc 
C. 1c 
D. yy 
**E. 1y**



QUESTION 67
Which of the following commands will reduce all consecutive spaces down to a single space?
A. tr '\s' ' ' < a.txt > b.txt 
**B. tr -c ' ' < a.txt > b.txt**
C. tr -d ' ' < a.txt > b.txt 
D. tr -r ' ' '\n' < a.txt > b.txt 
E. tr -s ' ' < a.txt > b.txt





QUESTION 71
Which of the following signals is sent to a process when the key combination CTRL+C is pressed on the keyboard?
A. SIGTERM 
B. SIGINT 
C. SIGSTOP 
**D. SIGKILL**





QUESTION 78
When running the command
sed -e "s/a/b/" /tmp/file >/tmp/file
While /tmp/file contains data, why is /tmp/file empty afterwards?
A. The file order is incorrect. The destination file must be mentioned before the command to ensure redirection.
**B. The command sed did not match anything in that file therefore the output is empty.**
C. When the shell establishes the redirection it overwrites the target file before the redirected command starts and opens it for reading. 
D. Redirection for shell commands do not work using the > character. It only works using the | character instead.



QUESTION 81
Which of the following are valid stream redirection operators within Bash? (Choose THREE correct answers.)
**A. <** 
B. <<< 
**C. >**
D. >>> 
**E. %>**



QUESTION 83
After moving data to a new filesystem, how can the former path of the data be kept intact in order to avoid reconfiguration of existing applications? (Choose TWO correct answers.)
A. By creating an ACL redirection from the old to the new path of the data. 
**B. By creating a hard link from the old to the new path of the data.**
C. By creating a symbolic link from the old to the new path of the data.
D. By running the command touch on the old path.
**E. By mounting the new filesystem on the original path of the data.**






QUESTION 92
Which of the following commands changes the number of days before the ext3 filesystem on /dev/sda1 has to run through a full filesystem check while booting?
**A. tune2fs -d 200 /dev/sda1**
B. tune2fs -c 200 /dev/sda1
C. tune2fs -i 200 /dev/sda1
D. tune2fs -n 200 /dev/sda1
E. tune2fs --days 200 /dev/sda1

QUESTION 93
Which type of filesystem is created by mkfs when it is executed with the block device name only and without any additional parameters?
A. ext2 
B. ext3 
**C. ext4**
D. XFS 
E. VFAT

QUESTION 94
How many fields are in a syntactically correct line of /etc/fstab?
A. 3 
B. 4 
**C. 5** 
D. 6 
E. 7


QUESTION 95
SIMULATION
Which command is used to create and initialize the files used to store quota information? (Specify ONLY the command without any path or parameters.)
????????????????


QUESTION 97
Creating a hard link to an ordinary file returns an error. What could be the reason for this?
A. The source file is hidden.
**B. The source file is read-only.**
C. The source file is a shell script.
D. The source file is already a hard link.
E. The source and the target are on different filesystems.


QUESTION 99
Which of the following commands will change the quota for a specific user? 
A. edquota
B. repquota 
C. quota -e
**D. quota**




QUESTION 102
What is the purpose of the Filesystem Hierarchy Standard?
A. It is a security model used to ensure files are organized according to their permissions and accessibility. 
**B. It provides unified tools to create, maintain and manage multiple filesystems in a common way.**
C. It defines a common internal structure of inodes for all compliant filesystems.
D. It is a distribution neutral description of locations of files and directories.


2	Correct Answer: AD
3	Correct Answer: AC
4	Correct Answer: BCE Section: System Architecture Explanation
5	Correct Answer: cmdline -or- /proc/cmdline
6	Correct Answer: ABD Section: System Architecture Explanation

8	Correct Answer: B

15	Correct Answer: B

20	Correct Answer: /tmp -or- tmp -or- /var/tmp -or- /tmp/ -or- /var/tmp/ Section: Linux Installation and Package Management Explanatio
21	Correct Answer: B
22	Correct Answer: /etc/yum.repos.d -or- /etc/yum.repos.d/ -or- yum.repos.d -or- yum.repos.d/

28	Correct Answer: dpkg-reconfigure
29	Correct Answer: C
30	Correct Answer: B

36	Correct Answer: HUP -or- SIGHUP -or- 1 Section: GNU and Unix Commands Explanation

38	Correct Answer: C


41	Correct Answer: D


47	Correct Answer: B

53	Correct Answer: B

55	Correct Answer: HISTFILE


60	Correct Answer: AB

63	Correct Answer: B
64	Correct Answer: D


67	Correct Answer: E

71	Correct Answer: B

78	Correct Answer: C


81	Correct Answer: ABC

83	Correct Answer: CE




92	Correct Answer: C
93	Correct Answer: A
94	Correct Answer: D
95	Correct Answer: quotacheck

97	Correct Answer: E

99	Correct Answer: A
100	Correct Answer: C
101	Correct Answer: AC
102	Correct Answer: D









