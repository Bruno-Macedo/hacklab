# LPIC 102 - Cheat Sheet

## 105.2 Bash Scrippting
- #!/bin/bash = shebang,hashpling,hashbang
  - scripts are executed in bash process (sub-shell)
- Running
  - same path: bash script.sh
  - exec perm: chmod u+x script.sh + ./script.sh
  - diff loct: /path/to/script.sh
  - set $PATH: script on $PATH
  - sourcing:  source script.sh | . script.sh = same shell
  - Exec cmd:ex  exec ./script
- Build commands
  - $()
  - ``
  - xargs
  - cmd=Substitution

- Chaining = both executed, no matter error
  - ;  = both executed
  - && = both must be true
  - || = either other

- Success
  - ?!
    - 0  = successfull
    - !0 =  failed = 0-255

- Flow control
  - if
```
if CONDITION
    then DO this
    else DO that
    elsif do this
fi
```
  - test: file exist/directory/empty/etc
    - test = [ -f /etc/passwd ]
    - echo $? = save results in the exit
    - 0 = true
    - 1 = false
    - 2 = error
  - Mail
    - echo "message" | mail -s "Subject" TARGET
  
  - FOR-Loop
    - seq START STOP | seq START path STOp

```
for var in a b c d e f g
do
    echo "The letter is: " $var
    sleep 1
done


for var in $(seq 1 100)
do
    echo "The letter is: " $var
    sleep 1
done
```

  - WHILE-Loop
    - always, until false
```
while [ $test ]
do
    action
done
```
  - UNTIL-Loop = if true not run
```
until COND
do
    runs while it is false
done
```

- User input/file
  - read
    - -p = prompt
    - -s = hide
  - cat file | while read LineFile do dasdada done
  - Parameters
    - $0 = name of the script
    - $1...n
    - $*.$@ = all arguments
    - $# = total of arguments
    - $! = last pid
    - $$ = current shell
    - $? = exit status
  - Arrays: 
    - declare -a SIZES
    - SIZES=(a,b,c)
  - echo
  - printf = more controlle to display

## 105.1 Shell Enviromnment
- bash
  - -l login
  - -i interactive
  - --noprofile 
  - --norc = no profile (system-wide and user)
  - --rcfile = use custom file
  - interactive login: -bash,-su
  - non-login: bash, zsh
- SKEL
  - template 
- global:
  - /etc/profile
  - /etc/profile.d
  - /etc/bashrc (ubuntu)
  - /etc/bash.bashrc (ubuntu)
- local: 
  - ~/.bash_profile
  - ~/.bash_login
  - ~/.profile
  - ~/.bashrc
  - ~/.bash_logou
- Priority: only one is runed
  - local > global
  - ~/.bash_profile, ~/.bash_login, ~/.profile
- What to do?
  - set env variables + alias + change appearance

- Alias: modifed command
  - alias -p
  - unalias CMD
  - Where set
  - alias name="script to be run"

- Functions = group of commands that runs several time
```
function func_name {
    commands    
}

func_name () {
    commands
}
```

- Env/user variables
  - set,env,printev = only env variable
  - unset variable | better change than unset
  - export PATH=$PATH:/path/to/my/target = make all available
  - set
    - echo $- = how {} works
    - set +a = turn off flag
    - set -a = turn on flag
      - -u = error/blank for non existent varaibles

## 107.1 Users and Groups
- DAC: Discretionary Access COntrol
- MAC: Mandatory Access Control
- DAC
  - Owner + Group + World
  - --- --- ---
  - getent = entries of adm db
    - /etc/nsswitch.conf = list files for getet
    - passwd username
  - groups
  - Primary group in /etc/passwd
  
- useradd | adduser = create user
  - -D = files used to create user (default)
  - -d = home directory
  - -e YYYY-MM-DD = expire
  - -f 1 = secure account, after this amount of day the account is disabled
  - /etc/passwd = account info
    - username:X password in shadow:ID:group ID:Comment:
  - /etc/shadow = password information
    - userame:password(hash):last changed:minimum days to change:days until change:warning:account deactaive:exp date
    - !! or ! = no password
    - ! or * = cannot log in
    - ! = account locked
  - /etc/group  = group information
  - /etc/gshadow = password group
  - 
- usermod: modify account
  - -c comment "blabla" username
- userdel: delete user
  - -r = also file
- groupadd (not remove from primary)
  - -g 
- references
  - /etc/default/useradd = , when shell, location of $HOME
  - /etc/login.defs = $HOME yes or no, password change, user id, group id
  - /etc/skel files are copied to $HOME

- passwords
  - passwd = my own change
  - sudo passwd username
    - -d = delete
    - -e = force change
  - -S = status
    - -1 = inactive disabled
    - 99999 = not change nedded
  - -l = lock account
  - -u = enable
- chage
  - -l aging info

- Groups
  - current group
  - primary: etc/passwd
  - newgrp = change group
  - etc/group
    - name:password(X):ID:member
  - groupadd Name_Group
    - usermod -aG Name_Group New_user
    - groupmod -n NewName OldName
    - groupdel NameGroup
  - If you dont belong to group: u need password
    - gpasswd: better to add user to group
    - 

## Jobs 107.2
- at
  - now (when), HH:MM, noon,midnight,teatime(4:00 PM)
    - June 24, MMDDYY, offset: today + 3 hours/day/months,  
  - ctr+d
  - location: sent mail message
  - -l = list
- atq = see jobs
- atrm ID = remove jobs
- /etc/at.allow = not default
  - users allowed to use
- /etc/at.deny
  - deny at

- crontab: backgroun
  - -e =create
  - -l = list
  - 
  - Minute Hour Day Month Day(Monday-Sunday) Command
  -   \-    \-  \-   \-         \-   
  - \* = every  
  - 15,45 = multiple time
  - 0 8-17/2 * * *  = every two hours between 8 and 17