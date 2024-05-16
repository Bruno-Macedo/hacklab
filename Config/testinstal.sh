#!/bin/bash

ZSHRCFILE="$PWD/file1.txt" 
BASHALIAS="$PWD/file2.txt" 

# Aliases
UPDATE='alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"'
START='alias start="code workspace ; vpn -ad ; tmux new -s htb"'
RUSTSCAN='alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' 
BOXTEMPLATE="alias box='function boxfolder(){ cp -r /home/$USER/workspace/hacklab/room_template /home/$USER/workspace/hacklab/\$1; mv /home/$USER/workspace/hacklab/\$1/room_Template.md /home/$USER/workspace/hacklab/\$1/\$1.md; }; boxfolder'" 
CRACK='alias cme="crackmapexec"'

ARRAYALIAS=( "$UPDATE" "$START" "$RUSTSCAN" "$BOXTEMPLATE" "$CRACK") 


# Packages
PACKGES=( ufw gufw gobuster seclists )


# echo "Setting up customized alias"
# echo "========================================================"

# for f in $BASHALIAS $ZSHRCFILE
# do
#     for a in "${!ARRAYALIAS[@]}"
#     do
#     echo ${ARRAYALIAS[$a]} | tee -a $f
#     done
# done
# #touch $BASHALIAS 
# #touch $ZSHRCFILE

# echo "========================================================"
# echo

echo "Installing packages"
echo "========================================================"
for p in "${!PACKGES[@]}"
do
  echo "==> Installing ${PACKGES[$p]} <=="
  sudo apt-get install ${PACKGES[$p]} -y
  echo "==> Installation Completed <=="
  echo
done
echo "========================================================"
echo
