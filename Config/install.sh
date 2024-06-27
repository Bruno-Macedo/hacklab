#!/bin/bash

ZSHRCFILE="/home/$USER/.zshrc" 
BASHALIAS="/home/$USER/.bash_aliases"

# Aliases
UPDATE='alias up="sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade && sudo apt autoremove -y"'
START='alias start="code workspace ; vpn -ad ; tmux new -s htb ; cd workspace"'
RUSTSCAN='alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' 
BOXTEMPLATE="alias box='function boxfolder(){ cp -r /home/$USER/workspace/hacklab/room_template /home/$USER/workspace/hacklab/\$1; mv /home/$USER/workspace/hacklab/\$1/room_Template.md /home/$USER/workspace/hacklab/\$1/\$1.md;  nxcdb -cw \$1; nxcdb -sw \$1;}; boxfolder'" 
CRACK='alias cme="crackmapexec"'
NETEXEC='alias nxc="netexec"'
HC='alias hc="hashcat --potfile-path $(basename "$PWD").potfile"'
TMUXT='alias tmuxt="function tmuxtarget(){ TARGET=$1; tmux setenv TARGET $TARGET && export TARGET=$TARGET ;}; tmuxtarget"' 

ARRAYALIAS=( "$UPDATE" "$START" "$RUSTSCAN" "$BOXTEMPLATE" "$CRACK" "$HC" "$TMUXT") 


# Packages
PACKGES=( ufw gufw gobuster seclists netexec)
CHROME="/home/$USER/Downloads/chrome.deb"
SCHROME="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
CODE="/home/$USER/Downloads/code.deb"
SCODE="https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64"
DISCORD="/home/$USER/Downloads/discord.deb"
SDISCORD="https://discord.com/api/download?platform=linux&format=deb"

# First update /upgrade
echo "First updated and upgrade after fresh install"
echo "========================================================"
sudo apt-get update
sudo apt full-upgrade -y
echo "==========================Done=========================="
echo

# Add current user to sudo
echo "Adding current user to sudo"
echo "========================================================"
echo "${USER}        ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
#echo 'basicuser       ALL=(ALL) ALL' | sudo tee -a /etc/sudoers
echo "==========================Done=========================="
echo

# Install and config docker and docker-ce
echo "Installing and setting up docker and docker-ce"
echo "========================================================"
sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
 sudo tee /etc/apt/sources.list.d/docker.list 
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io
echo "==========================Done=========================="
echo

# Download and install google chrome
echo "Downloading and installing google chrome, vs code and discord"
echo "========================================================"
wget $SCHROME -O $CHROME
sudo dpkg -i $CHROME
sudo apt-get install -f

wget $SCODE -O $CODE
sudo dpkg -i $CODE
sudo apt-get install -f

wget $SDISCORD -O $DISCORD
rm $CHROME $CODE $DISCORD
echo "==========================Done=========================="
echo

echo "Cloning hacklab"
echo "========================================================"
git clone git@github.com:Bruno-Macedo/hacklab.git  /home/$USER/workspace/hacklab
echo "==========================Done=========================="
echo

# Setting up tmux
echo "Setting up tmux"
echo "========================================================"
sudo apt-get install xclip -y
cp /home/$USER/workspace/hacklab/Config/.tmux.conf ~/.tmux.conf
tmux source-file ~/.tmux.conf
echo "==========================Done=========================="
echo

# Setting up vpn script
echo "Setting up the vpn script"
echo "========================================================"
sudo cp /home/$USER/workspace/hacklab/Config/vpn /usr/bin/vpn
echo "==========================Done=========================="
echo

# Setting up checkproc
echo "Setting up the checkproc script"
echo "========================================================"
sudo cp /home/$USER/workspace/scripts/checkproc /usr/bin/checkproc
echo "==========================Done=========================="
echo

# Installing usefull packages
echo "Installing following packages: ufw, gufw, gobuster, seclists"
echo "========================================================"

for p in "${!PACKGES[@]}"
do
  echo "==> Installing ${PACKGES[$p]} <=="
  sudo apt-get install ${PACKGES[$p]} -y
  echo "==> Installation Completed <=="
  echo
done

echo "==========================Done=========================="
sudo ufw enable
echo

# Customizing aliases and rebooting
echo "Setting up customized alias"
echo "========================================================"
touch $BASHALIAS 
echo "# Customized alias" | tee -a $ZSHRCFILE

for f in $BASHALIAS $ZSHRCFILE
do
  for a in "${!ARRAYALIAS[@]}"
  do
  echo ${ARRAYALIAS[$a]} | tee -a $f
  done
done

source $ZSHRCFILE 
bash -c "source $BASHALIAS" 
sudo reboot now
echo "==========================Done=========================="
echo