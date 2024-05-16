#!/bin/bash

ZSHRCFILE="~/.zshrc" 
BASHALIAS="~/.bash_aliases"

# Aliases
UPDATE='alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"'
START='alias start="code workspace ; vpn -ad ; tmux new -s htb"'
RUSTSCAN='alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' 
BOXTEMPLATE="alias box='function boxfolder(){ cp -r /home/$USER/workspace/hacklab/room_template /home/$USER/workspace/hacklab/\$1; mv /home/$USER/workspace/hacklab/\$1/room_Template.md /home/$USER/workspace/hacklab/\$1/\$1.md; }; boxfolder'" 
CRACK='alias cme="crackmapexec"'

ARRAYALIAS=( "$UPDATE" "$START" "$RUSTSCAN" "$BOXTEMPLATE" "$CRACK") 

# Packages
PACKGES=( ufw gufw gobuster seclists )

sudo apt-get install ufw -y
sudo ufw enable
sudo apt-get install gufw -y
sudo apt install gobuster -y
sudo apt install seclists -y


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
echo "Downloading and installing google chrome"
echo "========================================================"
wget 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb' -O ~/Downloads/chrome.deb
sudo dpkg -i *.deb
sudo apt-get install -f
echo "==========================Done=========================="
echo

# Setting up tmux
echo "Setting up tmux"
echo "========================================================"
sudo apt-get install xclip -y
cp ${PWD}/hacklab/Config/.tmux.conf ~/.tmux.conf
tmux source-file ~/.tmux.conf
echo "==========================Done=========================="
echo

# Setting up vpn script
echo "Setting up the vpn script"
echo "========================================================"
sudo cp ${PWD}/hacklab/Config/vpn /usr/bin/vpn
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

#sudo apt-get install ufw -y
#sudo apt-get install gufw -y
#sudo apt install gobuster -y
#sudo apt install seclists -y

echo "==========================Done=========================="
sudo ufw enable
echo

# Customizing aliases
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

source .zshrc
bash ; source .bashrc ; exit
echo "==========================Done=========================="
echo

echo "Rebooting the system"
echo "========================================================"
sudo reboot now
echo "==========================Done=========================="
echo







# Update + upgrade + autoremove
##echo 'alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"' | tee -a $BASHALIAS
# Start htb vpn + vs code + tmux
##echo 'alias start="code workspace ; vpn -ad ; tmux new -s htb"' | tee -a $BASHALIAS
# Enable rustscan with docker
##echo 'alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' | tee -a $BASHALIAS
# Easier name for crackmapexec
##echo 'alias cme="crackmapexec"' | tee -a $BASHALIAS
# Easier creation of folders for boxes
##echo "alias box='function boxfolder(){ cp -r /home/$USER/workspace/hacklab/room_template /home/$USER/workspace/hacklab/\$1; mv /home/$USER/workspace/hacklab/\$1/room_Template.md /home/$USER/workspace/hacklab/\$1/\$1.md; }; boxfolder'" | tee -a $BASHALIAS




##echo 'alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"' | tee -a $ZSHRCFILE
##echo 'alias start="code workspace ; vpn -ad ; tmux new -s htb"' | tee -a $ZSHRCFILE
##echo 'alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' | tee -a $ZSHRCFILE
##echo 'alias cme="crackmapexec"' | tee -a $ZSHRCFILE
##echo "alias box='function boxfolder(){ cp -r /home/$USER/workspace/hacklab/room_template /home/$USER/workspace/hacklab/\$1; mv /home/$USER/workspace/hacklab/\$1/room_Template.md /home/$USER/workspace/hacklab/\$1/\$1.md; }; boxfolder'" | tee -a  $ZSHRCFILE
