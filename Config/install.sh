#!/bin/bash

# First update /upgrade
echo "First updated and upgrade after fresh install"
echo "========================================================"
sudo apt-get update
sudo apt full-upgrade -y
echo "==========================Done=========================="
echo

echo "Adding current user to sudo"
echo "========================================================"
echo "${USER}        ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
#echo 'basicuser       ALL=(ALL) ALL' | sudo tee -a /etc/sudoers
echo "==========================Done=========================="
echo

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

echo "Downloading and installing google chrome"
echo "========================================================"
wget 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb' -O ~/Downloads/chrome.deb
sudo dpkg -i *.deb
sudo apt-get install -f
echo "==========================Done=========================="
echo

echo "Setting up tmux"
echo "========================================================"
sudo apt-get install xclip -y
cp ${PWD}/hacklab/Config/.tmux.conf ~/.tmux.conf
tmux source-file ~/.tmux.conf
echo "==========================Done=========================="
echo

echo "Setting up the vpn script"
echo "========================================================"
sudo cp ${PWD}/hacklab/Config/vpn /usr/bin/vpn
echo "==========================Done=========================="
echo

echo "Installing following packages: ufw, gufw, gobuster, seclists"
echo "========================================================"
sudo apt-get install ufw -y
sudo ufw enable
sudo apt-get install gufw -y
sudo apt install gobuster -y
sudo apt install seclists -y
echo "==========================Done=========================="
echo

echo "Setting up customized alias"
echo "========================================================"
touch ~/.bash_aliases 
echo 'alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"' | tee -a ~/.bash_aliases
echo 'alias start="code workspace ; vpn -ad ; tmux new -s htb"' | tee -a ~/.bash_aliases
echo 'alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' | tee -a ~/.bash_aliases
echo 'alias cme="crackmapexec"' | tee -a ~/.bash_aliases

bash ; source .bashrc ; exit

echo "# Customized alias" | tee -a ~/.zshrc 
echo 'alias up="sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"' | tee -a ~/.zshrc 
echo 'alias start="code workspace ; vpn -ad ; tmux new -s htb"' | tee -a ~/.zshrc 
echo 'alias rustscan="docker run -it --rm --name rustscan rustscan/rustscan:2.1.1"' | tee -a ~/.zshrc 
echo 'alias cme="crackmapexec"' | tee -a ~/.zshrc 
source .zshrc
echo "==========================Done=========================="
echo

echo "Rebooting the system"
echo "========================================================"
sudo reboot now
echo "==========================Done=========================="
echo
