#!/bin/bash

sudo apt-get update
sudo apt full-upgrade -y
echo "${USER}        ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
#echo 'basicuser       ALL=(ALL) ALL' | sudo tee -a /etc/sudoers


sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list 
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

sudo apt autoremove -y

wget 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb' -O ~/Downloads/Chrome.deb
sudo dpkg -i *.deb
sudo apt-get install -f

sudo apt-get install xclip -y

sudo cp ~/workspace/hacklab/Config/vpn /usr/bin/vpn

cp ~/workspace/hacklab/Config/.tmux.conf ~/.tmux.conf
tmux source-file ~/.tmux.conf

sudo apt-get  install ufw
sudo ufw enable
sudo apt-get install gufw

sudo apt install gobuster -y
sudo apt install seclists -y
