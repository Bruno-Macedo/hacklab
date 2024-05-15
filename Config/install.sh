#!bin/bash

sudo apt-get update
sudo apt full-upgrade -y
echo 'kaliwork        ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers
echo 'basicuser       ALL=(ALL) ALL' | sudo tee -a /etc/sudoers


sudo apt install -y docker.io
sudo systemctl enable docker --now
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list 
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

sudo apt autoremove -y

wget 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb'
sudo dpkg -i *.deb
sudo apt-get install -f