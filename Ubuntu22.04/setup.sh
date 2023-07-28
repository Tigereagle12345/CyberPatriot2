#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip
pip install -r requirements.txt

echo "Finished setting up!"
