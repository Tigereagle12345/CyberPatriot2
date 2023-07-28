#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip -y
pip install requirements.txt

echo "Finished setting up!"
