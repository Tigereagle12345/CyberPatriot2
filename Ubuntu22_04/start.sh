#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip -y

PWD=$(pwd)
DIRECTORY=$(cd `dirname $0` && pwd)

pip install -r "$DIRECTORY/requirements.txt"

echo "Finished setting up!"
