#!/usr/bin/bash
echo "Setting up script..."

apt update -y
apt upgrade -y
apt update --fix-missing -y

apt install python3 -y
apt install python3-pip -y || apt install python-pip -y

pip3 install argparse || pip install argparse
#sudo -u $(logname) pip3 install os-sys
pip3 install lib-platform || pip install lib-platform
pip3 uninstall crontab || pip uninstall crontab
pip3 install python-crontab || pip install python-crontab
pip3 install pexpect || pip install pexpect
pip3 install regex || pip install regex

echo "Finished setting up!"

SCRIPT=$(readlink -f $0)
SCRIPTPATH="dirname $SCRIPT"

python3 "$SCRIPTPATH/main.py -v"
