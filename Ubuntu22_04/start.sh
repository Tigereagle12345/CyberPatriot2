#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip -y

sudo -u $(logname) pip3 install argparse
sudo -u $(logname) pip3 install os-sys
sudo -u $(logname) pip3 install lib-platform
pip3 uninstall crontab
pip3 install python-crontab
sudo -u $(logname) pip3 install pexpect
sudo -u $(logname) pip3 install regex

echo "Finished setting up!"
