#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip -y

#PWD=$(pwd)
#DIRECTORY=$(cd `dirname $0` && pwd)

#sudo -u $(logname) pip install -r "$DIRECTORY/requirements.txt"

sudo -u $(logname) pip3 install os
sudo -u $(logname) pip3 install argparse
sudo -u $(logname) pip3 install sys
sudo -u $(logname) pip3 install platform
sudo -u $(logname) pip3 install subprocess
sudo -u $(logname) pip3 install psutil
sudo -u $(logname) pip3 install crontab
sudo -u $(logname) pip3 install pexpect
sudo -u $(logname) pip3 install re

echo "Finished setting up!"
