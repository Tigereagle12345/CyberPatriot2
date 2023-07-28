#!/usr/bin/bash
echo "Setting up script..."

apt install python3 -y
apt install python3-pip -y
pip install os
pip install sys
pip install logging
pip install platform
pip install subprocess
pip install psutil
pip install crontab
pip install pexpect
pip install re

echo "Finished setting up!"
