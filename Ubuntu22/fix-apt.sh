#!/usr/bin/bash

echo "My Script To Fix APT (Apache Package Manager)"
echo "Make Sure To Run With Sudo!"

# Configure dpkg
dpkg --configure -a

# Add Google's DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null

apt-get update -y
apt-get upgrade -y
apt-get update --fix-missing -y
apt-get dist-upgrade -y

apt-get install software-properties-common -y

add-apt-repository main -y
add-apt-repository universe -y
add-apt-repository multiverse -y
add-apt-repository restricted -y

apt-get update -y
apt-get upgrade -y
apt-get --fix-missing update -y
apt-get dist-upgrade -y

apt-get autoremove -y

