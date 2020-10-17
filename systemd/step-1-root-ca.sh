#! /bin/bash

# compile and install ndncert
git clone https://github.com/Zhiyi-Zhang/ndncert.git
cd ndncert
git checkout origin/v0.3
./waf configure
./waf install

# set up systemd file for linux service
sudo cp ./build/systemd/ndncert-server.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/ndncert-server.service

# update CA configuration file
echo -e "{\n\"ca-prefix\": \"/ndn\",\n\"ca-info\": \"NDN testbed root CA\",\n\"max-validity-period\": \"1296000\",\n\"max-suffix-length\": \"2\",\n\"supported-challenges\":\n[\n{ \"challenge\": \"pin\" }\n]\n}" > /usr/local/etc/ndncert/ca.conf

# sudo HOME=/var/lib/ndn/ndncert-ca -u ndn ndnsec-keygen /ndn

# prepare
mkdir /var/lib/ndn/ndncert-ca
chown ndn /var/lib/ndn/ndncert-ca

# run the CA
sudo systemctl start ndncert-server

# check the status to make sure everything is correct
sudo systemctl status ndncert-server