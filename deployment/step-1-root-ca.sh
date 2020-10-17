#! /bin/bash

# compile and install ndncert
git clone https://github.com/Zhiyi-Zhang/ndncert.git
cd ndncert
git checkout origin/v0.3
./waf configure
sudo ./waf install
sudo cp ./build/systemd/ndncert-ca.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/ndncert-server.service

# prepare the CA root key
sudo mkdir /var/lib/ndncert-ca
sudo chown ndn /var/lib/ndncert-ca
sudo HOME=/var/lib/ndncert -u ndn ndnsec-keygen /ndn

# prepare CA configuration file
echo -e "{\n\"ca-prefix\": \"/ndn\",\n\"ca-info\": \"NDN testbed root CA\",\n\"max-validity-period\": \"1296000\",\n\"max-suffix-length\": \"2\",\n\"supported-challenges\":\n[\n{ \"challenge\": \"pin\" }\n]\n}" > /usr/local/etc/ndncert/ca.conf

# run the CA
sudo systemctl start ndncert-server
sleep(2)

# check the status to make sure everything is correct
sudo systemctl status ndncert-server