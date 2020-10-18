#!/usr/bin/env bash

# Usage: ./step-1-root-ca.sh safebag-file-name password
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 safebag-file-name password" >&2
  exit 1
fi

# file name and password to a safebag TODO
SAFEBAG_FILE=$1
PWD=$2

# compile and install ndncert
git clone https://github.com/Zhiyi-Zhang/ndncert.git
cd ndncert
git checkout origin/v0.3
./waf configure
sudo ./waf install
sudo cp ./build/systemd/ndncert-ca.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/ndncert-ca.service

# prepare the CA root key
sudo mkdir /var/lib/ndncert-ca
sudo chown ndn /var/lib/ndncert-ca
sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-import -i $SAFEBAG_FILE -P $PWD

# prepare CA configuration file
echo -e "{\n\"ca-prefix\": \"/ndn\",\n\"ca-info\": \"NDN testbed root CA\",\n\"max-validity-period\": \"1296000\",\n\"max-suffix-length\": \"2\",\n\"supported-challenges\":\n[\n{ \"challenge\": \"pin\" }\n]\n}" > /usr/local/etc/ndncert/ca.conf

# run the CA
sudo systemctl start ndncert-ca
sleep(2)

# check the status to make sure everything is correct
sudo systemctl status ndncert-ca