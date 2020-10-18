#! /bin/bash

# sudo check
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo 'Please enter the /ndn certificate:(end with Ctrl-D)'
ROOT_CERT=$(cat | tr -d '\n')

# compile and install ndncert
git clone https://github.com/Zhiyi-Zhang/ndncert.git
cd ndncert
git checkout origin/v0.3
./waf configure
sudo ./waf install
sudo cp ./build/systemd/ndncert-ca.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/ndncert-ca.service

# Generate ndncert config file
echo 'Please enter the /ndn certificate:(end with Ctrl-D)'
root_cert=$(cat | tr -d '\n')

cat > ndncert-site-client.conf << ~EOF
{
  "ca-list":
  [
    {
      "ca-prefix": "/ndn",
      "ca-info": "NDN Testbed Root Trust Anchor",
      "max-validity-period": "1296000",
      "max-suffix-length": "3",
      "probe-parameters":
      [
        {"probe-parameter-key": "pin"}
      ],
      "certificate": "$root_cert"
    }
  ]
}
~EOF

#run client
sudo mkdir /var/lib/ndncert-ca
sudo chown ndn /var/lib/ndncert-ca
sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-keygen /ndn
sudo HOME=/var/lib/ndncert-ca -u ndn ndncert-client -c ndncert-site-client.conf


# prepare CA configuration file
echo 'Please enter the /ndn certificate:'
site_prefix=$(read)
cat > /usr/local/etc/ndncert/ca.conf << ~EOF
{
  "ca-prefix": "$site_prefix",
  "ca-info": "NDN Testbed Site Trust Anchor: $site_prefix",
  "max-validity-period": "1296000",
  "max-suffix-length": "2",
  "probe-parameters":
  [
    {"probe-parameter-key": "email"}
  ],
  "supported-challenges":
  [
    { "challenge": "pin" },
    { "challenge": "email" }
  ],
  "name-assignment":
  {
    "param": "/email"
  }
}
~EOF

# run the CA
sudo systemctl start ndncert-ca
sleep(2)

# check the status to make sure everything is correct
sudo systemctl status ndncert-server

