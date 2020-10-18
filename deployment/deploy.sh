#!/usr/bin/env bash

function generate_client_config() {
echo
echo "What is the parent CA's prefix?"
read -r parent_ca_prefix
echo "what is the parent certificate?"
root_cert=$(cat | tr -d '\n')

cat > ndncert-site-client.conf << ~EOF
{
  "ca-list":
  [
    {
      "ca-prefix": "$parent_ca_prefix",
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
echo "config file generated at ndncert-site-client.conf"
echo
}

function generate_ca_config() {
echo "Load the new configuration file for the CA"
echo "Would you like to allow email challenge for this CA? [Y/N]"
read -r allow_email_challenge
# prepare CA configuration file
cat > /usr/local/etc/ndncert/ca.conf << ~EOF
{
  "ca-prefix": "$1",
  "ca-info": "NDN Trust Anchor: $1",
  "max-validity-period": "1296000",
  "max-suffix-length": "2",
  "probe-parameters":
  [
    {"probe-parameter-key": "email"}
  ],
  "supported-challenges":
  [
~EOF
if [ "$allow_email_challenge" = 'y' ]; then
    echo '{ "challenge": "email" },' >> /usr/local/etc/ndncert/ca.conf
elif [ "$allow_email_challenge" = 'Y' ]; then
    echo '{ "challenge": "email" },' >> /usr/local/etc/ndncert/ca.conf
fi
cat >> /usr/local/etc/ndncert/ca.conf << ~EOF
    { "challenge": "pin" }
  ],
  "name-assignment":
  {
    "param": "/email"
  }
}
~EOF
echo ""
}

deployment_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ndncert_dir="$(dirname "$deployment_dir")"
current_path="$(pwd)"
cd "$ndncert_dir"

echo "Do you want to (re) compile and build NDNCERT? [Y/N]"
read -r NDNCERT_COMPILE
echo ""

case $NDNCERT_COMPILE in
             N|n)
                   echo "Okay, we'll skip compilation and build."
             ;;
             Y|y)
                   CXXFLAGS="-O2" "./waf" configure
                   "./waf"
             ;;
             *)
                   echo "Unknown option, build and install is cancelled"
                   cd "$current_path"
                   exit 1
             ;;
esac
echo "Need sudo to install NDNCERT CLI tools"
sudo "./waf" install
echo ""

echo "==================================================================="
echo "=="
echo "== deploying NDNCERT"
echo "=="
echo "==================================================================="
echo ""
echo "Are you sure [Y/n] ?"
read -r deploy

case $deploy in
             N|n)
                   echo "deployment cancelled"
                   cd "$current_path"
                   exit 1
             ;;
             Y|y)
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   cd "$current_path"
                   exit 1
             ;;
esac

echo ""
echo "==================================================================="
echo "=="
echo "== deployment started"
echo "=="
echo "==================================================================="

echo "What is the CA Prefix (eg. /example) you want to deploy?"
read -r ca_prefix
echo ""

echo "Do you want to install ndncert CA for systemd on this machine? [Y/N]"
read -r systemd_install
echo ""

case $systemd_install in
             N|n)
                   echo "We will not install systemd CA on this machine"
                   echo "Successfully finish the deployment of NDNCERT. To run NDNCERT, please use CLI ndncert-ca-server"
                   cd "$current_path"
                   exit 0
             ;;
             Y|y)
                   echo "Copying NDNCERT-CA systemd service on this machine"
		               sudo cp "$ndncert_dir/build/systemd/ndncert-ca.service" /etc/systemd/system
		               sudo chmod 644 /etc/systemd/system/ndncert-ca.service
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   cd "$current_path"
                   exit 1
             ;;
esac

echo ""
echo "ndncert-ca service requires user ndn. Will check it now :D"
if id ndn &>/dev/null; then
    echo 'ndn user account found, GOOD!'
else
    echo 'ndn user not found; adding ndn user as root'
    sudo useradd ndn
fi

echo ""
echo "ndncert-ca service requires /var/lib/ndncert-ca. Will check or create the keychain in /var/lib/ndncert-ca"
sudo mkdir -p /var/lib/ndncert-ca
sudo chown ndn /var/lib/ndncert-ca
echo '/var/lib/ndncert-ca is ready, GOOD!'

echo ""
echo "Do you want to import an exisitng safebag for $ca_prefix ? [Y/N]"
read -r USE_SAFE_BAG

case $USE_SAFE_BAG in
             N|n)
                   echo "Generating new NDN identity for $ca_prefix"
                   sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-keygen "$ca_prefix"
             ;;
             Y|y)
                   echo "Reading the safebag."
                   echo "What is the safebag file name?"
                   read -r safe_bag_path
                   echo ""

                   echo "What is the password of the safebag?"
                   read -r safe_bafg_pwd
                   echo ""

                   sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-import -i "$safe_bag_path" -P "$safe_bafg_pwd"
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   cd "$current_path"
                   exit 1
             ;;
esac

echo ""
echo "Do you want to request a certificate from a parent CA? [Y/N]"
read -r run_client
case $run_client in
             Y|y)
                  echo "Running ndncert client"
                  generate_client_config
                  ndncert-client -c ndncert-site-client.conf
                  rm ndncert-site-client.conf

                  echo "What is the new certificate name?"
                  read -r new_cert_name
                  ndnsec set-default -c "$new_cert_name"
             ;;
             *)
                   echo "Will not request a certificate. "
             ;;
esac

generate_ca_config "$ca_prefix"

echo "Do you want to start the service now? [Y/N]"
read -r start_now
case $start_now in
             N|n)
                   echo "Successfully finish the deployment of NDNCERT. You can run sudo systemctl start ndncert-ca when you want to start the service"
                   cd "$current_path"
                   exit 0
             ;;
             Y|y)
                   echo "Starting the service ndncert-ca"
                   sudo systemctl start ndncert-ca
                   sleep 2
                   echo "Reading the status of service ndncert-ca"
                   sudo systemctl status ndncert-ca
                   echo "Successfully finish the deployment of NDNCERT. You can run sudo systemctl status ndncert-ca when you want to check the status of the service"
                   cd "$current_path"
                   exit 0
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   cd "$current_path"
                   exit 1
             ;;
esac

cd "$current_path"