#!/usr/bin/env bash

echo "What is the CA Prefix (eg. /example) you want to deploy?"
read CA_PREFIX
echo ""

echo "Do you want to (re) compile and build NDNCERT? [Y/N]"
read NDNCERT_COMPILE
echo ""

case $NDNCERT_COMPILE in
             N|n)
                   echo "Okay, we'll skip compilation and build."
             ;;
             Y|y)
                   cd ../ && CXXFLAGS="-O2" ./waf configure
                   ./waf
             ;;
             *)
                   echo "Unknown option, build and install is cancelled"
                   exit
             ;;
esac
echo "Need sudo to install NDNCERT CLI tools"
sudo ./waf install
echo ""

echo "==================================================================="
echo "=="
echo "== Deploying NDNCERT"
echo "=="
echo "==================================================================="
echo ""
echo "Are you sure [Y/n] ?"
read DEPLOY

case $DEPLOY in
             N|n)
                   echo "Deployment cancelled"
                   exit
             ;;
             Y|y)
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   exit
             ;;
esac

echo ""
echo "==================================================================="
echo "=="
echo "== Deployment started"
echo "=="
echo "==================================================================="

echo "Do you want to install ndncert CA for systemd on this machine? [Y/N]"
read SYSTEMD_INSTALL
echo ""

case $SYSTEMD_INSTALL in
             N|n)
                   echo "We will not install systemd CA on this machine"
                   echo "Successfully finish the deployment of NDNCERT. To run NDNCERT, please use CLI ndncert-ca-server"
                   exit
             ;;
             Y|y)
                   echo "Copying NDNCERT-CA systemd service on this machine"
		               sudo cp $(pwd)/../build/systemd/ndncert-ca.service /etc/systemd/system
		               sudo chmod 644 /etc/systemd/system/ndncert-ca.service
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   exit
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
echo "Do you want to import an exisitng safebag for ${CA_PREFIX}? [Y/N]"
read USE_SAFE_BAG

case $USE_SAFE_BAG in
             N|n)
                   echo "Generating new NDN identity for ${CA_PREFIX}"
                   sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-keygen $CA_PREFIX
             ;;
             Y|y)
                   echo "Reading the safebag."
                   echo "What is the safebag file name?"
                   read SAFE_BAG_PATH
                   echo ""

                   echo "What is the password of the safebag?"
                   read SAFE_BAG_PWD
                   echo ""

                   sudo HOME=/var/lib/ndncert-ca -u ndn ndnsec-import -i $SAFEBAG_FILE -P $PWD
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   exit
             ;;
esac

echo "Load the new configuration file for the CA"
echo -e "{\n\"ca-prefix\": \"${CA_PREFIX}\",\n\"ca-info\": \"NDNCERT CA for ${CA_PREFIX}\",\n\"max-validity-period\": \"1296000\",\n\"max-suffix-length\": \"2\",\n\"supported-challenges\":\n[\n{ \"challenge\": \"pin\" }\n]\n}" > /usr/local/etc/ndncert/ca.conf
echo ""

echo "Do you want to start the service now? [Y/N]"
read START_NOW
case $START_NOW in
             N|n)
                   echo "Successfully finish the deployment of NDNCERT. You can run sudo systemctl start ndncert-ca when you want to start the service"
                   exit
             ;;
             Y|y)
                   echo "Starting the service ndncert-ca"
                   sudo systemctl start ndncert-ca
                   sleep 2
                   echo "Reading the status of service ndncert-ca"
                   sudo systemctl status ndncert-ca
                   echo "Successfully finish the deployment of NDNCERT. You can run sudo systemctl status ndncert-ca when you want to check the status of the service"
                   exit
             ;;
             *)
                   echo "Unknown option, deployment cancelled"
                   exit
             ;;
esac
