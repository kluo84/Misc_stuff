#!/bin/bash
display_usage() {
  echo "[+] This script is using to set up the openvpn client."
  echo "[+] Need run this script after central-server.sh script."
  echo -e "\n[+] Usage: $0 [CA Server IP address] \n"
}
if [ $# -le 0 ]
then
  display_usage
  exit 1
fi

read -p "Enter OpenVPN client hostname you want to connect: " client
cd /home/debian/EasyRSA-3.0.8/
./easyrsa init-pki
./easyrsa gen-req $client nopass
cp /home/debian/EasyRSA-3.0.8/pki/private/$client.key ~/client-configs/keys/
#transfer client request to CA for signature
scp /home/debian/EasyRSA-3.0.8/pki/reqs/$client.req debian@$1:/tmp/
ssh debian@$1 "sudo chown debian:debian /tmp/$client.req; cd /home/debian/EasyRSA-3.0.8/; ./easyrsa import-req /tmp/$client.req $client"
ssh debian@$1 "cd /home/debian/EasyRSA-3.0.8/; ./easyrsa sign-req client $client"
scp debian@$1:/home/debian/EasyRSA-3.0.8/pki/issued/$client.crt /tmp
sudo chown debian:debian /tmp/$client.crt
cp /tmp/$client.crt ~/client-configs/keys/
