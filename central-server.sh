#!/bin/bash
#usage
# $1 is CA server IP

#run with non-root user with sudo privilege
sudo hostnamectl set-hostname central-server
cd ~
sudo apt update -y
sudo apt install openvpn -y

wget -P  ~/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz

tar xvf EasyRSA-3.0.8.tgz 
cd ~/EasyRSA-3.0.8
cp vars.example vars

sed -i 's/^#set_var/set_var/; s/California/Texas/; s/San Francisco/San Antonio/; s/me@example.net/info@motorolasolutions.com/; s/My Organizational Unit/Motorola Solutions/; ' vars

./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req server nopass

sudo cp pki/private/central-server.key /etc/openvpn

#transfer server.req to CA server
scp ~/EasyRSA-3.0.8/pki/reqs/server.req debian@$1:/tmp/

