#!/bin/bash
#usage
# $1 is CA server IP

#run with non-root user with sudo privilege
ssh-keygen -t rsa
ssh-copy-id debian@$1

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

sudo cp pki/private/central-server.key /etc/openvpn/

#transfer server.req to CA server
scp -i /home/debian/.ssh/id_rsa ~/EasyRSA-3.0.8/pki/reqs/server.req debian@$1:/tmp/
ssh -i /home/debian/.ssh/id_rsa debian@$1 'sudo apt update -y; wget -P  ~/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz;tar xvf EasyRSA-3.0.8.tgz; '
ssh -i /home/debian/.ssh/id_rsa debian@$1 'cp ~/EasyRSA-3.0.8/vars.example ~/EasyRSA-3.0.8/vars'
ssh -i /home/debian/.ssh/id_rsa debian@$1 'sed -i "s/^#set_var/set_var/; s/California/Texas/; s/San Francisco/San Antonio/; s/me@example.net/info@motorolasolutions.com/; s/My Organizational Unit/Motorola Solutions/; " ~/EasyRSA-3.0.8/vars'
ssh -i /home/debian/.ssh/id_rsa debian@$1 '~/EasyRSA-3.0.8/easyrsa init-pki'
ssh -i /home/debian/.ssh/id_rsa debian@$1 '~/EasyRSA-3.0.8/easyrsa build-ca nopass'
ssh -i /home/debian/.ssh/id_rsa debian@$1 'sudo cp ~/EasyRSA-3.0.8/pki/ca.crt /usr/local/share/ca-certificates/sudo update-ca-certificates;'
ssh -i /home/debian/.ssh/id_rsa debian@$1 'sudo chown debian:debian /tmp/central-server.req; ~/EasyRSA-3.0.8/easyrsa import-req /tmp/central-server.req central-server'
ssh -i /home/debian/.ssh/id_rsa debian@$1 'echo "Type YES and press Enter"; ~/EasyRSA-3.0.8/easyrsa sign-req server central-server'
scp -i /home/debian/.ssh/id_rsa debian@$1:/home/debian/EasyRSA-3-0-8/pki/issued/central-server.crt /tmp/
scp -i /home/debian/.ssh/id_rsa debian@$1:/home/debian/EasyRSA-3-0-8/pki/ca.crt /tmp/
sudo mv /tmp/{central-server,ca}.crt /etc/openvpn/
./easyrsa gen-dh
openvpn --genkey --secret ta.key
sudo cp ta.key /etc/openvpn/
sudo cp pki/dh.pem /etc/openvpn/

# generate a client certificate and key pair
mkdir -p ~/client-configs/keys
chmod -R 700 ~/client-configs
read -p "Enter OpenVPN client hostname you want to connect: " client
/home/debian/EasyRSA-3.0.8/easyrsa gen-req $client nopass
cp /home/debian/EasyRSA-3.0.8/pki/private/$client.key ~/client-configs/keys/
#transfer client request to CA for signature
scp -i /home/debian/.ssh/id_rsa /home/debian/EasyRSA-3-0-8/pki/reqs/$client.req debian@$1:/tmp/
ssh -i /home/debian/.ssh/id_rsa debian@$1 "sudo chown debian:debian /tmp/$client.req; ~/EasyRSA-3.0.8/easyrsa import-req /tmp/$client.req $client"
ssh -i /home/debian/.ssh/id_rsa debian@$1 "~/EasyRSA-3.0.8/easyrsa sign-req client $client"
scp -i /home/debian/.ssh/id_rsa debian@$1:/home/debian/EasyRSA-3-0-8/pki/issued/$client.crt /tmp
sudo chown debian:debian /tmp/$client.crt
cp /tmp/$client.crt ~/client-configs/keys/
cp ta.key ~/client-configs/keys/
cp ca.crt ~/client-configs/keys/

#configure OpenVPN Service
sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz /etc/openvpn/
sudo gzip -d /etc/openvpn/server.conf.gz
sed -i 's/^;tls-auth ta.key 0/tls-auth ta.key 0/; s/^;cipher AES-256-CBC/cipher AES-256-CBC\nauth SHA256/; s/^dh dh2048.pem/dh dh.pem/; s/^port 1194/port 443/; s/^proto udp/proto tcp/; s/^explicit-exit-notify 1/explicit-exit-notify 0/; s/^cert server.crt/cert central-server.crt/; s/^key server.key/key central-server.key/;' /etc/openvpn/server.conf
