#!/bin/bash
#usage
# $1 is CA server IP
#adduser debian
#usermod -aG sudo debian
#su debian
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

display_usage() {
  echo "[+] This script is using to set up the openvpn central server for remote client machines."
  echo "[+] Need to set up debian account on the CA server before run this script."
  echo -e "\n[+] Usage: $0 [CA Server IP address] \n"
}
if [ $# -le 0 ]
then
  display_usage
  exit 1
fi
#run with non-root user with sudo privilege
ssh-keygen -R $1
ssh-keygen -t rsa
ssh-copy-id debian@$1

cd ~
sudo apt update -y
sudo apt install openvpn -y

wget -P  ~/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz

tar xvf EasyRSA-3.0.8.tgz 
rm EasyRSA-3.0.8.tgz
cd ~/EasyRSA-3.0.8
cp vars.example vars

sed -i 's/^#set_var/set_var/; s/California/Texas/; s/San Francisco/San Antonio/; s/me@example.net/info@motorolasolutions.com/; s/My Organizational Unit/Motorola Solutions/; ' vars

./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req server nopass

sudo cp pki/private/server.key /etc/openvpn/

#transfer server.req to CA server
scp ~/EasyRSA-3.0.8/pki/reqs/server.req debian@$1:/tmp/
cat << EOF >> /tmp/ca.sh
sudo apt update -y
sudo apt install openvpn -y
wget -P  ~/ https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz
tar xvf EasyRSA-3.0.8.tgz
rm EasyRSA-3.0.8.tgz
cp /home/debian/EasyRSA-3.0.8/vars.example /home/debian/EasyRSA-3.0.8/vars
sed -i "s/^#set_var/set_var/; s/California/Texas/; s/San Francisco/San Antonio/; s/me@example.net/info@motorolasolutions.com/; s/My Organizational Unit/Motorola Solutions/; " /home/debian/EasyRSA-3.0.8/vars
cd /home/debian/EasyRSA-3.0.8/
./easyrsa init-pki
./easyrsa build-ca nopass
sudo cp /home/debian/EasyRSA-3.0.8/pki/ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
echo "Updated CA Cert!"
sudo chown debian:debian /tmp/server.req
./easyrsa import-req /tmp/server.req server
echo "Type YES and press Enter"
./easyrsa sign-req server server
EOF
scp -i /home/debian/.ssh/id_rsa /tmp/ca.sh debian@$1:/home/debian/
rm /tmp/ca.sh
ssh debian@$1 'chmod +x /home/debian/ca.sh; /home/debian/ca.sh' 
scp debian@$1:/home/debian/EasyRSA-3.0.8/pki/issued/server.crt /tmp/
scp debian@$1:/home/debian/EasyRSA-3.0.8/pki/ca.crt /tmp/
sudo cp /tmp/{server,ca}.crt /etc/openvpn/
echo "Done copy server.crt and ca.cert to /etc/openvpn"
echo "Generate DH key..."
./easyrsa gen-dh
openvpn --genkey --secret ta.key
echo -e "${GREEN}[+] Copy ta.key and dh.pem to /etc/openvpn${NC}"
sudo cp ta.key /etc/openvpn/
sudo cp pki/dh.pem /etc/openvpn/

# generate a client certificate and key pair
mkdir -p ~/client-configs/keys
chmod -R 700 ~/client-configs
read -p "Enter OpenVPN client hostname you want to connect: " client
/home/debian/EasyRSA-3.0.8/easyrsa gen-req $client nopass
cp /home/debian/EasyRSA-3.0.8/pki/private/$client.key ~/client-configs/keys/
#transfer client request to CA for signature
scp /home/debian/EasyRSA-3.0.8/pki/reqs/$client.req debian@$1:/tmp/
ssh debian@$1 "sudo chown debian:debian /tmp/$client.req; cd /home/debian/EasyRSA-3.0.8/; ./easyrsa import-req /tmp/$client.req $client"
ssh debian@$1 "cd /home/debian/EasyRSA-3.0.8/; ./easyrsa sign-req client $client"
scp debian@$1:/home/debian/EasyRSA-3.0.8/pki/issued/$client.crt /tmp
sudo chown debian:debian /tmp/$client.crt
cp /tmp/$client.crt ~/client-configs/keys/
cp ta.key ~/client-configs/keys/
sudo cp /etc/openvpn/ca.crt ~/client-configs/keys/

#configure OpenVPN Service
sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz /etc/openvpn/
sudo gzip -d /etc/openvpn/server.conf.gz
sudo sed -i 's/^;tls-auth ta.key 0/tls-auth ta.key 0/; s/^cipher AES-256-CBC/cipher AES-256-CBC\nauth SHA256/; s/^dh dh2048.pem/dh dh.pem/; s/^port 1194/port 443/; s/^proto udp/proto tcp/; s/^explicit-exit-notify 1/explicit-exit-notify 0\n/;' /etc/openvpn/server.conf
sudo sed -i 's/^#net.ipv4.ip_forward/net.ipv4.ip_forward/;' /etc/sysctl.conf
sudo sysctl -p
sudo apt install ufw
echo -e "${GREEN}[+]Create before.rules...${NC}"
cat << EOF >> /tmp/before.rules
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#
# Start OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# End required lines


# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp code for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
EOF
sudo cp /tmp/before.rules /etc/ufw/before.rules

sudo sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/;' /etc/default/ufw
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH
sudo ufw disable
sudo ufw enable

#start openvpn server service
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server

#set up client configuration
mkdir -p ~/client-configs/files
cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf ~/client-configs/base.conf
host_ip=$(hostname -I | awk '{print $1}')
sed -i "s/^#proto tcp/proto tcp/; s/^remote my-server-1 1194/remote $host_ip 443/; s/^cert client.crt/cert $client.crt/; s/^key client.key/key $client.key/; s/^cipher AES-256-CBC/cipher AES-256-CBC\nauth SHA256/; s/^;mute 20/;mute 20\nkey-direction 1/;" ~/client-configs/base.conf
sudo systemctl status openvpn@server
echo -e "${GREEN}[+]Check ~/client-configs/keys/ for client files${NC}"
echo -e "${GREEN}[+]DONE...${NC}"



