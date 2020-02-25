#!/bin/bash

###SET UP GHOSTWRITER #################################
##   https://github.com/GhostManager/Ghostwriter ######
#######################################################

#Prepping
sudo apt update -y
sudo apt autoremove -y
sudo apt install docker-compose -y
sudo service docker start

cd ~
git clone https://github.com/GhostManager/Ghostwriter

cd Ghostwriter
mkdir .envs && cp -rT .envs_template .envs

# install requirements
pip3 install -r requirements/base.txt
pip3 install -r requirements/local.txt
#python manage.py migrate

# building the container
docker-compose -f local.yml up -d

docker-compose -f local.yml run --rm django /seed_data

# for production 
# docker-compose -f production.yml up -d

# Update container after a code update
# docker-compose -f local.yml stop; docker-compose -f local.yml rm -f; docker-compose -f local.yml build; docker-compose -f local.yml up -d
docker-compose -f local.yml run --rm django python manage.py createsuperuser
