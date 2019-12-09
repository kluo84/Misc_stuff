apt update -y
apt install git tmux vim unzip -y
wget https://raw.githubusercontent.com/kluo84/Misc_stuff/master/tmux.conf -O ~/.tmux.conf
cd ~
wget -O ~/.vim-config https://github.com/kluo84/vim-config .vim-config
ln -s ~/.vim-config/.vim
ln -s ~/.vim-config/.vimrc

#set :PlugInstall!
vim
