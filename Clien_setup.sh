apt update -y
apt install git tmux vim unzip -y
wget https://raw.githubusercontent.com/kluo84/Misc_stuff/master/tmux.conf -O ~/.tmux.conf
cd ~
git clone https://github.com/kluo84/vim-prep.git ~/.vim-prep
ln -s ~/.vim-prep/vim-prep/.vim
ln -s ~/.vim-config/vim-prep/.vimrc

#set :PlugInstall!
