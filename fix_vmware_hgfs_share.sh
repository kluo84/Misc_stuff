#git clone https://github.com/rasa/vmware-tools-patches.git
#cd vmware-tools-pathes
#./patched-open-vm-tools.sh
vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000
