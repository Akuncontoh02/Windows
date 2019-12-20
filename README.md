# Windows
## vncdotools
pip install vncdotools

## virt-install
### win2k19
virt-install  --connect qemu:///system  --hvm --virt-type kvm  --network=default,model=virtio  --noautoconsole  --name Win2k19-x64-GenericCloud  --disk /home/kvm/win2k19-sys.qcow2,size=80,bus=virtio,cache=none  --ram 4096  --vcpus=2  --vnc  --os-type windows  --disk path=/home/kvm/virtio-win2k19_amd64.vfd,device=floppy  --cdrom /home/kvm/isos/cn_windows_server_2019_updated_march_2019_x64_dvd_c1ffb46c.iso --boot cdrom,hd,menu=on

## virsh
virsh destroy

virsh undfine

## cockpit

## CloudResetPwdAgent
https://github.com/Huawei/CloudResetPwdAgent/archive/master.zip

## virtio driver floppy
https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win_amd64.vfd


## Windows Admin Center
https://download.microsoft.com/download/1/0/5/1059800B-F375-451C-B37E-758FFC7C8C8B/WindowsAdminCenter1910.msi
