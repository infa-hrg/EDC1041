#!/bin/bash
#Purpose: To install EDC services
#Author: hrg
host=`hostname`
host1='.net'
host2=$host$host1
echo HOSTNAME=$host2 >> /etc/sysconfig/network
iptables --flush
echo "iptables --flush" >> /etc/rc.d/rc.local
chmod +x /etc/rc.d/rc.local
privateip=`hostname -I`
echo "$privateip  $host  $host2" >> /etc/hosts
sudo rm -rf /opt/Informatica
sudo rm -rf /opt/Infa_Installer
sudo rm -rf /opt/downloads
mkdir /home/infa/.ssh/
echo " " >> /home/infa/.ssh/authorized_keys
cat /opt/keys/authorized_keys >> /home/infa/.ssh/authorized_keys
cp /opt/keys/id_rsa.pub /home/infa/.ssh/id_rsa.pub
cp /opt/keys/id_rsa /home/infa/.ssh/id_rsa
chmod 600 /home/infa/.ssh/authorized_keys /home/infa/.ssh/id_rsa /home/infa/.ssh/id_rsa.pub
sudo chown -R infa:infa /home/infa/.ssh/

mkdir /root/.ssh/
 echo " " >> /root/.ssh/authorized_keys
cat /opt/keys/authorized_keys >> /root/.ssh/authorized_keys
cp /opt/keys/id_rsa.pub /root/.ssh/id_rsa.pub
cp /opt/keys/id_rsa /root/.ssh/id_rsa
chmod 600 /root/.ssh/authorized_keys /root/.ssh/id_rsa /root/.ssh/id_rsa.pub