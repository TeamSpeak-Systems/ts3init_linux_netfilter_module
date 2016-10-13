#!/bin/bash
sudo modprobe xt_ts3init

#create an autorized ts3 client ip set.
#perhaps create the set with more than the default 1024 entries
sudo ipset create ts3_authorized hash:ip timeout 30 || { echo "ipset not installed or there is a problem with it"; exit -1; }

#create new chain that handles ts3
sudo iptables -N TS3_UDP_TRAFFIC
sudo iptables -N TS3_TCP_TRAFFIC
sudo iptables -N TS3_ACCEPT_NEW
sudo iptables -N TS3_UPDATE_AUTHORIZED

RANDOM_FILE_NAME=random.data
if [ ! -f "${RANDOM_FILE_NAME}" ]
then
  xxd -l 60 -c 60 -p /dev/urandom > "${RANDOM_FILE_NAME}" || { echo "could not use xxd to create random data"; exit -1; }
fi

RANDOM_FILE=`pwd`/${RANDOM_FILE_NAME}

#disable connection tracking for ts3 server
sudo iptables -t raw -A PREROUTING -p udp --dport 9987 -j CT --notrack

#move ts3 traffic to TS3_TRAFFIC chain, and filetransfer to TCP chain
sudo iptables -A INPUT -p udp --dport 9987 -j TS3_UDP_TRAFFIC
sudo iptables -A INPUT -p tcp --dport 30033 -j TS3_TCP_TRAFFIC

#Allow authorized clients on UDP
sudo iptables -A TS3_UDP_TRAFFIC -m set --match-set ts3_authorized src -j TS3_UPDATE_AUTHORIZED

#Allow 3.0.19 and up clients
sudo iptables -A TS3_UDP_TRAFFIC -p udp -m ts3init_get_cookie --min-client 1459504131 -j TS3INIT_SET_COOKIE --seed-file ${RANDOM_FILE}

#add new connection if cookie is valid
sudo iptables -A TS3_UDP_TRAFFIC -p udp -m ts3init_get_puzzle --check-cookie --seed-file ${RANDOM_FILE} -j TS3_ACCEPT_NEW

#drop the rest
sudo iptables -A TS3_UDP_TRAFFIC -j DROP

#add new connection to authorized src
sudo iptables -A TS3_ACCEPT_NEW -j SET --add-set ts3_authorized src
sudo iptables -A TS3_ACCEPT_NEW -p udp -j TS3INIT_RESET


#Allow authorized clients on TCP
sudo iptables -A TS3_TCP_TRAFFIC -m set --match-set ts3_authorized src -j ACCEPT
sudo iptables -A TS3_TCP_TRAFFIC -j DROP

#update timeout in set and allow traffic
sudo iptables -A TS3_UPDATE_AUTHORIZED -j SET --add-set ts3_authorized src --exist
sudo iptables -A TS3_UPDATE_AUTHORIZED -j ACCEPT

