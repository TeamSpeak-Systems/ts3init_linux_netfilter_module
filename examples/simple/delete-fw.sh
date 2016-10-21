#!/bin/bash

if [ "$1" == "4" ]
then
  IPTABLES=iptables
  FRAGMENT_FLAG="! -f "
elif [ "$1" == "6" ]
then
  IPTABLES=ip6tables
  FRAGMENT_FLAG=""
else
  echo "specify either 4 or 6 as a parameter for ipv4 or ipv6";
  exit -1
fi

#clear up ${IPTABLES}
sudo ${IPTABLES} -t raw -D PREROUTING -p udp --dport 9987 -j CT --notrack
sudo ${IPTABLES} -D INPUT -p udp --dport 9987 ${FRAGMENT_FLAG} -j TS3_UDP_TRAFFIC
sudo ${IPTABLES} -D INPUT -p tcp --dport 30033 -j TS3_TCP_TRAFFIC

sudo ${IPTABLES} -F TS3_UDP_TRAFFIC
sudo ${IPTABLES} -F TS3_TCP_TRAFFIC
sudo ${IPTABLES} -F TS3_ACCEPT_NEW
sudo ${IPTABLES} -F TS3_UPDATE_AUTHORIZED

sudo ${IPTABLES} -X TS3_UDP_TRAFFIC
sudo ${IPTABLES} -X TS3_TCP_TRAFFIC
sudo ${IPTABLES} -X TS3_ACCEPT_NEW
sudo ${IPTABLES} -X TS3_UPDATE_AUTHORIZED

#delete the ipset
sudo ipset destroy ts3_authorized${1}
