#!/bin/bash

if [ "$1" == "4" ]
then
  IPTABLES=iptables
elif [ "$1" == "6" ]
then
  IPTABLES=ip6tables
else
  echo "specify either 4 or 6 as a parameter for ipv4 or ipv6";
  exit -1
fi

#clear up ${IPTABLES}
sudo ${IPTABLES} -t raw -D PREROUTING -p udp --dport 9987 -j CT --notrack
sudo ${IPTABLES} -t raw -D OUTPUT -p udp --sport 9987 -j CT --notrack
sudo ${IPTABLES} -D INPUT -p udp --dport 9987 \! -f -j TS3_UDP_TRAFFIC
sudo ${IPTABLES} -D INPUT -p tcp --dport 30033 -j TS3_TCP_TRAFFIC
sudo ${IPTABLES} -D OUTPUT -p udp --sport 9987 \! -f -j OUT_TS3

sudo ${IPTABLES} -F TS3_UDP_TRAFFIC
sudo ${IPTABLES} -F TS3_UDP_TRAFFIC_AUTHORIZING
sudo ${IPTABLES} -F TS3_UDP_TRAFFIC_AUTHORIZED
sudo ${IPTABLES} -F TS3_TCP_TRAFFIC
sudo ${IPTABLES} -F TS3_ACCEPT_AUTHORIZING
sudo ${IPTABLES} -F TS3_UPDATE_AUTHORIZED
sudo ${IPTABLES} -F OUT_TS3
sudo ${IPTABLES} -F OUT_TS3_AUTHORIZING
sudo ${IPTABLES} -F OUT_TS3_AUTHORIZED
sudo ${IPTABLES} -F OUT_TS3_ACCEPT_AUTHORIZED

sudo ${IPTABLES} -X TS3_UDP_TRAFFIC
sudo ${IPTABLES} -X TS3_UDP_TRAFFIC_AUTHORIZING
sudo ${IPTABLES} -X TS3_UDP_TRAFFIC_AUTHORIZED
sudo ${IPTABLES} -X TS3_TCP_TRAFFIC
sudo ${IPTABLES} -X TS3_ACCEPT_AUTHORIZING
sudo ${IPTABLES} -X TS3_UPDATE_AUTHORIZED
sudo ${IPTABLES} -X OUT_TS3
sudo ${IPTABLES} -X OUT_TS3_AUTHORIZING
sudo ${IPTABLES} -X OUT_TS3_AUTHORIZED
sudo ${IPTABLES} -X OUT_TS3_ACCEPT_AUTHORIZED

#delete the ipset
sudo ipset destroy ts3_authorized${1}
sudo ipset destroy ts3_authorized_ft${1}
sudo ipset destroy ts3_authorizing${1}
