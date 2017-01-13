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

if [ "$2" == "" ]
then
  echo "need the interface name where client packets will enter as 2nd parameter"
  exit -1
fi
CLIENT_SIDE_IF=$2

if [ "$3" == "" ]
then
  echo "need the interface name where server is located as 3rd parameter"
  exit -1
fi
SERVER_SIDE_IF=$3

#clear up ${IPTABLES}
sudo ${IPTABLES} -t raw -D PREROUTING -i $CLIENT_SIDE_IF -p udp --dport 9987 -j CT --notrack
sudo ${IPTABLES} -t raw -D PREROUTING -i $SERVER_SIDE_IF -p udp --sport 9987 -j CT --notrack
sudo ${IPTABLES} -D FORWARD -i $CLIENT_SIDE_IF -p udp --dport 9987 ${FRAGMENT_FLAG} -j TS3_UDP_TRAFFIC
sudo ${IPTABLES} -D FORWARD -i $CLIENT_SIDE_IF -p tcp --dport 30033 -j TS3_TCP_TRAFFIC
sudo ${IPTABLES} -D FORWARD -i $SERVER_SIDE_IF -p udp --sport 9987 ${FRAGMENT_FLAG} -j OUT_TS3

sudo ${IPTABLES} -F TS3_UDP_TRAFFIC
sudo ${IPTABLES} -F TS3_UDP_TRAFFIC_AUTHORIZING
sudo ${IPTABLES} -F TS3_UDP_TRAFFIC_AUTHORIZED
sudo ${IPTABLES} -F TS3_TCP_TRAFFIC
sudo ${IPTABLES} -F TS3_ACCEPT_AUTHORIZING
sudo ${IPTABLES} -F OUT_TS3
sudo ${IPTABLES} -F OUT_TS3_AUTHORIZING
sudo ${IPTABLES} -F OUT_TS3_AUTHORIZED
sudo ${IPTABLES} -F OUT_TS3_ACCEPT_AUTHORIZED

sudo ${IPTABLES} -X TS3_UDP_TRAFFIC
sudo ${IPTABLES} -X TS3_UDP_TRAFFIC_AUTHORIZING
sudo ${IPTABLES} -X TS3_UDP_TRAFFIC_AUTHORIZED
sudo ${IPTABLES} -X TS3_TCP_TRAFFIC
sudo ${IPTABLES} -X TS3_ACCEPT_AUTHORIZING
sudo ${IPTABLES} -X OUT_TS3
sudo ${IPTABLES} -X OUT_TS3_AUTHORIZING
sudo ${IPTABLES} -X OUT_TS3_AUTHORIZED
sudo ${IPTABLES} -X OUT_TS3_ACCEPT_AUTHORIZED

#delete the ipset
sudo ipset destroy ts3_authorized${1}
sudo ipset destroy ts3_authorized_ft${1}
sudo ipset destroy ts3_authorizing${1}
