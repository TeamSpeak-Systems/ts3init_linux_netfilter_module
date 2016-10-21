#!/bin/bash

#This example is a more complex.
#The traffic will be split up into "unknown" / authorizing / authorized
#We use packets from the ts3 server for extra state info
#We also limit the concurrent connection to file transfer tcp port to 20/ip

sudo modprobe xt_ts3init

if [ "$1" == "4" ]
then
  IPTABLES=iptables
  IPFAMILY=inet
  FRAGMENT_FLAG="! -f "
elif [ "$1" == "6" ]
then
  IPTABLES=ip6tables
  IPFAMILY=inet6
  FRAGMENT_FLAG=""
else
  echo "specify either 4 or 6 as a parameter for ipv4 or ipv6";
  exit -1
fi

#create an autorized ts3 client ip set.
#perhaps create the set with more than the default 1024 entries
sudo ipset create ts3_authorizing${1} hash:ip,port family ${IPFAMILY} timeout 8 || { echo "ipset not installed or there is a problem with it (1)"; exit -1; }
sudo ipset create ts3_authorized${1} hash:ip,port family ${IPFAMILY} timeout 30 || { echo "ipset not installed or there is a problem with it (2)"; exit -1; }
sudo ipset create ts3_authorized_ft${1} hash:ip family ${IPFAMILY} timeout 30 || { echo "ipset not installed or there is a problem with it (3)"; exit -1; }

#create new chains that handles ts3
sudo ${IPTABLES} -N TS3_UDP_TRAFFIC
sudo ${IPTABLES} -N TS3_UDP_TRAFFIC_AUTHORIZING
sudo ${IPTABLES} -N TS3_UDP_TRAFFIC_AUTHORIZED
sudo ${IPTABLES} -N TS3_TCP_TRAFFIC
sudo ${IPTABLES} -N TS3_ACCEPT_AUTHORIZING
sudo ${IPTABLES} -N OUT_TS3
sudo ${IPTABLES} -N OUT_TS3_AUTHORIZING
sudo ${IPTABLES} -N OUT_TS3_AUTHORIZED
sudo ${IPTABLES} -N OUT_TS3_ACCEPT_AUTHORIZED


RANDOM_FILE_NAME=random.data
if [ ! -f "${RANDOM_FILE_NAME}" ]
then
  xxd -l 60 -c 60 -p /dev/urandom > "${RANDOM_FILE_NAME}" || { echo "could not use xxd to create random data"; exit -1; }
fi

RANDOM_FILE=`pwd`/${RANDOM_FILE_NAME}

#disable connection tracking for ts3 client->server
sudo ${IPTABLES} -t raw -A PREROUTING -p udp --dport 9987 -j CT --notrack

#disable connection tracking for ts3 server->client
sudo ${IPTABLES} -t raw -A OUTPUT -p udp --sport 9987 -j CT --notrack

#move ts3 traffic to TS3_UDP_TRAFFIC chain (do not allow fragments)
sudo ${IPTABLES} -A INPUT -p udp --dport 9987 ${FRAGMENT_FLAG} -j TS3_UDP_TRAFFIC

#move filetransfer to TS3_TCP_TRAFFIC chain
sudo ${IPTABLES} -A INPUT -p tcp --dport 30033 -j TS3_TCP_TRAFFIC

#move authorized clients to TS3_UDP_TRAFFIC_AUTHORIZED chain
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC -m set --match-set ts3_authorized${1} src,src -j TS3_UDP_TRAFFIC_AUTHORIZED

#move authorizing clients to TS3_UDP_TRAFFIC_AUTHORIZING chain
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC -m set --match-set ts3_authorizing${1} src,src -j TS3_UDP_TRAFFIC_AUTHORIZING

#Allow 3.0.19 and up clients. If its get cookie, send back a cookie
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC -p udp -m ts3init_get_cookie --min-client 1459504131 -j TS3INIT_SET_COOKIE --random-seed-file ${RANDOM_FILE}

#add new connection if cookie is valid
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC -p udp -m ts3init_get_puzzle --check-cookie --random-seed-file ${RANDOM_FILE} -j TS3_ACCEPT_AUTHORIZING

#drop the rest
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC -j DROP

#accept autorized/authorizing. Here is the time to rate limit per ip for autorized (connected) streams
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC_AUTHORIZED -j ACCEPT

#accept autorized/authorizing. Here is the time to rate limit per ip for authorizing (ip checked, but not connected)
sudo ${IPTABLES} -A TS3_UDP_TRAFFIC_AUTHORIZING -j ACCEPT

#add new connection to authorizing src, and send the ts3 server a get cookie request
sudo ${IPTABLES} -A TS3_ACCEPT_AUTHORIZING -j SET --add-set ts3_authorizing${1} src,src
sudo ${IPTABLES} -A TS3_ACCEPT_AUTHORIZING -p udp -j TS3INIT_GET_COOKIE

#Allow authorized clients on TCP only
sudo ${IPTABLES} -A TS3_TCP_TRAFFIC -m set ! --match-set ts3_authorized_ft${1} src,src -j DROP

#only allow 20 connections
sudo ${IPTABLES} -A TS3_TCP_TRAFFIC -p tcp --syn -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

#accept
sudo ${IPTABLES} -A TS3_TCP_TRAFFIC -j ACCEPT

#watch server->client traffic
sudo ${IPTABLES} -A OUTPUT -p udp --sport 9987 ${FRAGMENT_FLAG} -j OUT_TS3

#Move clients in the authorized phase to the OUT_TS3_AUTHORIZED chain.
sudo ${IPTABLES} -A OUT_TS3 -m set --match-set ts3_authorized${1} dst,dst -j OUT_TS3_AUTHORIZED
#Move clients in the authorizing phase to the OUT_TS3_AUTHORIZING chain.
sudo ${IPTABLES} -A OUT_TS3 -m set --match-set ts3_authorizing${1} dst,dst -j OUT_TS3_AUTHORIZING
#These are packets from TS3INIT_SET_COOKIE
sudo ${IPTABLES} -A OUT_TS3 -j ACCEPT

#Is this still ts3init (not fully connected)
sudo ${IPTABLES} -A OUT_TS3_AUTHORIZING -p udp -m ts3init --server -j ACCEPT
#else this connection is accepeted(authorized) now
sudo ${IPTABLES} -A OUT_TS3_AUTHORIZING -j OUT_TS3_ACCEPT_AUTHORIZED

#update/add timeout in set and allow traffic
sudo ${IPTABLES} -A OUT_TS3_AUTHORIZED -j SET --add-set ts3_authorized${1} dst,dst --exist
sudo ${IPTABLES} -A OUT_TS3_AUTHORIZED -j SET --add-set ts3_authorized_ft${1} dst --exist
sudo ${IPTABLES} -A  OUT_TS3_AUTHORIZED -j ACCEPT

#accept connection as authorized. Remove from authorizing and treat as accepted
sudo ${IPTABLES} -A OUT_TS3_ACCEPT_AUTHORIZED -j SET --del-set ts3_authorizing${1} dst,dst
sudo ${IPTABLES} -A OUT_TS3_ACCEPT_AUTHORIZED -j OUT_TS3_AUTHORIZED

