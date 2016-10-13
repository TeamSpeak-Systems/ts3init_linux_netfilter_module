#!/bin/bash

#clear up iptables
sudo iptables -t raw -D PREROUTING -p udp --dport 9987 -j CT --notrack
sudo iptables -D INPUT -p udp --dport 9987 -j TS3_UDP_TRAFFIC
sudo iptables -D INPUT -p tcp --dport 30033 -j TS3_TCP_TRAFFIC

sudo iptables -F TS3_UDP_TRAFFIC
sudo iptables -F TS3_TCP_TRAFFIC
sudo iptables -F TS3_ACCEPT_NEW
sudo iptables -F TS3_UPDATE_AUTHORIZED

sudo iptables -X TS3_UDP_TRAFFIC
sudo iptables -X TS3_TCP_TRAFFIC
sudo iptables -X TS3_ACCEPT_NEW
sudo iptables -X TS3_UPDATE_AUTHORIZED

#delete the ipset
sudo ipset destroy ts3_authorized
