ts3init linux netfilter module
==============================

A linux netfilter module to help filter ts3nit floods on TeamSpeak 3 servers

How to install
--------------
```
make
sudo make install
sudo depmod -a
modprobe xt_ts3init
```
Example iptables setup
------------------------------
TODO
