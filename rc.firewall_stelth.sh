#!/bin/sh
log=0
echo "Loading Firewall Rules"
/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_nat_ftp
# the module for full ftp connection tracking
/sbin/modprobe ip_conntrack_ftp
# the module for full irc connection tracking
/sbin/modprobe ip_conntrack_irc
echo "1" > /proc/sys/net/ipv4/ip_forward
# This enables SYN flood protection.
# The SYN cookies activation allows your system to accept an unlimited
# number of TCP connections while still trying to give reasonable
# service during a denial of service attack.
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# This enables dynamic address hacking.
# This may help if you have a dynamic IP address \(e.g. slip, ppp, dhcp\).
echo "1" > /proc/sys/net/ipv4/ip_dynaddr

IPT="/sbin/iptables"
INET_IFACE="eth0"

# Localhost Interface
LO_IFACE="lo"
LO_IP="127.0.0.1"

# Reset Default Policies
$IPT -P INPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -t nat -P PREROUTING ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT
$IPT -t nat -P OUTPUT ACCEPT
$IPT -t mangle -P PREROUTING ACCEPT
$IPT -t mangle -P OUTPUT ACCEPT

# Flush all rules
$IPT -F
$IPT -t nat -F
$IPT -t mangle -F
# Erase all non-default chains
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X
# Above No firewall
$IPT -P INPUT DROP
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD DROP
#Create Chain
$IPT -N inbound
$IPT -N badaddress

# Allow all on localhost interface
#$IPT -A INPUT -p ALL -i $LO_IFACE -j ACCEPT


$IPT -A INPUT -p ALL -i $INET_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rules for the private network (accessing gateway system itself)
#$IPT -A INPUT -p ALL -i $LOCAL_IFACE -s $LOCAL_NET -j ACCEPT
#$IPT -A INPUT -p ALL -i $LOCAL_IFACE -d $LOCAL_BCAST -j ACCEPT

$IPT -A INPUT -i tun+ -j ACCEPT
$IPT -A FORWARD -i tun+ -j ACCEPT


echo "Finished Loading Rules"
