#!/bin/bash
IPT="/sbin/iptables"
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


INET_IFACE="eth1"
LOCAL_IFACE="eth0"
LOCAL_NET="10.20.6.0/24"
LOCAL_BCAST="10.20.6.255"

logall=0
log=0
gw=1

# SI allowed ports 1755
TCP_PORTS="80 993 994 25 22 21 9000 10001 10000 4040 443 32400 1755"
UDP_PORTS="1194 5000 81"

# Localhost Interface
LO_IFACE="lo"
LO_IP="127.0.0.1"
LOGLEVEL="4"
echo "Loading Firewall Rules"

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
$IPT -N fromlan
$IPT -N badaddress
$IPT -N BLOCK

# Allow all on localhost interface
#
$IPT -A INPUT -p ALL -i $LO_IFACE -j ACCEPT
$IPT -A FORWARD -p ALL -i $LO_IFACE -j ACCEPT

#$IPT -A	BLOCK -s 173.194.55.0/24 -j DROP
#$IPT -A	BLOCK -s 206.111.0.0/24 -j DROP

#$IPT -I FORWARD -s $LOCAL_NET -d 206.111.0.0/16 -j DROP 
#$IPT -I FORWARD -s $LOCAL_NET -d 173.194.55.0/24 -j DROP 

ADDRS="111.111.111.11"


# Accept to local network IF
#
$IPT -A INPUT -i $LOCAL_IFACE -j ACCEPT
$IPT -A FORWARD -i $LOCAL_IFACE -j ACCEPT

#
# allow dhcp and dns
$IPT -A INPUT -i eth2 -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i eth2 -p udp -d 255.255.255.255 --dport 67 -j ACCEPT
$IPT -A INPUT -i eth2 -p udp --dport 53 -j ACCEPT
# allow access to eth2 from other networks
$IPT -A FORWARD -i eth2  -m state --state RELATED,ESTABLISHED -j ACCEPT
# allow data back in from eth0 -> eth2
$IPT -A FORWARD -i eth2 -o eth0 -j ACCEPT

#$IPT -A INPUT -i eth2 -j ACCEPT
#$IPT -A FORWARD -i eth2 -j ACCEPT

#$IPT -A FORWARD -i eth2 -m state --state ESTABLISHED -j ACCEPT

#$IPT -A INPUT -i eth2 -j ACCEPT
#$IPT -A FORWARD -i eth2 -o $INET_IFACE -j ACCEPT
#$IPT -A FORWARD -i eth2 -o eth1 -j DROP
#$IPT -A FORWARD -s 10.21.6.0/24 -d 10.20.6.0/24 -j ACCEPT
#$IPT -A FORWARD -s 10.20.6.0/24 -d 10.21.6.0/24 -j ACCEPT
#$IPT -A FORWARD -i eth2 -j ACCEPT

#$IPT -A FORWARD -i eth2 -j ACCEPT

if [ $gw == 1 ]
        then
	# NAT Connection
	$IPT -t nat -A POSTROUTING -o $INET_IFACE -j MASQUERADE
	$IPT -A FORWARD -i $INET_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

	# Accept incoming established connections
	#
	$IPT -A INPUT -p ALL -i $INET_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# Allow full VPN access
#
$IPT -A INPUT -i tun+ -j ACCEPT
$IPT -A FORWARD -i tun+ -j ACCEPT

if [ $log == 1 ]
	then
	$IPT -A INPUT -i tun+ -j LOG --log-prefix="iptables|tun input|"
	$IPT -A FORWARD -i tun+ -j LOG --log-prefix="iptables|tun forward|"
fi

# Allow Networks 
# Rules for the private network (accessing gateway system itself)
#
if [ $gw == 1 ]
        then
	$IPT -A INPUT -p ALL -i $LOCAL_IFACE -s $LOCAL_NET -j ACCEPT
	$IPT -A INPUT -p ALL -i $LOCAL_IFACE -d $LOCAL_BCAST -j ACCEPT
	# block lan packets when not DMZ
	$IPT -A	BLOCK	 -s 192.168.0.0/24 -j DROP
fi

# Use this to find blocked ports on another network 
#$IPT -t nat -A PREROUTING -i eth0 -p TCP --dport 1:6000 -j REDIRECT --to-port 22
if [ $log == 1 ]
        then
	$IPT -A FORWARD -i $INET_IFACE -o tun1 -m state --state RELATED,ESTABLISHED -j LOG --log-prefix="iptables|NAT|DCVPN|"
fi

#
# Allow NAT from 10.20.2. to the internet
#
if [ gw == 1 ]
	then
	$IPT -t nat -A POSTROUTING -o $INET_IFACE -s 10.20.2.0/24 -d 0/0 -j MASQUERADE
	# Allow Inbound Traffic
	$IPT -A FORWARD -i $INET_IFACE -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
	# Allow Outbound Traffic 
	$IPT -A FORWARD -i tun1 -o $INET_IFACE -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

	# This rule will prevent packet looping.
	$IPT -A FORWARD -i $INET_IFACE -o $INET_IFACE -j REJECT
fi
# This rule will prevent packet looping.
$IPT -A FORWARD -i $LOCAL_IFACE -o $LOCAL_IFACE -j REJECT

# Rules for external IF
# WEB
for PORT in $TCP_PORTS
do
	if [ $log == 1 ]
	then
		if [ $PORT != 9000 ]
		then
			$IPT -A inbound ! -s  $LOCAL_NET -p TCP --destination-port $PORT -j LOG --log-prefix="iptables"
		fi

	fi
	echo "Allowing TCP Port $PORT"
	$IPT -A inbound -p TCP -s 0/0 --destination-port $PORT -j ACCEPT
done

for PORT in $UDP_PORTS
do
	if [ $log == 1 ]
	then
		$IPT -A inbound -p UDP ! -s  $LOCAL_NET --destination-port $PORT -j LOG --log-prefix="iptables"

	fi
	echo "Allowing UDP Port $PORT"
	$IPT -A inbound -p UDP -s 0/0 --destination-port $PORT -j ACCEPT
done
#$IPT -t nat -A PREROUTING -i $INET_IFACE -p tcp --dport 1000:2000 -j REDIRECT --to-port 22
#$IPT -t nat -A PREROUTING -i $INET_IFACE -p UDP --dport 1000:1193 -j REDIRECT --to-port 1194

# Plex
iptables -t nat -A PREROUTING -p tcp -i $INET_IFACE --dport 1755 -j DNAT --to 10.20.6.100:32400
iptables -A FORWARD -p tcp -d 10.20.6.100 --dport 32400 -j ACCEPT
#$IPT -A INPUT -p TCP -i eth0 --destination-port 32400 -j ACCEPT



# Block samba rules from lan
$IPT -A fromlan -p TCP -s 0/0 --destination-port 137 -j DROP
$IPT -A fromlan -p UDP -s 0/0 --destination-port 137 -j DROP
$IPT -A fromlan -p TCP -s 0/0 --destination-port 138 -j DROP
$IPT -A fromlan -p UDP -s 0/0 --destination-port 138 -j DROP
if [ $log == 1 ] 
	then
		$IPT -A fromlan -p TCP -s 0/0 --destination-port 137 -j LOG --log-prefix="iptables ** TCP 137 **"
		$IPT -A fromlan -p UDP -s 0/0 --destination-port 137 -j LOG --log-prefix="iptables ** UDP 137 **"
		$IPT -A fromlan -p TCP -s 0/0 --destination-port 138 -j LOG --log-prefix="iptables ** TCP 138 **"
		$IPT -A fromlan -p UDP -s 0/0 --destination-port 138 -j LOG --log-prefix="iptables ** UDP 138 **"
		$IPT -A fromlan -m pkttype --pkt-type multicast -j LOG --log-prefix="iptables ** Multicast **"
fi

# Log everything 
#$IPT -A FORWARD -i $INET_IFACE -j LOG --log-prefix="iptables|ALL FWD FROM LAN|"
#$IPT -A OUTPUT -j LOG --log-prefix="iptables|ALL OUTPUT FROM LAN|"
#$IPT -A INPUT -i $INET_IFACE -j LOG --log-prefix="iptables|ALL INPUT FROM LAN|"

# Enable ping
#$IPT -A OUTPUT -p icmp --icmp-type echo-request -j DROP
$IPT -A inbound -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A inbound -p icmp --icmp-type echo-reply -j ACCEPT
$IPT -A inbound -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A inbound -p icmp --icmp-type redirect -j ACCEPT
$IPT -A inbound -p icmp --icmp-type time-exceeded -j ACCEPT
$IPT -A OUTPUT -p ICMP --icmp-type echo-request -j ACCEPT
$IPT -A OUTPUT -p ICMP --icmp-type echo-reply -j ACCEPT
# LOG things we didn't ask for LOTS
if [ $logall == 1 ] 
	then 
	$IPT -A inbound  ! -s  $LOCAL_NET -p TCP -j LOG --log-level="$LOGLEVEL" --log-prefix="iptables|TCP_DROPPED_UNSOLICITED|"
fi

# Don't know what this does
#$IPT -A inbound -p TCP -j RETURN
if [ $gw == 1 ]
	then
	$IPT -A INPUT -i $INET_IFACE -j inbound
	$IPT -A INPUT -i $INET_IFACE -j BLOCK
	$IPT -A FORWARD -i $INET_IFACE -j BLOCK
fi

# outbound rules
# Block Multicast
if [ $log == 1 ]
	then
	$IPT -A OUTPUT -m pkttype --pkt-type multicast -j LOG --log-prefix="iptables ** MULTICAST **"

	$IPT -A INPUT -i $LOCAL_IFACE -m pkttype --pkt-type broadcast -j LOG --log-prefix="iptables ** INPUT BKSTpt ** "
	$IPT -A OUTPUT -o $LOCAL_IFACE -m pkttype --pkt-type broadcast -j LOG --log-prefix="iptables ** OUTPUT BKSTpt ** "
	$IPT -A FORWARD -o $LOCAL_IFACE -m pkttype --pkt-type broadcast -j LOG --log-prefix="iptables ** fwd BKSTpt ** "

	$IPT -A OUTPUT -o $INET_IFACE -d 255.255.255.255 -j LOG --log-prefix="iptables ** output BKST ** "
	$IPT -A FORWARD -i $LOCAL_IFACE -d 255.255.255.255 -j LOG --log-prefix="iptables ** fwd BKST ** "
	$IPT -A INPUT -i $LOCAL_IFACE -d 255.255.255.255 -j LOG --log-prefix="iptables ** input BKST ** "
	$IPT -A OUTPUT -m state -p icmp --state INVALID -j LOG --log-prefix="iptables ** INVALID **"
#	$IPT -A OUTPUT -j LOG --log-level="$LOGLEVEL" --log-prefix="iptables|DROPPED#2|"
fi

# Reject any packets that do not meet the specified criteria
#
$IPT -A INPUT -p tcp -j REJECT --reject-with tcp-reset
$IPT -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
#$IPT -A FORWARD -p icmp -j DROP

# Port Forward to other internal box's
#$IPT -t nat -I PREROUTING -p tcp -i tun1 --dport 8080 -j DNAT --to 10.20.6.100:8888
#$IPT -A FORWARD -i tun1 -p tcp --dport 8080 -j ACCEPT
#$IPT -t nat -A PREROUTING -i tun1 -s 212.58.0.0/255.255.0.0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Apply rules
#
if [ $gw == 1 ]
	then
	$IPT -A INPUT -i $LOCAL_IFACE -j fromlan
fi
$IPT -A OUTPUT -m state -p icmp --state INVALID -j DROP


# Push all http through squid
#
#$IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080

for ADDR in $ADDRS
do
	echo "Blocking $ADDR"
	$IPT -I FORWARD -s $ADDR -j DROP 
	$IPT -I OUTPUT -d $ADDR -j DROP 
	$IPT -I INPUT -s $ADDR -j DROP 
done

echo "Finished Loading IPv4 Rules"
echo Loading IPV6

WAN=eth0
LAN=eth1

# Clear everything
ip6tables -F INPUT;
ip6tables -F FORWARD;
ip6tables -F OUTPUT;
# drop input and forward 
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
# allow output. 
ip6tables -P OUTPUT ACCEPT
# allow input and forward for trusted if.
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -i $LAN -j ACCEPT

ip6tables -A FORWARD -i tun1 -j ACCEPT

ip6tables -A FORWARD -i lo -j ACCEPT
ip6tables -A FORWARD -i $LAN -j ACCEPT
ip6tables -A FORWARD -i eth2 -j ACCEPT
ip6tables -A INPUT -i eth2 -j ACCEPT

# needed so you can ping the server/router
ip6tables -A INPUT -p icmpv6 -j ACCEPT
# allow items in the conntrack for server/router
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH and 9000 access to the server.  NOTE: thse do not work with the -i 
#ip6tables -A INPUT -i $WAN -p tcp --dport 80 -j ACCEPT
#ip6tables -A FORWARD -i $WAN -p tcp --dport 80 -j ACCEPT
#ip6tables -A INPUT -i $WAN -p tcp --dport ssh -j ACCEPT
#ip6tables -A INPUT -i $WAN -p tcp --dport 9000 -j ACCEPT

# enable ping, ssh for all other manchines on the network with IPV6 addresses. 
#ip6tables -A FORWARD -p icmpv6 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
ip6tables -A FORWARD -p tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 9000 -j ACCEPT
ip6tables -A INPUT -p tcp --dport ssh -j ACCEPT
# SSH is not good as many devices (APPLE TV) use default u/p for root. 
#ip6tables -A FORWARD -i $WAN -p tcp --dport ssh -j ACCEPT

# do I need this? 
#ip6tables -A FORWARD -i $LAN -o $WAN -j ACCEPT
#ip6tables -A FORWARD -i TUN1 -o $LAN -j ACCEPT
# allow connections in the conntrack to come back in. 
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# needed for DHCP, probably don't need all of these.
ip6tables -A INPUT -p UDP --dport 547 -j ACCEPT
ip6tables -A INPUT -p UDP --dport 546 -j ACCEPT
ip6tables -A FORWARD -p UDP --dport 547 -j ACCEPT
ip6tables -A FORWARD -p UDP --dport 546 -j ACCEPT
# needed for RA
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Allow router advertisements on local network segments
#for icmptype in 133 134 135 136 137
#do
#	ip6tables -A INPUT -p icmpv6 --icmpv6-type $icmptype -m hl --hl-eq 255 -j ACCEPT
#	ip6tables -A OUTPUT -p icmpv6 --icmpv6-type $icmptype -m hl --hl-eq 255 -j ACCEPT
#done
