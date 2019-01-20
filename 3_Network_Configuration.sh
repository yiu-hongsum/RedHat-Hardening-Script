#!/bin/bash
# hardening script RHEL7.5
# Date Modified 25/06/2018
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
############################
#3 Network Configuration
############################
#3.1 Network Parameters (Host Only)
############################
#3.1.1 Ensure IP forwarding is disabled (Scored)
sed -i -e "s/\(net.ipv4.ip_forward = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1
#3.1.2 Ensure packet redirect sending is disabled (Scored)
sed -i -e "s/\(net.ipv4.conf.all.send_redirects = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.send_redirects = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
############################
#3.2 Network Parameters (Host and Router)
############################
#3.2.1 Ensure source routed packets are not accepted (Scored)
sed -i -e "s/\(net.ipv4.conf.all.accept_source_route = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.accept_source_route = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
#3.2.2 Ensure ICMP redirects are not accepted (Scored)
sed -i -e "s/\(net.ipv4.conf.all.accept_redirects = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.accept_redirects = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.3 Ensure secure ICMP redirects are not accepted (Scored)
sed -i -e "s/\(net.ipv4.conf.all.secure_redirects = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.secure_redirects = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.4 Ensure suspicious packets are logged (Scored)
sed -i -e "s/\(net.ipv4.conf.all.log_martians = \).*/\11/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.log_martians = \).*/\11/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
sed -i -e "s/\(net.ipv4.icmp_echo_ignore_broadcasts = \).*/\11/" /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.2.6 Ensure bogus ICMP responses are ignored (Scored)
sed -i -e "s/\(net.ipv4.icmp_ignore_bogus_error_responses = \).*/\11/" /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
sed -i -e "s/\(net.ipv4.conf.all.rp_filter = \).*/\11/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv4.conf.default.rp_filter = \).*/\11/" /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#3.2.8 Ensure TCP SYN Cookies is enabled (Scored)
sed -i -e "s/\(net.ipv4.tcp_syncookies = \).*/\11/" /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
############################
#3.3 IPv6
############################
#3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored)
sed -i -e "s/\(net.ipv6.conf.all.accept_ra = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv6.conf.default.accept_ra = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
#3.3.2 Ensure IPv6 redirects are not accepted (Not Scored)
sed -i -e "s/\(net.ipv6.conf.all.accept_redirects = \).*/\10/" /etc/sysctl.conf
sed -i -e "s/\(net.ipv6.conf.default.accept_redirects = \).*/\10/" /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
#3.3.3 Ensure IPv6 is disabled (Not Scored)
sed -i -e "s/\(GRUB_CMDLINE_LINUX=\).*/\1\"ipv6.disable=1\"/" /etc/sysctl.conf
grub2-mkconfig > /boot/grub2/grub.cfg
############################
#3.4 TCP Wrappers
############################
#3.4.1 Ensure TCP Wrappers is installed (Scored)
yum install tcp_wrappers
#3.4.2 Ensure /etc/hosts.allow is configured (Scored) - Manual
#Run the following command to create /etc/hosts.allow :
#echo "ALL: <net>/<mask>, <net>/<mask>, ..." >/etc/hosts.allow
#where each <net>/<mask> combination (for example, "192.168.1.0/255.255.255.0") represents one network block in use by your organization that requires access to this system.
#3.4.3 Ensure /etc/hosts.deny is configured (Scored)
echo "ALL: ALL" >> /etc/hosts.deny
#3.4.4 Ensure permissions on /etc/hosts.allow are configured (Scored)
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
#3.4.5 Ensure permissions on /etc/hosts.deny are configured (Scored)
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
############################
#3.5 Uncommon Network Protocols
############################
#3.5.1 Ensure DCCP is disabled (Not Scored)
echo install dccp /bin/true >> /etc/modprobe.d/CIS.conf
#3.5.2 Ensure SCTP is disabled (Not Scored)
echo install sctp /bin/true >> /etc/modprobe.d/CIS.conf
#3.5.3 Ensure RDS is disabled (Not Scored)
echo install rds /bin/true >> /etc/modprobe.d/CIS.conf
#3.5.4 Ensure TIPC is disabled (Not Scored)
echo install tipc /bin/true >> /etc/modprobe.d/CIS.conf
############################
#3.6 Firewall Configuration
############################
#3.6.1 Ensure iptables is installed (Scored)
yum install iptables -y
#Flush the iptables
iptables -F
#3.6.2 Ensure default deny firewall policy (Scored)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
#3.6.3 Ensure loopback traffic is configured (Scored)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
#3.6.4 Ensure outbound and established connections are configured (Not Scored)
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
#3.6.5 Ensure firewall rules exist for all open ports (Scored) - Manual
#For each port identified in the audit which does not have a firewall rule establish a proper rule for accepting inbound connections:
#iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT
#3.7 Ensure wireless interfaces are disabled (Not Scored) - Manual
#Run the following command to disable any wireless interfaces:
#ip link set <interface> down
#Disable any wireless interfaces in your network configuration.
echo 3 Network Configuration Completed!