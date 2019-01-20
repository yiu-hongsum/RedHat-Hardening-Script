#!/bin/bash
# hardening script RHEL7.5
# Date Modified 21/06/2018
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
############################
#2 Services
############################
#2.1 inetd Services
#2.1.1 Ensure chargen services are not enabled (Scored)
chkconfig chargen-dgram off
chkconfig chargen-stream off
#2.1.2 Ensure daytime services are not enabled (Scored)
chkconfig daytime-dgram off
chkconfig daytime-stream off
#2.1.3 Ensure discard services are not enabled (Scored)
chkconfig discard-dgram off
chkconfig discard-stream off
#2.1.4 Ensure echo services are not enabled (Scored)
chkconfig echo-dgram off
chkconfig echo-stream off
#2.1.5 Ensure time services are not enabled (Scored)
chkconfig time-dgram off
chkconfig time-stream off
#2.1.6 Ensure tftp server is not enabled (Scored)
chkconfig tftp off
#2.1.7 Ensure xinetd is not enabled (Scored)
systemctl disable xinetd
############################
#2.2 Special Purpose Services
############################
#2.2.1 Time Synchronization
############################
#2.2.1.1 Ensure time synchronization is in use (Not Scored)
yum install ntp -y
yum install chrony -y
#2.2.1.2 Ensure ntp is configured (Scored)
echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
#Add or edit server or pool lines to /etc/ntp.conf as appropriate
#server <remote-server>
if grep -q OPTIONS /etc/sysconfig/ntpd
then
sed -i -e "s/\(OPTIONS=\).*/\1\"-u ntp:ntp\"/" /etc/sysconfig/ntpd
else
echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd
fi
#2.2.1.3 Ensure chrony is configured (Scored) - Manual
#Add or edit server or pool lines to /etc/chrony.conf as appropriate
#server <remote-server>
if grep -q OPTIONS /etc/sysconfig/chronyd
then
sed -i -e "s/\(OPTIONS=\).*/\1\"-u chrony\"/" /etc/sysconfig/chronyd
else
echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd
fi
############################
#2.2.2 Ensure X Window System is not installed (Scored) - Manual
#yum remove xorg-x11* -y
#2.2.3 Ensure Avahi Server is not enabled (Scored)
systemctl disable avahi-daemon
#2.2.4 Ensure CUPS is not enabled (Scored)
systemctl disable cups
#2.2.5 Ensure DHCP Server is not enabled (Scored)
systemctl disable dhcpd
#2.2.6 Ensure LDAP server is not enabled (Scored)
systemctl disable slapd
#2.2.7 Ensure NFS and RPC are not enabled (Scored)
systemctl disable nfs
systemctl disable nfs-server
systemctl disable rpcbind
#2.2.8 Ensure DNS Server is not enabled (Scored)
systemctl disable named
#2.2.9 Ensure FTP Server is not enabled (Scored)
systemctl disable vsftpd
#2.2.10 Ensure HTTP server is not enabled (Scored)
systemctl disable httpd
#2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)
systemctl disable dovecot
#2.2.12 Ensure Samba is not enabled (Scored)
systemctl disable smb
#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
systemctl disable squid
#2.2.14 Ensure SNMP Server is not enabled (Scored)
systemctl disable snmpd
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
sed -i -e "s/\(inet_interfaces = \).*/\1loopback-only/" /etc/postfix/main.cf
systemctl restart postfix
#2.2.16 Ensure NIS Server is not enabled (Scored)
systemctl disable ypserv
#2.2.17 Ensure rsh server is not enabled (Scored)
systemctl disable rsh.socket
systemctl disable rlogin.socket
systemctl disable rexec.socket
#2.2.18 Ensure talk server is not enabled (Scored)
systemctl disable ntalk
#2.2.19 Ensure telnet server is not enabled (Scored)
systemctl disable telnet.socket
#2.2.20 Ensure tftp server is not enabled (Scored)
systemctl disable tftp.socket
#2.2.21 Ensure rsync service is not enabled (Scored)
systemctl disable rsyncd
############################
#2.3 Service Clients
############################
#2.3.1 Ensure NIS Client is not installed (Scored)
yum remove ypbind -y
#2.3.2 Ensure rsh client is not installed (Scored)
yum remove rsh -y
#2.3.3 Ensure talk client is not installed (Scored)
yum remove talk -y
#2.3.4 Ensure telnet client is not installed (Scored)
yum remove telnet -y
#2.3.5 Ensure LDAP client is not installed (Scored)
yum remove openldap-clients -y
echo 2 Services Completed!