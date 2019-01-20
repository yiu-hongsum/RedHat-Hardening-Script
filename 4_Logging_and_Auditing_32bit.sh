#!/bin/bash
#CIS RedHat Enterprise Linux 7 Benchmark
#v2.2.0 - 27-012-2017
#author Yiu Hong Sum
#date 21/06/2018'
#sudo yum install dos2unix 
#cat /etc/audit/auditd.conf
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
######################################################################
#4.1.1.1 Ensure Audit Log Storage Size is Configured (Not Scored)
#Set the max_log_file parameter in /etc/audit/auditd.conf max_log_file = <MB>
#Note: MB is the number of MegaBytes the file can be"
sed -i "s/\(max_log_file = \).*/\1100/" /etc/audit/auditd.conf
#\(max_log_file =\).*/\1 this command checks for any value like a wildcard
#note that max_log_file is in terms of MB. By default, auditd will max out the log fields at 5MB and retain only 4 copies of them. 
#Older version will be deleted
#4.1.1.2 Ensure System is disabled when audit logs are full (Scored) 	
sed -i "s/\(space_left_action = \).*/\1email/" /etc/audit/auditd.conf
sed -i "s/\(action_mail_acct = \).*/\1root/" /etc/audit/auditd.conf
sed -i "s/\(admin_space_left_action = \).*/\1halt/" /etc/audit/auditd.conf
#4.1.1.3 Ensure audit logs are not automatically deleted (Scored)
sed -i "s/\(max_log_file_action = \).*/\1keep_logs/" /etc/audit/auditd.conf
#4.1.2 Ensure auditd Service is Enabled (Scored) 	
chkconfig auditd on
#4.1.3 Ensure Auditing for processes that start prior to auditd is enabled (Scored)
GRUB_CMDLINE_LINUX="audit=1"
sed -i "s/\(GRUB_CMDLINE_LINUX=\).*/\1\"audit=1\"/" /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
#4.1.4 Ensure events that modify date and time information are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change
EOM
#4.1.5 Ensure events that modify user/group information are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity
EOM
#4.1.6 Ensure events that modify the system network environment are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale 
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
EOM
#4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /etc/selinux/ -p wa -k MAC-policy 
-w /usr/share/selinux/ -p wa -k MAC-policy
EOM
#4.1.8 Ensure login and logout events are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /var/log/lastlog -p wa -k logins 
-w /var/run/faillock/ -p wa -k logins
EOM
#4.1.9 Ensure session initiation information is collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k logins 
-w /var/log/btmp -p wa -k logins
EOM
#4.1.10 Ensure discretionary access control permission modification events are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 
-k perm_mod
EOM
#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOM
#4.1.12 Ensure use of privileged commands is collected (Scored) - Manual
#Replace PART with a list of paritions where programs can be executed from the system
#echo "#4.1.12" >> /etc/audit/audit.rules
#find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
#4.1.13 Ensure successful file system mounts are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOM
#4.1.14 Ensure file deletion events by users are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOM
#4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /etc/sudoers -p wa -k scope 
-w /etc/sudoers.d/ -p wa -k scope
EOM
#4.1.16 Ensure system administrator actions (sudolog) are collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /var/log/sudo.log -p wa -k actions
EOM
#4.1.17 Ensure kernel module loading and unloading is collected (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules 
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOM
#4.1.18 Ensure the audit configuration is immutable (Scored)
cat << 'EOM' >> /etc/audit/audit.rules
-e 2
EOM
service auditd reload
#4.2.1.1 Ensure rsyslog Service is enabled (Scored)
systemctl enable rsyslog
#4.2.1.2 Ensure logging is configured (Not Scored) - Manual
#Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment:
#echo "*.emerg :omusrmsg:*" >> /etc/rsyslog.conf
#echo "mail.* -/var/log/mail" >> /etc/rsyslog.conf
#echo "mail.info -/var/log/mail.info" >> /etc/rsyslog.conf
#echo "mail.warning -/var/log/mail.warn" >> /etc/rsyslog.conf
#echo "mail.err /var/log/mail.err" >> /etc/rsyslog.conf
#echo "news.crit -/var/log/news/news.crit" >> /etc/rsyslog.conf
#echo "news.err -/var/log/news/news.err" >> /etc/rsyslog.conf
#echo "news.notice -/var/log/news/news.notice" >> /etc/rsyslog.conf
#echo "*.=warning;*.=err -/var/log/warn" >> /etc/rsyslog.conf
#echo "*.crit /var/log/warn" >> /etc/rsyslog.conf
#echo "*.*;mail.none;news.none -/var/log/messages" >> /etc/rsyslog.conf
#echo "local0,local1,local2,local3,local4,local5,local6,local7.* -/var/log/localmessages" >> /etc/rsyslog.conf
# Execute the following command to restart rsyslogd
pkill -HUP rsyslogd
#4.2.1.3 Ensure rsyslog default file permissions configured (Scored)
# touch <logfile>
# chown root:root <logfile> 
# chmod og-rwx <logfile>
touch /var/log/messages
chown root:root /var/log/messages
chmod og-rwx /var/log/messages
touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log
touch /var/log/daemon.log
chown root:root /var/log/daemon.log
chmod og-rwx /var/log/daemon.log
touch /var/log/syslog
chown root:root /var/log/syslog
chmod og-rwx /var/log/syslog
touch /var/log/unused.log
chown root:root /var/log/unused.log
chmod og-rwx /var/log/unused.log
#$FileCreateMode 0640
#4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored) - Manual
#Edit the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and add the following line (where loghost.example.com is the name of your central log host).
#*.* @@loghost.example.com
#@@ directs rsyslogto use TCP to send log messages to the server, which is a more reliable transport mechanism than the default UDP protocol.
pkill -HUP rsyslogd
#4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)
#For hosts that are designated as log hosts, edit the /etc/rsyslog.conf file and un-comment or add the following lines:
echo "$ModLoad imtcp" >> /etc/rsyslog.conf
echo "$InputTCPServerRun 514" >> /etc/rsyslog.conf
#For hosts that are not designated as log hosts, edit the /etc/rsyslog.conf file and comment or remove the following lines:
#echo "$ModLoad imtcp" >> /etc/rsyslog.conf
#echo "$InputTCPServerRun 514" >> /etc/rsyslog.conf
pkill -HUP rsyslogd
#4.2.2.x This section only applies if syslog-ng is installed on the system.
#4.2.2.1 Ensure syslog-ng service is enabled (Scored) - Manual
#systemctl enable syslog-ng
#4.2.2.2 Ensure logging is configured (Not Scored) - Manual
#Edit the log lines in the /etc/syslog-ng/syslog-ng.conf file as appropriate for your environment:
#log { source(src); source(chroots); filter(f_console); destination(console); }; 
#log { source(src); source(chroots); filter(f_console); destination(xconsole); }; 
#log { source(src); source(chroots); filter(f_newscrit); destination(newscrit); }; 
#log { source(src); source(chroots); filter(f_newserr); destination(newserr); }; 
#log { source(src); source(chroots); filter(f_newsnotice); destination(newsnotice); };
#log { source(src); source(chroots); filter(f_mailinfo); destination(mailinfo); }; 
#log { source(src); source(chroots); filter(f_mailwarn); destination(mailwarn); }; 
#log { source(src); source(chroots); filter(f_mailerr); destination(mailerr); };
#log { source(src); source(chroots); filter(f_mail); destination(mail); }; 
#log { source(src); source(chroots); filter(f_acpid); destination(acpid); flags(final); }; 
#log { source(src); source(chroots); filter(f_acpid_full); destination(devnull); flags(final); }; 
#log { source(src); source(chroots); filter(f_acpid_old); destination(acpid); flags(final); }; 
#log { source(src); source(chroots); filter(f_netmgm); destination(netmgm); flags(final); }; 
#log { source(src); source(chroots); filter(f_local); destination(localmessages); }; 
#log { source(src); source(chroots); filter(f_messages); destination(messages); }; 
#log { source(src); source(chroots); filter(f_iptables); destination(firewall); }; 
#log { source(src); source(chroots); filter(f_warn); destination(warn); };
#pkill -HUP syslog-ng
#4.2.2.3 Ensure syslog-ng default file permissions configured (Scored) - Manual
#options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };
#4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Not Scored) - Manual
#Edit the /etc/syslog-ng/syslog-ng.conf file and add the following lines (where logfile.example.com is the name of your central log host).
#destination logserver { tcp("logfile.example.com" port(514)); }; log { source(src); destination(logserver); };
#pkill -HUP syslog-ng
#4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored) - Manual
#source net{ tcp(); }; 
#destination remote { file("/var/log/remote/${FULLHOST}-log"); }; 
#log { source(net); destination(remote); };
#pkill -HUP syslog-ng
#4.2.3 Ensure rsyslog or syslog-ng is installed (Scored) - Manual
#Install rsyslog or syslog-ng using one of the following commands:
yum install rsyslog -y
#yum install syslog-ng
#The syslog-ng package requires the EPEL7 and Optional repositories be enabled.
#4.2.4 Ensure permissions on all logfiles are configured (Scored)
find /var/log -type f -exec chmod g-wx,o-rwx {} +
#4.3 Ensure logrotate is configured (Not Scored) - Manual
#Edit /etc/logrotate.conf and /etc/logrotate.d/* to ensure logs are rotated according to site policy.
service auditd reload
echo 4 Logging and Auditing Completed
##############################################################################