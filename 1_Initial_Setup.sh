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
#1 Initial Setup
############################
#1.1 Filesystem Configuration
############################
#1.1.1 Disable unused filesystems
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)
if [ -f "/etc/modprobe.d/CIS.conf" ]
then
	echo install cramfs /bin/true >> /etc/modprobe.d/CIS.conf
else
	echo install cramfs /bin/true >> /etc/modprobe.d/CIS.conf
fi
rmmod cramfs
#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)
echo install freevxfs /bin/true >> /etc/modprobe.d/CIS.conf
rmmod freevxfs
#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)
echo install jffs2 /bin/true >> /etc/modprobe.d/CIS.conf
rmmod jffs2
#1.1.1.4 Ensure mounting of hfs filesystems is disabled( Scored)
echo install hfs /bin/true >> /etc/modprobe.d/CIS.conf
rmmod hfs
#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
echo install hfsplus /bin/true >> /etc/modprobe.d/CIS.conf
rmmod hfsplus
#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)
echo install squashfs /bin/true >> /etc/modprobe.d/CIS.conf
rmmod squashfs
#1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)
echo install udf /bin/true >> /etc/modprobe.d/CIS.conf
rmmod udf
#1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)
echo install vfat /bin/true >> /etc/modprobe.d/CIS.conf
rmmod vfat
############################
#1.1.2 Ensure separate partition exists for /tmp (Scored)
#1.1.3 Ensure nodev option set on /tmp partition (Scored)
#1.1.4 Ensure nosuid option set on /tmp partition (Scored)
#1.1.5 Ensure noexec option set on /tmp partition (Scored)
systemctl unmask tmp.mount
systemctl enable tmp.mount
sed -i -e "s/\(Options=\).*/\1mode=1777,strictatime,noexec,nodev,nosuid/" /etc/systemd/system/local-fs.target.wants/tmp.mount
#1.1.6 Ensure separate partition exists for /var (Scored)
#1.1.7 Ensure separate partition exists for /var/tmp (Scored)
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
#1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
#1.1.11 Ensure separate partition exists for /var/log (Scored)
#1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
#1.1.13 Ensure separate partition exists for /home (Scored)
#1.1.14 Ensure nodev option set on /home partition (Scored)
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
#1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
#1.1.18 Ensure nodev option set on removable media partitions (Not Scored)
#1.1.19 Ensure nosuid option set on removable media partitions (Not Scored)
#1.1.20 Ensure noexec option set on removable media partitions (Not Scored)
#1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | -exec chmod a+t '{}' + 2>/dev/null
#1.1.22 Disable Automounting (Scored)
systemctl disable autofs
############################
#1.2 Configure Software Updates
############################
#1.2.1 Ensure package manager repositories are configured (Not Scored) - Manual
#1.2.2 Ensure gpgcheck is globally activated (Scored)
#Edit the /etc/yum.conf file and set the gpgcheck to 1 as follows: gpgcheck=1
sed -i "s/gpgcheck=0/gpgcheck=1/" /etc/yum.conf
#1.2.3 Ensure GPG keys are configured (Not Scored) - Manual
#1.2.4 Ensure Red Hat Subscription Manager connection is configured (Not Scored) - Manual
#1.2.5 Disable the rhnsd Daemon (Not Scored)
chkconfig rhnsd off
############################
#1.3 Filesystem Integrity Checking
############################
#1.3.1 Ensure AIDE is installed (Scored)
yum install aide -y
#Configure AIDE as appropriate for your environment. Consult the AIDE documentation for options.
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
#1.3.2 Ensure filesystem integrity is regularly checked (Scored) - Manual
#crontab -u root -e
#crontab -l|sed "\$a0 5 * * * /usr/sbin/aide --check"|crontab -
############################
#1.4 Secure Boot Settings
############################
#1.4.1 Ensure permissions on bootloader config are configured (Scored)
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
chown root:root /boot/grub2/user.cfg
chmod og-rwx /boot/grub2/user.cfg
#1.4.2 Ensure bootloader password is set (Scored) - Manual
#grub2-setpassword
#1.4.3 Ensure authentication required for single user mode (Scored)
sed -i -e "s?\(ExecStart=\).*?\1-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"?" /usr/lib/systemd/system/rescue.service
sed -i -e "s?\(ExecStart=\).*?\1-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"?" /usr/lib/systemd/system/emergency.service
############################
#1.5 Additional Process Hardening
############################
#1.5.1 Ensure core dumps are restricted (Scored)
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
#1.5.2 Ensure XD/NX support is enabled (Not Scored)
#1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2
#1.5.4 Ensure prelink is disabled (Scored)
prelink -ua
yum remove prelink -y
############################
#1.6 Mandatory Access Control
############################
#1.6.1 Configure SELinux
#1.6.1.1 Ensure SELinux is not disabled in bootloader configuration (Scored)
sed -i -e "s/\(GRUB_CMDLINE_LINUX=\).*/\1\"\"/" /etc/default/grub
if grep -q GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub
then
sed -i -e "s/\(GRUB_CMDLINE_LINUX_DEFAULT=\).*/\1\"quiet\"/" /etc/default/grub
else
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" >> /etc/default/grub
fi
grub2-mkconfig -o /boot/grub2/grub.cfg
#1.6.1.2 Ensure the SELinux state is enforcing (Scored)
sed -i -e "s/\(SELINUX=\).*/\1enforcing/" /etc/selinux/config
#1.6.1.3 Ensure SELinux policy is configured (Scored)
sed -i -e "s/\(SELINUXTYPE=\).*/\1targeted/" /etc/selinux/config
#1.6.1.4 Ensure SETroubleshoot is not installed (Scored)
yum remove setroubleshoot -y
#1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed (Scored)
yum remove mcstrans -y
#1.6.1.6 Ensure no unconfined daemons exist (Scored)
#Perform the following to determine if unconfined daemons are running on the system. 
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' [no output produced]
#1.6.2 Ensure SELinux is installed (Scored)
yum install libselinux -y
############################
#1.7 Warning Banners
############################
#1.7.1 Command Line Warning Banners
#1.7.1.1 Ensure message of the day is configured properly (Scored) - Manual
#Edit the /etc/motd file with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , or \v.
#1.7.1.2 Ensure local login warning banner is configured properly (Not Scored) - Manual
#Edit the /etc/issue file with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , or \v
#echo "Authorized users only. All activity may be monitored and reported." >> /etc/issue
#1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored) - Manual
#Edit the /etc/issue.net file with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , or \v
#echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
#1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored)
chown root:root /etc/motd
chmod 644 /etc/motd
#1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
chown root:root /etc/issue
chmod 644 /etc/issue
#1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored)
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
############################
#1.7.2 Ensure GDM login banner is configured (Scored)
cat > /etc/dconf/profile/gdm << EOF
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
if [ -f "/etc/dconf/db/gdm.d/01-banner-message" ]
then
	sed -i -e "s/\(banner-message-enable=\).*/\1true/" /etc/dconf/db/gdm.d/01-banner-message
	sed -i -e "s/\(banner-message-text=\).*/\1\"Authorized users only. All activity may be monitored and reported.\"/" /etc/dconf/db/gdm.d/01-banner-message
else
	cat > /etc/dconf/db/gdm.d/01-banner-message << EOF
	[org/gnome/login-screen]
	banner-message-enable=true
	banner-message-text="Authorized users only. All activity may be monitored and reported."
EOF
fi
dconf update
############################
#1.8 Ensure updates, patches, and additional security software are installed (Scored)
yum update --security -y
echo 1 Initial Setup Completed!