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
#5.1.1 Ensure cron daemon is enabled (Scored)
systemctl enable crond
#5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
chown root:root /etc/crontab 
chmod og-rwx /etc/crontab
#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly
#5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)	
chown root:root /etc/cron.daily 
chmod og-rwx /etc/cron.daily
#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
chown root:root /etc/cron.weekly 
chmod og-rwx /etc/cron.weekly
#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)	
chown root:root /etc/cron.monthly 
chmod og-rwx /etc/cron.monthly
#5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
#5.1.8 Ensure at/cron is restricted to authorized users (Scored)
rm /etc/cron.deny -f
rm /etc/at.deny -f
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
chown root:root /etc/ssh/sshd_config 
chmod og-rwx /etc/ssh/sshd_config
#5.2.2 Ensure SSH Protocol is set to 2 (Scored)
if grep "^Protocol" /etc/ssh/sshd_config; then
   sed -i "s/\(Protocol \).*/\12/" /etc/ssh/sshd_config
else
    echo "Protocol 2" >> /etc/ssh/sshd_config
fi
#5.2.3 Ensure SSH LogLevel is set to INFO (Scored)
if grep "^LogLevel" /etc/ssh/sshd_config; then
   sed -i "s/\(LogLevel \).*/\1INFO/" /etc/ssh/sshd_config
else
    echo "LogLevel INFO" >> /etc/ssh/sshd_config
fi
#5.2.4 Ensure SSH X11 forwarding is disabled (Scored)
if grep "^X11Forwarding" /etc/ssh/sshd_config; then
   sed -i "s/\(X11Forwarding \).*/\1no/" /etc/ssh/sshd_config
else
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi
#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
if grep "^MaxAuthTries" /etc/ssh/sshd_config; then
    sed -i "s/\(MaxAuthTries \).*/\14/" /etc/ssh/sshd_config
else
    echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
fi
#5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored)
if grep "^IgnoreRhosts" /etc/ssh/sshd_config; then
    sed -i "s/\(IgnoreRhosts \).*/\1yes/" /etc/ssh/sshd_config
else
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
fi
#5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored)
if grep "^HostbasedAuthentication" /etc/ssh/sshd_config; then
    sed -i "s/\(HostbasedAuthentication \).*/\1no/" /etc/ssh/sshd_config
else
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi
#5.2.8 Ensure SSH root login is disabled (Scored)
if grep "^PermitRootLogin" /etc/ssh/sshd_config; then
    sed -i "s/\(PermitRootLogin \).*/\1no/" /etc/ssh/sshd_config
else
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi
#5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored)
if grep "^PermitEmptyPasswords" /etc/ssh/sshd_config; then
    sed -i "s/\(PermitEmptyPasswords \).*/\1no/" /etc/ssh/sshd_config
else
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
fi
#5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored)
if grep "^PermitUserEnvironment" /etc/ssh/sshd_config; then
    sed -i "s/\(PermitUserEnvironment \).*/\1no/" /etc/ssh/sshd_config
else
    echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
fi
#Ensure only approved MAC algorithms are used (Scored)
if grep "^MACs" /etc/ssh/sshd_config; then
sed -i "s/\(MACs \).*/\1hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com/" /etc/ssh/sshd_config
else
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
fi
#5.2.12 Ensure SSH Idle Timeout Interval is configured (Scored)
if grep "^ClientAliveInterval" /etc/ssh/sshd_config; then
    sed -i "s/\(ClientAliveInterval \).*/\1300/" /etc/ssh/sshd_config
else
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
fi
if grep "^ClientAliveCountMax" /etc/ssh/sshd_config; then
    sed -i "s/\(ClientAliveCountMax \).*/\10/" /etc/ssh/sshd_config
else
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi
#5.2.13 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
if grep "^LoginGraceTime" /etc/ssh/sshd_config; then
    sed -i "s/\(LoginGraceTime \).*/\160/" /etc/ssh/sshd_config
else
    echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
fi
#5.2.14 Ensure SSH access is limited (Scored) - Manual
#if grep "^AllowUsers" /etc/ssh/sshd_config; then
#    sed -i "s/\(AllowUsers \).*/\1<userlist>/" /etc/ssh/sshd_config
#else
#    echo "AllowUsers <userlist>" >> /etc/ssh/sshd_config
#fi
#if grep "^AllowGroups" /etc/ssh/sshd_config; then
#    sed -i "s/\(AllowGroups \).*/\1<grouplist>/" /etc/ssh/sshd_config
#else
#    echo "AllowGroups <grouplist>" >> /etc/ssh/sshd_config
#fi
#if grep "^DenyUsers" /etc/ssh/sshd_config; then
#    sed -i "s/\(DenyUsers \).*/\1<userlist>/" /etc/ssh/sshd_config
#else
#    echo "DenyUsers <userlist>" >> /etc/ssh/sshd_config
#fi
#if grep "^DenyGroups" /etc/ssh/sshd_config; then
#    sed -i "s/\(DenyGroups \).*/\1<grouplist>/" /etc/ssh/sshd_config
#else
#    echo "DenyGroups <grouplist>" >> /etc/ssh/sshd_config
#fi
#5.2.15 Ensure SSH warning banner is configured (Scored)
if grep "^Banner" /etc/ssh/sshd_config; then
	sed -i "s/\(Banner \).*/\1\/etc\/issue.net/" /etc/ssh/sshd_config
else
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
fi
systemctl reload sshd
#5.3.1 Ensure password creation requirements are configured (Scored)
if grep "^password requisite pam_pwquality.so" /etc/pam.d/password-auth; then
	sed -i "s/\(password requisite pam_pwquality.so \).*/\1try_first_pass retry=3/" /etc/pam.d/password-auth
else
    echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth
fi
if grep "^password requisite pam_pwquality.so" /etc/pam.d/system-auth; then
	sed -i "s/\(password requisite pam_pwquality.so \).*/\1try_first_pass retry=3/" //etc/pam.d/system-auth
else
    echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/system-auth
fi
if grep "^minlen" /etc/security/pwquality.conf; then
	sed -i "s/\(minlen = \).*/\114/" /etc/security/pwquality.conf
else
    echo "minlen = 14" >> /etc/security/pwquality.conf
fi
if grep "^dcredit" /etc/security/pwquality.conf; then
	sed -i "s/\(dcredit = \).*/\114/" /etc/security/pwquality.conf
else
    echo "dcredit = 14" >> /etc/security/pwquality.conf
fi
if grep "^lcredit" /etc/security/pwquality.conf; then
	sed -i "s/\(lcredit = \).*/\1-1/" /etc/security/pwquality.conf
else
    echo "lcredit = -1" >> /etc/security/pwquality.conf
fi
if grep "^ocredit" /etc/security/pwquality.conf; then
	sed -i "s/\(ocredit = \).*/\1-1/" /etc/security/pwquality.conf
else
    echo "ocredit = -1" >> /etc/security/pwquality.conf
fi
if grep "^ucredit" /etc/security/pwquality.conf; then
	sed -i "s/\(ucredit = \).*/\1-1/" /etc/security/pwquality.conf
else
    echo "ucredit = -1" >> /etc/security/pwquality.conf
fi
#5.3.2 Ensure lockout for failed password attempts is configured (Scored)
#5.3.3 Ensure password reuse is limited (Scored)
#5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)
cat << 'EOM' > /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad] pam_unix.so
auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        required      pam_faildelay.so delay=2000000
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOM
sort /etc/pam.d/system-auth | uniq > /etc/pam.d/temptemp
sort /etc/pam.d/temptemp | uniq > /etc/pam.d/system-auth
rm -rf /etc/pam.d/temptemp
cat << 'EOM' > /etc/pam.d/password-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad] pam_unix.so
auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        required      pam_faildelay.so delay=2000000
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOM
sort /etc/pam.d/password-auth | uniq > /etc/pam.d/temptemp
sort /etc/pam.d/temptemp | uniq > /etc/pam.d/password-auth
rm -rf /etc/pam.d/temptemp
#5.4.1.1 Ensure password expiration is 365 days or less (Scored)
#5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)
#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
useradd -D -f 30
#find all login users
## get UID limit ##
l=$(grep "^UID_MIN" /etc/login.defs)
## use awk to print if UID >= $UID_LIMIT ##
loginusers=`awk -F':' -v "limit=${l##UID_MIN}" '{ if ( $3 >= limit ) print $1}' /etc/passwd`
#loop through login user list and set password max age to 90 days
for user in $loginusers; do
        echo $user
        chage --maxdays 90 $user
        chage --mindays 7 $user
        chage --warndays 7 $user
		chage --inactive 30 $user
done
############################
#5.4.1.5 Ensure all users last password change date is in the past (Scored) - Manual
#Investigate any users with a password change date in the future and correct them. Locking the account, expiring the password, or resetting the password manually may be appropriate.
#5.4.2 Ensure system accounts are non-login (Scored) - Manual
#the following script is used to verify
#egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'
#any account returned by the audit script to /isr/sbin/nologin
# usermod -s /usr/sbin/nologin <user>
#!/bin/bash
#for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd` ; do 
#if [ $user != "root" ]; then 
#	usermod -L $user 
#	if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
#	usermod -s /sbin/nologin $user
#	fi 
#fi 
#done
#5.4.3 Ensure default group for the root account is GID 0 (Scored)
usermod -g 0 root
#5.4.4 Ensure default user umask is 027 or more restrictive (Scored)
sed -i "s/\(umask \).*/\1027/" /etc/bashrc
sed -i "s/\(umask \).*/\1027/" /etc/profile /etc/profile.d/*.sh
#5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)
if grep "^TMOUT" /etc/bashrc; then
    sed -i "s/\(TMOUT=\).*/\1600/" /etc/bashrc
else
    echo "TMOUT 600" >> /etc/bashrc
fi
if grep "^TMOUT" /etc/profile; then
    sed -i "s/\(TMOUT=\).*/\1600/" /etc/profile
else
    echo "TMOUT 600" >> /etc/profile
fi
#5.5 Ensure root login is restricted to system console (Not Scored) - Manual
#Remove entries for any consoles that are not in a physically secure location.
#5.6 Ensure access to the su command is restricted (Scored) - Manual
#this command should be in by default. check using 
#grep pam_wheel.so /etc/pam.d/su
#if command does not exist, run the following commnad
#echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
#Create a comma separated list of users in the wheel statement in the /etc/group file:
#<user list> like tom,harry,tim
#wheel:x:10:root,<user list>
echo 5 Access, Authentication and Authorization Completed
##############################################################################