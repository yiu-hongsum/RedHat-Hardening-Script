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
#6.1.1 Audit system file permissions (Not Scored) - Manual
#rpm -Va --nomtime --nosize --nomd5 --nolinkto > <filename>
#Correct any discrepancies found and rerun the audit until output is clean or risk is mitigated or accepted.
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
chown root:root /etc/passwd
chmod 644 /etc/passwd
#6.1.3 Ensure permissions on /etc/shadow are configured (Scored)
chown root:root /etc/shadow
chmod 000 /etc/shadow
#6.1.4 Ensure permissions on /etc/group are configured (Scored)
chown root:root /etc/group
chmod 644 /etc/group
#6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)
chown root:root /etc/gshadow
chmod 000 /etc/gshadow
#6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
#6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
chown root:root /etc/shadow-
chmod 000 /etc/shadow-
#6.1.8 Ensure permissions on /etc/group- are configured (Scored)
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
#6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored)
chown root:root /etc/gshadow-
chmod 000 /etc/gshadow-
#6.1.10 Ensure no world writable files exist (Scored) - Manual
#df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
#The command above only searches local filesystems, there may still be compromised items on network mounted partitions. The following command can be run manually for individual partitions if needed:
#find <partition> -xdev -type f -perm -0002
#6.1.11 Ensure no unowned files or directories exist (Scored) - Manual
#echo "6.1.11 Ensure no unowned files or directories exist in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate."
touch /tmp/unowned.sh
cat << 'EOM' > /tmp/unowned.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls
EOM
bash /tmp/unowned.sh
# find <partition> -xdev -nouser
#6.1.12 Ensure no ungrouped files or directories exist (Scored) - Manual
#echo "6.1.12 Ensure no ungrouped files or directories exist in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate."
touch /tmp/ungrouped.sh
cat << 'EOM' > /tmp/ungrouped.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls
EOM
bash /tmp/ungrouped.sh
#find <partition> -xdev -nogroup
#6.1.13 Audit SUID executables (Not Scored) - Manual
touch /tmp/SUIDexe.sh
cat << 'EOM' > /tmp/SUIDexe.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -ls
EOM
bash /tmp/SUIDexe.sh
#find <partition> -xdev -type f -perm -4000
#6.1.14 Audit SGID executables (Not Scored) - Manual
touch /tmp/SGIDexe.sh
cat << 'EOM' > /tmp/SUIDexe.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -ls
EOM
bash /tmp/SGIDexe.sh
#find <partition> -xdev -type f -perm -2000
#6.2.1 Ensure password fields are not empty (Scored) - Manual
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
#If any accounts in the /etc/shadow file do not have a password, run the following command to lock the account until it can be determined why it does not have a password:
#passwd -l <username>
#6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored) - Manual
grep '^\+:' /etc/passwd
#Remove any legacy '+' entries from /etc/passwd if they exist.
#6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored) - Manual
grep '^\+:' /etc/shadow
#Remove any legacy '+' entries from /etc/shadow if they exist.
#6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored) - Manual
grep '^\+:' /etc/group
#Remove any legacy '+' entries from /etc/group if they exist.
#6.2.5 Ensure root is the only UID 0 account (Scored) - Manual
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'
#Remove any users other than root with UID 0 or assign them a new UID if appropriate.
#6.2.6 Ensure root PATH Integrity (Scored) - Manual
#echo "Correct or justify any items discovered in the Audit step."
touch /tmp/rootpath.sh
cat << 'EOM' > /tmp/rootpath.sh
#!/bin/bash
if [ "`echo $PATH | grep ::`" != "" ]; then
	echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
	echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
	if [ "$1" = "." ]; then
		echo "PATH contains ."
		shift
		continue
	fi
	if [ -d $1 ]; then
		dirperm=`ls -ldH $1 | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]; then
			echo "Group Write permission set on directory $1"
		fi
		if [ `echo $dirperm | cut -c9` != "-" ]; then
			echo "Other Write permission set on directory $1"
		fi
		dirown=`ls -ldH $1 | awk '{print $3}'`
		if [ "$dirown" != "root" ] ; then
			echo $1 is not owned by root
		fi
	else
		echo $1 is not a directory
	fi
	shift
done
EOM
bash /tmp/rootpath.sh
#6.2.7 Ensure all users' home directories exist (Scored) - Manual
#echo "If any users' home directories do not exist, create them and make sure the respective user owns the directory. Users without an assigned home directory should be removed or assigned a home directory as appropriate."
touch /tmp/homedir.sh
cat << 'EOM' > /tmp/homedir.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	fi
done
EOM
bash /tmp/homedir.sh
#6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored) - Manual
#echo "Making global modifications to user home directories without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user file permissions and determine the action to be taken in accordance with site policy."
touch /tmp/homedirpermission.sh
cat << 'EOM' > /tmp/homedirpermission.sh
#!/bin/bash 
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6` != "-" ]; then
			echo "Group Write permission set on the home directory ($dir) of user $user"
		fi
		if [ `echo $dirperm | cut -c8` != "-" ]; then
			echo "Other Read permission set on the home directory ($dir) of user $user"
		fi
		if [ `echo $dirperm | cut -c9` != "-" ]; then
			echo "Other Write permission set on the home directory ($dir) of user $user"
		fi
		if [ `echo $dirperm | cut -c10` != "-" ]; then
			echo "Other Execute permission set on the home directory ($dir) of user $user"
		fi
	fi
done
EOM
bash /tmp/homedirpermission.sh
#6.2.9 Ensure users own their home directories (Scored) - Manual
#echo "Change the ownership of any home directories that are not owned by the defined user to the correct user."
touch /tmp/userhomedir.sh
cat << 'EOM' > /tmp/userhomedir.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		owner=$(stat -L -c "%U" "$dir")
		if [ "$owner" != "$user" ]; then
			echo "The home directory ($dir) of user $user is owned by $owner."
		fi
	fi
done
EOM
bash /tmp/userhomedir.sh
#6.2.10 Ensure users' dot files are not group or world writable (Scored) - Manual
#echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user dot file permissions and determine the action to be taken in accordance with site policy."
touch /tmp/dotfiles.sh
cat << 'EOM' > /tmp/dotfiles.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		for file in $dir/.[A-Za-z0-9]*; do
			if [ ! -h "$file" -a -f "$file" ]; then
				fileperm=`ls -ld $file | cut -f1 -d" "`
				if [ `echo $fileperm | cut -c6` != "-" ]; then
					echo "Group Write permission set on file $file"
				fi
				if [ `echo $fileperm | cut -c9` != "-" ]; then
					echo "Other Write permission set on file $file"
				fi
			fi
		done
	fi
done
EOM
bash /tmp/dotfiles.sh
#6.2.11 Ensure no users have .forward files (Scored) - Manual
#echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .forward files and determine the action to be taken in accordance with site policy."
touch /tmp/forward.sh
cat << 'EOM' > /tmp/forward.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
			echo ".forward file $dir/.forward exists"
		fi
	fi
done
EOM
bash /tmp/forward.sh
#6.2.12 Ensure no users have .netrc files (Scored) - Manual
#echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc files and determine the action to be taken in accordance with site policy."
touch /tmp/usernetrc.sh
cat << 'EOM' > /tmp/usernetrc.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
			echo ".netrc file $dir/.netrc exists"
		fi
	fi
done
EOM
bash /tmp/usernetrc.sh
#6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored) - Manual
#echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc file permissions and determine the action to be taken in accordance with site policy."
touch /tmp/netrc.sh
cat << 'EOM' > /tmp/netrc.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
	echo "The home directory ($dir) of user $user does not exist."
	else
		for file in $dir/.netrc; do
			if [ ! -h "$file" -a -f "$file" ]; then
				fileperm=`ls -ld $file | cut -f1 -d" "`
				if [ `echo $fileperm | cut -c5` != "-" ]; then
					echo "Group Read set on $file"
				fi
				if [ `echo $fileperm | cut -c6` != "-" ]; then
					echo "Group Write set on $file"
				fi
				if [ `echo $fileperm | cut -c7` != "-" ]; then
					echo "Group Execute set on $file"
				fi
				if [ `echo $fileperm | cut -c8` != "-" ]; then
					echo "Other Read set on $file"
				fi
				if [ `echo $fileperm | cut -c9` != "-" ]; then
					echo "Other Write set on $file"
				fi
				if [ `echo $fileperm | cut -c10` != "-" ]; then
					echo "Other Execute set on $file"
				fi
			fi
		done
	fi
done
EOM
bash /tmp/netrc.sh
#6.2.14 Ensure no users have .rhosts files (Scored) - Manual
#echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .rhosts files and determine the action to be taken in accordance with site policy."
touch /tmp/rhosts.sh
cat << 'EOM' > /tmp/rhosts.sh
#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
	if [ ! -d "$dir" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	else
		for file in $dir/.rhosts; do
			if [ ! -h "$file" -a -f "$file" ]; then
				echo ".rhosts file in $dir"
			fi
		done
	fi
done
EOM
bash /tmp/rhosts.sh
#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored) - Manual
#echo "Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found."
touch /tmp/passwd.sh
cat << 'EOM' > /tmp/passwd.sh
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:[^:]*:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done
EOM
bash /tmp/passwd.sh
#6.2.16 Ensure no duplicate UIDs exist (Scored) - Manual
#echo "Based on the results of the audit script, establish unique UIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to."
touch /tmp/dupUID.sh
cat << 'EOM' > /tmp/dupUID.sh
#!/bin/bash
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
		echo "Duplicate UID ($2): ${users}"
	fi
done
EOM
bash /tmp/dupUID.sh
#6.2.17 Ensure no duplicate GIDs exist (Scored) - Manual
#echo "Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed to belong to."
touch /tmp/dupGID.sh
cat << 'EOM' > /tmp/dupGID.sh
#!/bin/bash
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
		echo "Duplicate GID ($2): ${groups}"
	fi
done
EOM
bash /tmp/dupGID.sh
#6.2.18 Ensure no duplicate user names exist (Scored) - Manual
#echo "Based on the results of the audit script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs."
touch /tmp/dupusernames.sh
cat << 'EOM' > /tmp/dupusernames.sh
#!/bin/bash
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
		echo "Duplicate User Name ($2): ${uids}"
	fi
done
EOM
bash /tmp/dupusernames.sh
#6.2.19 Ensure no duplicate group names exist (Scored) - Manual
#echo "sed on the results of the audit script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs."
touch /tmp/dupgroupname.sh
cat << 'EOM' > /tmp/dupgroupname.sh
#!/bin/bash
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
		echo "Duplicate Group Name ($2): ${gids}"
	fi
done
EOM
bash /tmp/dupgroupname.sh
echo 6 System Maintenance Completed! 
##############################################################################