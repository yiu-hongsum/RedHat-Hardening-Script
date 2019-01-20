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
chmod +x 1_Initial_Setup.sh
chmod +x 2_Services.sh
chmod +x 3_Network_Configuration.sh
chmod +x 4_Logging_and_Auditing_64bit.sh
chmod +x 4_Logging_and_Auditing_32bit.sh
chmod +x 5_Access_Authentication_Authorization.sh
chmod +x 6_System_Maintenance.sh
dos2unix 1_Initial_Setup.sh
dos2unix 2_Services.sh
dos2unix 3_Network_Configuration.sh
dos2unix 4_Logging_and_Auditing_64bit.sh
dos2unix 4_Logging_and_Auditing_32bit.sh
dos2unix 5_Access_Authentication_Authorization.sh
dos2unix 6_System_Maintenance.sh
echo Enter input:
options=("Initial Setup" "Services" "Network Configuration" "Logging and Audit 64-bit" "Logging and Audit 32-bit" "Access, Authenticate and Authorization" "System Maintenance" "Run all for 64bit" "Run all for 32bit" "Enter any other inputs to exit.")
############################
select input in "${options[@]}"
do
	case $input in
		"Initial Setup")
			./1_Initial_Setup.sh
			;;
		"Services")
			./2_Services.sh
			;;
		"Network Configuration")
			./3_Network_Configuration.sh
			;;
		"Logging and Audit 64-bit")
			./4_Logging_and_Auditing_64bit.sh
			;;
		"Logging and Audit 32-bit")
			./4_Logging_and_Auditing_32bit.sh
			;;
		"Access, Authenticate and Authorization")
			./5_Access_Authentication_Authorization.sh
			;;
		"System Maintenance")
			./6_System_Maintenance.sh
			;;
		"Run all for 64bit")
			./1_Initial_Setup.sh
			./2_Services.sh
			./3_Network_Configuration.sh
			./4_Logging_and_Auditing_64bit.sh
			./5_Access_Authentication_Authorization.sh
			./6_System_Maintenance.sh
			;;
		"Run all for 32bit")
			./1_Initial_Setup.sh
			./2_Services.sh
			./3_Network_Configuration.sh
			./4_Logging_and_Auditing_32bit.sh
			./5_Access_Authentication_Authorization.sh
			./6_System_Maintenance.sh
			;;
		*)
			echo Exiting CIS Script...
			exit 0
			break
			;;
	esac
done
