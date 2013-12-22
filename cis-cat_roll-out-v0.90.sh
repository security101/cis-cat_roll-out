#!/bin/sh
#
# created 2013 by Andreas von Keviczky
# All rights reserved.  The Berkeley software License Agreement
# specifies the terms and conditions for redistribution.
#
#	@cis-cat_roll-out.sh v0.90
#
# This script is designed to ease remote deployment, execution, report collection and clean up
# for the "Center of Internet Security - Configuration Assessment Tool" by using functions usually 
# provided by any POSIX operating system. Please refer to www.cisecurity.org concerning the CIS-CAT Tool.
# 
# The script is not fully tested yet!
# Code review using http://www.shellcheck.net passed but 54 comments concerning
# "SC2086 Double quote to prevent globbing and word splitting." 
# "SC1005 Drop the keyword 'function'. It's optional in Bash but invalid in other shells."
# "SC2006 Use $(..) instead of deprecated `..`"
# "SC2046 Quote this to prevent word splitting."
# "SC2003 expr is antiquated. Consider rewriting this using $((..)), ${} or [[ ]]."
# have not been cleaned up
# Functional testing concerning 
# #### target systems passed: CentOS 5.5, 5.9 and 6.4 as well as Mac OS Maverick
# #### host system passed: Maverick 
# #### CIS-CAT-Bundle passed: ciscat-full-bundle-2013-06-07
#
# Configuration section

usage="Usage: $0 "

# Value will be overwritten when config file is loaded
# its required just in case the config file cannot be 
# loaded to ensure that logging works fine in any case
VERBOSE="yes"

# for sanity purpose make the working directory set correctly
bin=`dirname "$0"`
bin=`cd "$bin">/dev/null; pwd`

# load the configuration from file
CONFIG_FILE="./cis-cat_roll-out.conf"
MESSAGE="Loaded configuration file ${CONFIG_FILE} --> "

function write_log ()
{
	NOW=$(date +"%Y-%m-%d: %H:%M:%S")
	MESSAGE="${@}"
	EVENT="${NOW}: ${BATCH_HOST}: ${MESSAGE}"

	if [ $VERBOSE = "yes" ] ; 
		then
			echo "${EVENT}"			
		else 
			echo "${EVENT}" >> "${LOGFILE}"
		fi
}

#
# check if config file is available and 
# has been loaded without errors
# or write message and exit otherwise

if test -f "${CONFIG_FILE}" ;
	then
		. ${CONFIG_FILE}
		errCode=$?
		if [ $errCode -ne 0 ] ;
			then
				write_log "$MESSAGE FAILED - return code ${errCode} "
				exit $errCode
			else
				write_log "$MESSAGE succeeded"
		fi
	else
		write_log "$MESSAGE file NOT FOUND"
		exit 1 	
	fi

function usage() 
{
echo "$usage"
  exit 1
}

function measure_process ()
{

		case "${@}" in
		START) 	#Option measure in seconds only
				T_START=$(date +%s)
				#If supported you may measure in nano seconds
				#T_START=$(date +%s%N)
				#Verbose
				write_log "START at $T_START"
				return 1
				;;
		STOP) 	
				#Option measure in seconds only
				T_END=$(date +%s)
				#If supported you may measure in nano seconds
				#T_END=$(date +%s%N)
				write_log "STOP at $T_END"
				return 1
				;;
		SHOW) 	
				#Option show seconds only
				ELAPSED=`echo "scale=0; $(( $T_END - $T_START )) / 1" | bc`
				#If supported you may measure in nano seconds
				#ELAPSED=`echo "scale=8; $(( $T_END - $T_START )) / 1000000000" | bc`
				write_log "SHOW now estimated processing time: $ELAPSED seconds!"
				return 1
				;;
		*) 		write_log "$@ is no valid option for `basename $0` in measure_process "
				return 0
				;;
	esac
		
}

function do_ssh_askpass ()
{
	FUNC0="do_ssh_askpass" 
	write_log "${FUNC0}: CALLED" 
	
	export SSH_ASKPASS="${USR_KEY_PWD}"
	
	VALUE=`ssh-add ${USR_KEY} < /dev/null 2>&1`

	write_log "${FUNC0}: ${SERVER}: ssh-add responded --> $VALUE --> return code = $?" 

	write_log "${FUNC0}: EXIT" 
	return 0 

}

function show_status ()
{
	FUNC="transfer_distribution"
	
	write_log "${FUNC}: ${SERVER}: CALLED"
	write_log "${FUNC}: ${SERVER}: Detected OS as $DISTRO $VER"
	write_log "${FUNC}: ${SERVER}: Using JRE located at '$JAVA_HOME'"
	write_log "${FUNC}: ${SERVER}: Using CISCAT located at '$CISCAT_DIR/CISCAT.jar'"
	write_log "${FUNC}: ${SERVER}: Using Benchmark '$CISCAT_DIR/benchmarks/$BENCHMARK'"
	write_log "${FUNC}: ${SERVER}: Using Profile '$PROFILE'"
	write_log "${FUNC}: ${SERVER}: Storing Reports at '$REPORTS_DIR'"
	write_log "${FUNC}: ${SERVER}: CISCAT_SHELL :${CISCAT_SHELL}"
	write_log "${FUNC}: ${SERVER}: CISCAT_PARAM :${CISCAT_PARAM}"
	write_log "${FUNC}: ${SERVER}: CISCAT_BENCH :${CISCAT_BENCH}"
	write_log "${FUNC}: ${SERVER}: CISCAT_PROFI :${CISCAT_PROFI}"
	write_log "${FUNC}: ${SERVER}: CISCAT_RPARA :${CISCAT_RPARA}"
	write_log "${FUNC}: ${SERVER}: CISCAT_DIR_R :${REPORT_DIR_REMOTE}"
	
	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

function check_process_status ()
{

	STATUS="do not know"
						
	case $1 in
		1) 	#Process terminated with problems
			STATUS="failed"
			;;
		0) 	#Process terminated with NO problems
			STATUS="succeeded"
			;;
		*) 	STATUS="return code = $1"
			;;
	esac
	
	write_log "$2 reported execution $STATUS"
	return $1

}

function check_hash_algo_support ()
{

	FUNC="check_hash_algo_support"
	write_log "${FUNC}: ${SERVER}: CALLED" 

	# check for common executables
	HASH_gpg2="`which gpg2 2> /dev/null | head -1`"
	HASH_gpg="`which gpg 2> /dev/null | head -1`"
	HASH_pgp="`which pgp 2> /dev/null | head -1`"
	HASH_openssl="`which openssl 2> /dev/null | head -1`"
	HASH_md5sum="`which md5sum 2> /dev/null | head -1`"
	HASH_md5="`which md5 2> /dev/null | head -1`"
	HASH_sha1sum="`which sha1sum 2> /dev/null | head -1`"
	HASH_sha1="`which sha1 2> /dev/null | head -1`"
		
	MESSAGE="Supported HASH algorithm -->"

	if test -x "${HASH_openssl}"; 
		then 
			write_log "$MESSAGE ${HASH_openssl}" 
		fi   
	if test -x "${HASH_gpg2}"; 
		then 
			write_log "$MESSAGE ${HASH_gpg2}" 
		fi  
	if test -x "${HASH_gpg}"; 
		then 
			write_log "$MESSAGE ${HASH_gpg}" 
		fi  
	if test -x "${HASH_pgp}"; 
		then 
			write_log "$MESSAGE ${HASH_pgp}" 
		fi  
	if test -x "${HASH_md5sum}"; 
		then 
			write_log "$MESSAGE ${HASH_md5sum}" 
		fi  
	if test -x "${HASH_md5}"; 
		then 
			write_log "$MESSAGE ${HASH_md5}" 
		fi  
	if test -x "${HASH_sha1sum}"; 
		then 
			write_log "$MESSAGE ${HASH_sha1sum}" 
		fi  
	if test -x "${HASH_sha1}"; 
		then 
			write_log "$MESSAGE ${HASH_sha1}" 
		fi  

	write_log "${FUNC}: ${SERVER}: EXIT" 
	return 0			
}

function check_distribution_source ()
{

	FUNC="check_distribution_source"
	write_log "${FUNC}: ${SERVER}: CALLED" 
	
	File=$1
	
	MESSAGE1="${FUNC}: Check distribution source namely $File"
 
	if test -f "${File}"
		then
    	
    	RESULT="found"
		write_log "$MESSAGE1 $RESULT"
												
		#MD5 is commonly installed and available but if others are supported by the operating systems
		#eg SHA1 or SHA256 could be used instead
		
		MD5_Value1=`md5 -q $File`
		MD5_Value2=`cut -d* -f1 $File.md5`
 
		MESSAGE2="${FUNC}: Check distribution source $File using $File.md5 comparing $MD5_Value1 vs $MD5_Value2 "
 
		if [ $MD5_Value1 = $MD5_Value2 ]
			then
    			RESULT="md5 checksum OK"
    			EXIT="0"
			else
    			RESULT="md5 checksum MISMATCH"
    			EXIT="1"
 		fi
		
		write_log "$MESSAGE2 $RESULT"

	else
    	RESULT="does NOT EXIST!"
    	EXIT="1"
		write_log "$MESSAGE1 $RESULT"
 	 fi 
	
	write_log "${FUNC}: ${SERVER}: EXIT" 
	return $EXIT			
}


function check_remote_ssh_connection ()
{
	FUNC="check_remote_ssh_connection"
	write_log "${FUNC}: ${SERVER}: CALLED" 
																																																			
	VALUE=`ssh ${SSH_OPTIONS} $USR@$SERVER hostname < /dev/null 2>&1 | tail -n 1` 
	RESPONSE=$?
				
	# ssh return code = 0 --> Permission granted
	# ssh return code = 255 --> Permission denied
	
	write_log "${FUNC}: ${SERVER}: ssh responded --> $VALUE --> return code = ${RESPONSE}" 
	write_log "${FUNC}: ${SERVER}: EXIT" 
	
	return ${RESPONSE}
										
}

function check_remote_ssh_connection_sudo ()
{
	FUNC="check_remote_ssh_connection"
	write_log "${FUNC}: ${SERVER}: CALLED"

	# Read in the password from the STDIN
	# read -s -p "Please enter your password:" PASSWORD
	# echo  
    
    # so fare no solution found to hand over the
	# password to the sudo function	
	# manual input on the console STDIN would work fine.	
	# if entered once the other calls will proceed
	# without additional input.
 
    VALUE=`ssh ${SSH_OPTIONS} $USR@$SERVER "sudo -S uname -a 2>&1 << EOF
$PASSWORD
EOF
"`
    	
	RESPONSE=$?
				
	# ssh return code = 0 --> Permission granted
	# ssh return code = 255 --> Permission denied
	
	write_log "${FUNC}: ${SERVER}: ssh responded --> $VALUE --> return code = ${RESPONSE}" 
	write_log "${FUNC}: ${SERVER}: EXIT" 
	
	return ${RESPONSE}
										
}

function check_remote_disc_space ()
{
	FUNC="check_disc_space" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
	
	case $DF_PARAMETER in
		-k) SCALE="KB"
			;;
		-m) SCALE="MB"	
			;;
		-g) SCALE="GB"
			;;
		--block-size=G) SCALE="GB"
			;;
		*) 	STATUS="return code = $1"
			;;
	esac
	
ssh ${SSH_OPTIONS} ${USR}@${SERVER} df $DF_PARAMETER | grep -vE '^Filesystem|tmpfs|cdrom|map|devfs' | grep ${DESTINATION_PART} | while read output; 
		do	
							
		#Extract values for size, used, available and percentage 
		D_partition=$(echo $output | awk '{ print $1 }' )
		# CentOS returns values including the block size, e.g. G for GB 
		D_size=$(echo $output | awk '{print $2}' | sed s/G//)
		D_used=$(echo $output | awk '{print $3}' | sed s/G//)
		D_available=$(echo $output | awk '{print $4}' | sed s/G//)
		D_percent=$(echo $output | awk '{print $5}')

		if [ ${DESTINATION_PART} = ${D_partition} ] ;
			then 
				write_log "${FUNC}: ${SERVER}: target destination partition ${DESTINATION_PART} checked and confirmed see ${SERVER} ${D_partition}" 
				write_log "${FUNC}: ${SERVER}: ${D_partition} size=(${D_size})${SCALE} used=(${D_used})${SCALE} available=(${D_available})${SCALE} percent=${D_percent}"
			fi				

		MESSAGE="${FUNC}: ${SERVER}: ${D_partition} (${D_available})${SCALE} disc space checked against limit (${DISC_SPACE_ALERT_LEVEL})${SCALE} : CHECK"
	
		if [ ${D_available} -ge ${DISC_SPACE_ALERT_LEVEL} ]; 
			then
				write_log "$MESSAGE PASSED" 
			else
				write_log "$MESSAGE FAILED"
				#Option 
				#echo $MESSAGE | mail -s "Alert: Lack of disk space on $SERVER" $ADMIN
			fi
	done

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 

}

function check_remote_java_installation ()
{
	FUNC="check_remote_java_installation" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
	
	ssh ${SSH_OPTIONS} ${USR}@${SERVER} printenv | grep java | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: Check remote JAVA environment --> $output"
	
	done 

	MESSAGE="${FUNC}: ${SERVER}: Check remote JAVA environment -->"

	if test -x "${output}";
		then 
			write_log "$MESSAGE entries found"
		else  
			write_log "$MESSAGE NO entries found"
		fi   
																																																																	
	REMOTE_JAVA_PATH=`ssh ${SSH_OPTIONS} ${USR}@${SERVER} which java | head -1`
						
	MESSAGE="${FUNC}: ${SERVER}: Check remote JAVA path -->"

	if test -x "${REMOTE_JAVA_PATH}"; 
		then 
			write_log "$MESSAGE ${REMOTE_JAVA_PATH} found"
			JAVA_HOME=${REMOTE_JAVA_PATH}
		else  
			write_log "$MESSAGE FAILED"
			write_log "${FUNC}: EXIT @ test-else" 
			return 1
		fi   

	ssh ${SSH_OPTIONS} ${USR}@${SERVER} java -version 2>&1 | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: Check remote JAVA version --> $output"
	
	done 
	
	REMOTE_JAVA_VERSION=`ssh ${SSH_OPTIONS} ${USR}@${SERVER} java -version 2>&1 | head -1 | awk '{print $3}' | sed 's/\"//g' | awk -F "_" '{print $1}' `
						
	MESSAGE="${FUNC}: ${SERVER}: Check remote JAVA version -->"
	
	write_log "$MESSAGE ${REMOTE_JAVA_VERSION}"

	if [ `expr ${REMOTE_JAVA_VERSION} \>= ${REMOTE_JAVA_REFERENCE_VERSION}` -eq 1 ] ;
			then 
				write_log "${FUNC}: ${SERVER}: remote version found ${REMOTE_JAVA_VERSION} meets reference version ${REMOTE_JAVA_REFERENCE_VERSION} criteria" 
			else
				write_log "${FUNC}: ${SERVER}: remote version found ${REMOTE_JAVA_VERSION} does NOT meet reference version ${REMOTE_JAVA_REFERENCE_VERSION} criteria" 
				write_log "${FUNC}: EXIT @ test-else" 
				return 1			
			fi				
		
	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

detect_os_variant_ssh()
{
      
    FUNC="detect_os_variant_ssh"
	write_log "${FUNC}: ${SERVER}: CALLED"
		
	# when invoked with no option, `uname` assumes -s
	# due to warning message reported by ssh when Permanently added '<host>' (RSA) to the list of known hosts.
	# only the last line is of interest

	VALUE=`ssh ${SSH_OPTIONS} $USR@$SERVER uname < /dev/null 2>&1 | tail -n 1`

                case ${VALUE} in
                Linux)
                ### RedHat and variants ###
                        if `ssh ${SSH_OPTIONS} $USR@$SERVER test -f /etc/redhat-release ` 
                        then
                        	DISTRO=`ssh ${SSH_OPTIONS} $USR@$SERVER cat /etc/redhat-release | awk {'print $1'}`
	
	                         case ${DISTRO} in
                                        Red)
                                                DISTRO='RedHat' ;;
                                        CentOS)
                                                DISTRO='CentOS' ;;
                                esac
                            
                            VER=`ssh ${SSH_OPTIONS} $USR@$SERVER egrep -o "[[:digit:]]\.?+" /etc/redhat-release | awk {'print $1'}`

                ### SuSE and variants ###
                        elif `ssh ${SSH_OPTIONS} $USR@$SERVER test -f "/etc/SuSE-release"`
                        then
                                DISTRO='SUSE'

                ### Debian and variants ###
                        elif `ssh ${SSH_OPTIONS} $USR@$SERVER test -f "/etc/debian_version"`
                        then
                                DISTRO='Debian'
                                VER= `ssh ${SSH_OPTIONS} $USR@$SERVER egrep -o "([[:digit:]]\.?)+" /etc/debian_version`

                                # Ubuntu appears to not use numbers...
                                if [ ! $? ]
                                then
                                        DISTRO='Ubuntu'
                                fi
                        else
                                DISTRO='Linux'
                        fi
                ;;
                HP-UX)
                        DISTRO="HPUX"
                        VER=`ssh ${SSH_OPTIONS} $USR@$SERVER uname -v | cut -d"." -f 2 < /dev/null 2>&1 | tail -n 1`
                ;;
                AIX)
                        DISTRO="AIX"
                        VER=`ssh ${SSH_OPTIONS} $USR@$SERVER uname -v < /dev/null 2>&1 | tail -n 1`.`ssh ${SSH_OPTIONS} $USR@$SERVER uname -r < /dev/null 2>&1 | tail -n 1`
                ;;
                Darwin)
                        DISTRO='OSX'
                        VER=`ssh ${SSH_OPTIONS} $USR@$SERVER uname -r < /dev/null 2>&1 | tail -n 1`
                ;;
                SunOS)
                        DISTRO='Solaris'
                        VER=`ssh ${SSH_OPTIONS} $USR@$SERVER uname -r < /dev/null 2>&1 | tail -n 1`
                ;;

              *)
                       DISTRO='<Unknown_Platform>'
                       VER='<Unknown_Version>'
        esac
		 
	write_log "${FUNC}: ${SERVER}: DISTRO = ${DISTRO}, VERSION = ${VER}" 
	write_log "${FUNC}: ${SERVER}: EXIT" 
	
	return 0 
	
}

#
# There is no need to make modifications below this point unless you want to override the benchmark profile 
# CIS-CAT uses. The default configuration of this script will cause CIS-CAT to run the "Level 2" equivalent
# profile, which includes all "Level 1" profile checks. 
#

map_to_benchmark()
{
    FUNC="map_to_benchmark"
	write_log "${FUNC}: ${SERVER}: CALLED"
        
    _DISTRO=$1
    _VER=$2

	write_log "${FUNC}: ${SERVER}: DISTRO=$1,  VERSION=$2"
	
        case $_DISTRO in
                OSX)                
                        # OSX 10.5
                        if [ `expr $_VER \>= 9.0 \& $_VER \< 10.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.5_Benchmark_v.1.1.0.xml"
                                PROFILE="Level 2 Profile"
                        fi

                        # OSX 10.6
                        if [ `expr $_VER \>= 10.0 \& $_VER \< 11.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.6_Benchmark_v.1.0.0.xml"
                                PROFILE="Level 2 Profile"
                        fi
                        
                        # OSX 10.7
                        if [ `expr $_VER \>= 11.0 \& $_VER \< 12.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.6_Benchmark_v.1.0.0.xml"
                                PROFILE="Level 2 Profile"
                        fi

                        # OSX 10.8
                        if [ `expr $_VER \>= 12.0 \& $_VER \< 13.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.6_Benchmark_v.1.0.0.xml"
                                PROFILE="Level 2 Profile"
                        fi

                       # OSX Maverick
                        if [ `expr $_VER \>= 13.0 \& $_VER \< 14.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Apple_OSX_10.6_Benchmark_v.1.0.0.xml"
                                PROFILE="Level 2 Profile"
                        fi

                        ;;
                Debian)
                        if [ `expr $_VER \>= 4 \& $_VER \< 7` -eq 1 ]
                        then
                                BENCHMARK="CIS_Debian_Linux_3_Benchmark_v1.0.0.xml"
                                PROFILE="debian-complete-profile"
                        fi

                        ;;
                HPUX)
                        if [ `expr $_VER \>= 11 \& $_VER \< 12` -eq 1 ]
                        then
                                BENCHMARK="CIS_HP-UX_11i_Benchmark_v1.4.2.xml"
                                PROFILE="Level 2 Profile"
                        fi

                        ;;
                AIX)
                                                # AIX 4.3 - 5.1
                        if [ `expr $_VER \>= 4.3 \& $_VER \< 5.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_4.3-5.1_Benchmark_v1.0.1.xml"
                                PROFILE="Level 1 Profile"
                        fi

                                                # AIX 5.3 - 6.1
                        if [ `expr $_VER \>= 5.3 \& $_VER \< 6.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_4.3-5.1_Benchmark_v1.0.1.xml"
                                PROFILE="Level 2"
                        fi

                                                # AIX 7.1
                        if [ `expr $_VER \>= 7.1 \& $_VER \< 7.2` -eq 1 ]
                        then
                                BENCHMARK="CIS_IBM_AIX_7.1_Benchmark_v1.1.0.xml"
                                PROFILE="Level 2"
                        fi


                        ;;
                RedHat)
                        # RHEL 4
                        if [ `expr $_VER \>= 4.0 \& $_VER \< 5.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_4_Benchmark_v1.0.5.xml"
                                PROFILE="level-1"
                        fi

                        # RHEL 5
                        if [ `expr $_VER \>= 5.0 \& $_VER \< 6.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.0.0.xml"
                                PROFILE="level-1"
                        fi

                        # RHEL 6
                        if [ `expr $_VER \>= 6.0 \& $_VER \< 7.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.2.0.xml"
                                PROFILE="level-1"
                        fi

                        ;;
            CentOS)
                        # RHEL 4
                        if [ `expr $_VER \>= 4.0 \& $_VER \< 5.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_4_Benchmark_v1.0.5.xml"
                                PROFILE="level-2"
                        fi

                        # RHEL 5
                        if [ `expr $_VER \>= 5.0 \& $_VER \< 6.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.0.0.xml"
                                PROFILE="level-2"
                        fi

                        # RHEL 6
                        if [ `expr $_VER \>= 6.0 \& $_VER \< 7.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.1.0.xml"
                                #                              BENCHMARK="CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.2.0.xml"
                                #PROFILE="Level 1"
                                PROFILE="Level 2"
                        fi

                        ;;
               SUSE)
                        # SUSE 10
                        if [ `expr $_VER \>= 10.0 \& $_VER \< 11.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_10_Benchmark_v2.0.0.xml"
                                PROFILE="Complete rule set"
                        fi

                        # SUSE 9
                        if [ `expr $_VER \>= 9.0 \& $_VER \< 10.0` -eq 1 ]
                        then
                                BENCHMARK="CIS_SUSE_Linux_Enterprise_Server_9_Benchmark_v1.0.0.xml"
                                PROFILE="Complete rule set"
                        fi

                        ;;

                Solaris)

                        # Solaris 11
                        if [ `expr $_VER == 5.11` -eq 1 ]
                        then
                                BENCHMARK="CIS_Oracle_Solaris_11_Benchmark_v1.0.0.xml"
                                PROFILE="Level 2"
                        fi

                        # Solaris 10
                        if [ `expr $_VER == 5.10` -eq 1 ]
                        then
                                BENCHMARK="CIS_Oracle_Solaris_10_Benchmark_v5.1.0.xml"
                                PROFILE="Level 2"
                        fi

                        # Solaris 2.5.1-9
                        if [ `expr $_VER \< 5.10` -eq 1 ]
                        then
                                BENCHMARK="CIS_Oracle_Solaris_2.5.1-9_Benchmark_v1.3.0.xml"
                                PROFILE="Level 1 Profile"
                        fi

                        ;;

                        #
                        # CIS_Slackware_Linux_10.2_Benchmark_v1.1.0.xml SlackWare benchmark is not integrated.
                        #       

#               *)
#
#
#                       ;;
        esac

	write_log "${FUNC}: ${SERVER}: BENCHMARK = ${BENCHMARK}, PROFILE = ${PROFILE}" 
	write_log "${FUNC}: ${SERVER}: EXIT" 
	
	return 0 
}

function transfer_distribution ()
{
	FUNC="transfer_distribution" 
	write_log "${FUNC}: ${SERVER}: CALLED" 

	# check for executables
	SCP="`which scp 2> /dev/null | head -1`"
			
	MESSAGE="${FUNC}: ${SERVER}: Check SCP path -->"

	if test -x "${SCP}"; 
		then 
			write_log "$MESSAGE ${SCP} found"
		else 
			write_log "$MESSAGE SCP NOT found!"
			write_log "${FUNC}: EXIT @ SCP Test" 
			return 1
	fi   
	
	scp ${SOURCE_DIR}/${SOURCE_FILE} ${USR}@${SERVER}:${DESTINATION_DIR} < /dev/null 
	# debugging in case we run into trouble	
	#scp -vv ${SOURCE_DIR}/${SOURCE_FILE} ${USR}@${SERVER}:${DESTINATION_DIR}

	check_process_status $?	"${FUNC}: ${SERVER}: SCP "

	MESSAGE="${FUNC}: ${SERVER}: Transfer --> ${SOURCE_DIR}/${SOURCE_FILE} to ${SERVER}/${DESTINATION_DIR} "
	write_log "$MESSAGE"

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

function untar_distribution_remote ()
{
	FUNC="untar_distribution_remote" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
	
	DESTINATION_FILE="${DESTINATION_DIR}/${SOURCE_FILE}"

	#ssh ${SSH_OPTIONS} ${USR}@${SERVER} cd ${DESTINATION_DIR} ; tar -xf ${SOURCE_FILE}	
			
	ssh ${SSH_OPTIONS} ${USR}@${SERVER} "cd ${DESTINATION_DIR} ; echo " dir before " ;ls ${SOURCE_FILE} ; tar -xpvf ${SOURCE_FILE} ;echo "dir after"; ls ${SOURCE_DISTRO} " 2>&1 | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: untar responded --> $output"
			
	done 

	check_process_status $?	"${FUNC}: ${SERVER}: untar "

	MESSAGE="${FUNC}: ${SERVER}: untar --> 	${DESTINATION_FILE}"
	write_log "$MESSAGE"

	ssh ${SSH_OPTIONS} ${USR}@${SERVER} "cd ${DESTINATION_DIR} ; rm ${SOURCE_FILE}" 2>&1 | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: clean up responded --> $output"
	
	done 

	check_process_status $?	"${FUNC}: ${SERVER}: clean up "

	MESSAGE="${FUNC}: ${SERVER}: clean up --> 	${DESTINATION_FILE}"
	write_log "$MESSAGE"
	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

function exec_distribution_remote ()
{
	FUNC="exec_distribution_remote" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
	
	# CISCAT_OPTS=" -a -s -x -r $REPORTS_DIR -b $CISCAT_DIR/benchmarks/$BENCHMARK "
	# CISCAT_CMD="$JAVA_HOME/bin/java -jar $CISCAT_DIR/CISCAT.jar $CISCAT_OPTS"
	# $CISCAT_CMD -p "$PROFILE"
	
	CISCAT_BENCH=$BENCHMARK
	CISCAT_PROFI=$PROFILE
	
	show_status
		
ssh ${SSH_OPTIONS} ${USR}@${SERVER} mkdir ${REPORT_DIR_REMOTE} 2>&1 ; export JAVA_HOME="${JAVA_HOME}" 
ssh ${SSH_OPTIONS} ${USR}@${SERVER} "sudo -S ${REMOTE_JAVA_PATH} -Xmx512M -jar ${CISCAT_DIR}/CISCAT.jar ${CISCAT_PARAM} ${CISCAT_DIR}/benchmarks/${CISCAT_BENCH} -p \"${CISCAT_PROFI}\" -r ${REPORT_DIR_REMOTE} ${CISCAT_RPARA} 2>&1 << EOF
$PASSWORD
EOF
"| while read output;
		do
	
		write_log "${FUNC}: ${SERVER}: CIS-CAT reports --> $output"
	
	done 			

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}


function transfer_back_results ()
{
	FUNC="transfer_back_results" 
	write_log "${FUNC}: ${SERVER}: CALLED" 

	# check for executables
	SCP="`which scp 2> /dev/null | head -1`"
			
	MESSAGE="${FUNC}: ${SERVER}: Check SCP path -->"

	if test -x "${SCP}"; 
		then 
			write_log "$MESSAGE ${SCP} found"
		else 
			write_log "$MESSAGE SCP NOT found!"
			write_log "${FUNC}: EXIT @ SCP Test" 
			return 1
	fi   

	MESSAGE="${FUNC}: ${SERVER}: Path -->"
	
	if [ -d "${REPORT_DIR_LOCAL}" ]; then
  		write_log "$MESSAGE ${REPORT_DIR_LOCAL} exist"
	else
		RESPONSE=`mkdir ${REPORT_DIR_LOCAL} 2>&1 < /dev/null`
		write_log "$MESSAGE ${REPORT_DIR_LOCAL} -> ${RESPONSE}"
	fi				
		
	RESPONSE=`cd ${REPORT_DIR_LOCAL} 2>&1`
	write_log "$MESSAGE ${RESPONSE}"
	
	if [ -d "${REPORT_DIR_LOCAL}/${SERVER}" ]; then
  		write_log "$MESSAGE ${REPORT_DIR_LOCAL}/${SERVER} exist"
	else
		RESPONSE=`mkdir ${REPORT_DIR_LOCAL}/${SERVER} 2>&1 < /dev/null`
		write_log "$MESSAGE ${REPORT_DIR_LOCAL}/${SERVER} -> ${RESPONSE}"
	fi				
		
	scp ${USR}@${SERVER}:${REPORT_DIR_REMOTE}/* ${REPORT_DIR_LOCAL}/${SERVER} < /dev/null 

	check_process_status $?	"${FUNC}: ${SERVER}: SCP "

	MESSAGE="${FUNC}: ${SERVER}: Transfered --> content from ${SERVER}:${REPORT_DIR_REMOTE} to ${REPORT_DIR_LOCAL}/${SERVER} "
	write_log $MESSAGE

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

function remove_distribution_remote ()
{
	FUNC="remove_distribution_remote" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
		
	ssh ${SSH_OPTIONS} ${USR}@${SERVER} rm -rf ${DESTINATION_DIR}/${SOURCE_DISTRO} | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: reported --> $output"
	
	done 			

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

function remove_reports_remote ()
{
	FUNC="remove_reports_remote" 
	write_log "${FUNC}: ${SERVER}: CALLED" 
		
	ssh ${SSH_OPTIONS} ${USR}@${SERVER} rm -rf ${REPORT_DIR_REMOTE} 2>&1 | while read output;
	do
	
			write_log "${FUNC}: ${SERVER}: reported --> $output"
	
	done 			

	write_log "${FUNC}: ${SERVER}: EXIT"
	return 0 
}

#### MAIN
#check_hash_algo_support 
#check_distribution_source ${SOURCE_FILE}

# credential set by do_ssh_askpass is used and required for any ssh commands within all other function!
do_ssh_askpass

for SERVER in ${SERVERS} ; do

	measure_process START
	
	check_remote_ssh_connection
	
	case $? in
		0) 	#Process terminated with NO problems
			write_log "MAIN reported connection established to ${SERVER}!"
			;;
		1) 	#Process terminated with problems
			write_log "MAIN reported cannot connect to ${SERVER}!"
			exit 1
			;;
		*) 	#Do not know what's going on "return code = $1"
			write_log "MAIN reported ERROR code $?"
			exit 1
			;;
	esac

	detect_os_variant_ssh
	map_to_benchmark ${DISTRO} ${VER}	
	check_remote_disc_space
	check_remote_java_installation
	
	transfer_distribution
	untar_distribution_remote

	check_remote_ssh_connection_sudo
	exec_distribution_remote
 
	transfer_back_results
	remove_distribution_remote
	remove_reports_remote

	measure_process STOP
	measure_process SHOW

done
exit 0