#!/bin/bash
#Author: hrg
#installerLocation=/opt/Infa_Installer
#installedLocation=/opt/Informatica
infaHome=/opt/Informatica
infaDownloads=/opt/downloads
licenseLocation=$1
dbServerPassword=$2
dbServerAddress=$3
dbServerPort="1433"
dbType="MSSQLServer"
domainName="Domain"
domainUsername=$4
domainPassword=$5
domainHostname=`hostname`
gatewayIp=${6}
highavAilability=${7}
haNodeName="node02"
nodeName="node01"
privateIp=`hostname -I`
isHAEnable=$8
ihshostname=$9
ihsip0=${10}
ihsip1=${11}
ihsip2=${12}
ihsip3=${13}
ihsip4=${14}
ihsip5=${15}
loadType=${16}
#$databricksUrl=${8}
#$databricksclusterID=${9}
#$databricksclusterToken=${10}
oneclicksolutionlog="/opt/Oneclicksolution.log"
logFile="/opt/Oneclicksolution.log"
oldDomainPassword="Administrator"
olddomainUser="Administrator"


logger()
{
	#Usage -  logger "${logStatement}" "${logFile}" "${logType}"
	logStatement=$1
	logFile=$2
	logType=$3
	
	logTypeU=$(echo $logType | tr 'a-z' 'A-Z')
	currnet_time=$(date)
	echo -e "\n---" &>> $logFile
	echo -e "[${logTypeU}] ${currnet_time} ::  ${logStatement}" &>> $logFile
}

configureMSSQL()
{
	logger "Configuring MSSQLServer properties..." "${logFile}" "info"
	sed -i -e "s/10.13.0.4/${dbServerAddress}/g" ${infaHome}/ODBC7.1/odbc.ini
	sed -i -e "s/\/home\/Informatica\/10.2.2/\/opt\/Informatica/g" $infaHome/ODBC7.1/odbc.ini
	
	export INFA_JDK_HOME=$infaHome/java
	export INFAINSTALL=$infaHome
	export ODBCHOME=${INFAINSTALL}/ODBC7.1
	export ODBCINI=${ODBCHOME}/odbc.ini
	export ODBCINST=${ODBCHOME}/odbcinst.ini
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${ODBCHOME}/lib:${INFAINSTALL}/server/bin:${INFAINSTALL}/DataTransformation/bin:${INFAINSTALL}/services/shared/bin
	export JAVA_HOME=/javasrc/java
	export PATH=${PATH}:$infaHome/ODBC7.1/bin:${JAVA_HOME}/bin:${INFAINSTALL}/server/bin:${INFAINSTALL}/DataTransformation/bin
	
	sed -i -e "s/INFA_JDK_HOME=\/opt\/Informatica\/java\/jre/INFA_JDK_HOME=\/opt\/Informatica\/java/g" /home/infa/.bash_profile
    sed -i -e "s/INFA_JDK_HOME=\/opt\/Informatica\/java\/jre/INFA_JDK_HOME=\/opt\/Informatica\/java/g" /home/infa/.bashrc
}

tnsOraHostUpdate()
{
	logger "Configuring MSSQLServer properties..." "${logFile}" "info"
	sed -i -e "s/10.13.0.4/${dbServerAddress}/g" ${infaHome}/ODBC7.1/odbc.ini
	sed -i -e "s/\/home\/Informatica\/10.2.2/\/opt\/Informatica/g" $infaHome/ODBC7.1/odbc.ini
	
	export INFA_JDK_HOME=$infaHome/java
	export INFAINSTALL=$infaHome
	export ODBCHOME=${INFAINSTALL}/ODBC7.1
	export ODBCINI=${ODBCHOME}/odbc.ini
	export ODBCINST=${ODBCHOME}/odbcinst.ini
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${ODBCHOME}/lib:${INFAINSTALL}/server/bin:${INFAINSTALL}/DataTransformation/bin:${INFAINSTALL}/services/shared/bin
	export JAVA_HOME=/javasrc/java
	export PATH=${PATH}:$infaHome/ODBC7.1/bin:${JAVA_HOME}/bin:${INFAINSTALL}/server/bin:${INFAINSTALL}/DataTransformation/bin

	sed -i -e "s/INFA_JDK_HOME=\/opt\/Informatica\/java\/jre/INFA_JDK_HOME=\/opt\/Informatica\/java/g" /home/infa/.bash_profile
    sed -i -e "s/INFA_JDK_HOME=\/opt\/Informatica\/java\/jre/INFA_JDK_HOME=\/opt\/Informatica\/java/g" /home/infa/.bashrc
}


preparepasswordlessssh()
{

mkdir /home/infa/.ssh/
echo " " >> /home/infa/.ssh/authorized_keys
cat /opt/keys/authorized_keys >> /home/infa/.ssh/authorized_keys
cp /opt/keys/id_rsa.pub /home/infa/.ssh/id_rsa.pub
cp /opt/keys/id_rsa /home/infa/.ssh/id_rsa
chmod 600 /home/infa/.ssh/authorized_keys /home/infa/.ssh/id_rsa /home/infa/.ssh/id_rsa.pub
sudo chown -R infa:infa /home/infa/.ssh/

mkdir /root/.ssh/
 echo " " >> /root/.ssh/authorized_keys
cat /opt/keys/authorized_keys >> /root/.ssh/authorized_keys
cp /opt/keys/id_rsa.pub /root/.ssh/id_rsa.pub
cp /opt/keys/id_rsa /root/.ssh/id_rsa
chmod 600 /root/.ssh/authorized_keys /root/.ssh/id_rsa /root/.ssh/id_rsa.pub
}

configureDatabase()
{
	if [ $dbType = 'MSSQLServer' ]
	then
		configureMSSQL
	else
		tnsOraHostUpdate
	fi
}

hostProcess()
{
	logger "Updating host entries for Informatica EDC domain..." "${logFile}" "info"
	host=`hostname`
	privateIp=`hostname -I`
	echo "$privateIp  $host  $host" >> /etc/hosts
}

hostProcessHA()
{
	logger "Updating host entries for Informatica EDC domain..." "${logFile}" "info"
	host=`hostname`
	privateIp=`hostname -I`
	echo "$privateIp  $host  $host" >> /etc/hosts

	Gatewayhost=`sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "hostname -f"`
	Gatewayhostshort=`sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "hostname"`
	echo -e "" >> /etc/hosts
	echo -e "${gatewayIp} ${Gatewayhost} ${Gatewayhostshort}" >> /etc/hosts
	
	sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
	sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
	sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "sudo su -c 'printf \"\n \" >> /etc/hosts'"

	i=0
	fdns='.net'
	datanode=''
	if [[ $loadType == "low" ]]
		then
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
	elif [[ $loadType == "medium" ]]
		then
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns1=$(ssh -o StrictHostKeyChecking=no root@$ihsip1 "hostname")
			fulldns1=$dns1$fdns
			echo $ihsip1 $fulldns1 $dns1 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns2=$(ssh -o StrictHostKeyChecking=no root@$ihsip2 "hostname")
			fulldns2=$dns2$fdns
			echo $ihsip2 $fulldns2 $dns2 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
	else
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip0} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns1=$(ssh -o StrictHostKeyChecking=no root@$ihsip1 "hostname")
			fulldns1=$dns1$fdns
			echo $ihsip1 $fulldns1 $dns1 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip1} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns2=$(ssh -o StrictHostKeyChecking=no root@$ihsip2 "hostname")
			fulldns2=$dns2$fdns
			echo $ihsip2 $fulldns2 $dns2 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip2} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns3=$(ssh -o StrictHostKeyChecking=no root@$ihsip3 "hostname")
			fulldns3=$dns3$fdns
			echo $ihsip3 $fulldns3 $dns3 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip3} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip3} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip3} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns4=$(ssh -o StrictHostKeyChecking=no root@$ihsip4 "hostname")
			fulldns4=$dns4$fdns
			echo $ihsip4 $fulldns4 $dns4 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip4} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip4} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip4} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			dns5=$(ssh -o StrictHostKeyChecking=no root@$ihsip5 "hostname")
			fulldns5=$dns5$fdns
			echo $ihsip5 $fulldns5 $dns5 >> /etc/hosts
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip5} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip5} "sudo su -c 'printf \"${privateIp} ${host} ${host}\" >> /etc/hosts'"
			sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${ihsip5} "sudo su -c 'printf \"\n \" >> /etc/hosts'"
	fi

}


configureDomain()
{
	if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="domainuser"
		dbtyp="MSSQLServer"
		dbnm="domaindb"
	else
		dbusr="domainuser"
		dbtyp="Oracle"
		dbnm=$dbName
	fi
	
	logger "Stopping Infa services..." "${logFile}" "info"
	sudo /etc/init.d/infaservice stop &>> $logFile
	sleep 60
	kill $(ps aux | grep '[J]ava' | awk '{print $2}') &>> $logFile
	sleep 60

	logger "Configuring Domain..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infasetup.sh updateGatewayNode -da ${dbServerAddress}:${dbServerPort} -du ${dbusr} -dp ${dbServerPassword} -dt ${dbtyp} -ds ${dbnm} -na ${domainHostname}:6005 -resetHostPort true &>> $logFile
	sudo chown -R infa:infa $infaHome
	
	logger "Bringing Domain up..." "${logFile}" "info"
	#sh ${infaHome}/tomcat/bin/infaservice.sh startup  &>> $logFile
	sudo /etc/init.d/infaservice start &>> $logFile
	sleep 120
	sudo chkconfig infaservice on
	
	logger "Checking Admin Console status..." "${logFile}" "info"
	status=$(${infaHome}/isp/bin/infacmd.sh  ping -dn $domainName -sn _AdminConsole -re 360)
	chkCount=0
	while [[ $status != *"Command ran successfully"* ]]
	do
		if [ $chkCount -eq 20 ]
		then
			logger "Domain is not up. Something went wrong. Exiting..." "${logFile}" "error"
			exit 1
		fi
		chkCount=`expr ${chkCount} + 1`
		sleep 10
		status=$(${infaHome}/isp/bin/infacmd.sh  ping -dn $domainName -sn _AdminConsole -re 360)
	done

	logger "Changing Domain to HTTPS mode ..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh isp UpdateDomainOptions -dn $domainName -un $olddomainUser -pd $oldDomainPassword -do TLSMode=true  &>> $logFile

	logger "Changing MasterDB Refresh Interval to avoid domain timeout ..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh isp UpdateDomainOptions -dn $domainName -un $olddomainUser -pd $oldDomainPassword -do MasterDBRefreshInterval=180 &>> $logFile

	logger "Changing Restart max attemps to One ..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh isp UpdateDomainOptions -dn $domainName -un $olddomainUser -pd $oldDomainPassword -do RestartsMaxAttempts=1 &>> $logFile

	logger "Starting Infa services..." "${logFile}" "info"
	sudo /etc/init.d/infaservice stop &>> $logFile
	sleep 120

	logger "Generating the keystore ..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -genkey -alias infa_dflt -keyalg RSA -keypass changeit -storepass changeit -keystore ${infaHome}/tomcat/conf/Default.keystore -dname CN=$privateDnsName,OU=Informatica,O=Informatica,L=RedwoodCity,S=California,C=US -validity 365 &>> $logFile
	
	logger "Updating the Gateway node to HTTPS mode ..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infasetup.sh updateGatewayNode -tls true -hs 8443 -kf ${infaHome}/tomcat/conf/Default.keystore -rst &>> $logFile
	
	logger "Updating the Gateway node ciphers ..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infasetup.sh updateGatewayNode -cwl TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA &>> $logFile

	logger "Exporting the keystore ..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -export -keystore ${infaHome}/tomcat/conf/Default.keystore -alias infa_dflt -storepass changeit -file ${infaHome}/tomcat/conf/infa_dflt.cert  &>> $logFile
	
	logger "Generating the truststore ..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -import -noprompt -file ${infaHome}/tomcat/conf/infa_dflt.cert -alias infa_dflt -keystore ${infaHome}/services/shared/security/infa_truststore.jks -storepass pass2038@infaSSL &>> $logFile
	
	logger "Importing java certs to Infa Truststore..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -importkeystore -srckeystore ${infaHome}/java/jre/lib/security/cacerts -destkeystore ${infaHome}/services/shared/security/infa_truststore.jks -srcstorepass changeit -deststorepass pass2038@infaSSL &>> $logFile
	
	logger "Deleting files ..." "${logFile}" "info"
	rm -rf ${infaHome}/tomcat/work/* &>> $logFile
	rm -rf ${infaHome}/tomcat/temp/* &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/ROOT &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/adminconsole &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/coreservices &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/csm &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/ROOT &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/adminconsole &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/adminhelp/ &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/adminhelp/ &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/administrator &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/monitoring &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/ows &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/passwordchange &>> $logFile
	rm -rf ${infaHome}/logs/ &>> $logFile

	#logger "Copying the Truststore file to Hadoop Gateway node ..." "${logFile}" "info"
	#scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@${hdpGatewayNodePubDns}:/opt &>> $logFile
	sudo chown -R infa:infa $infaHome 

	logger "Starting the Infa services ..." "${logFile}" "info"
	sudo /etc/init.d/infaservice start &>> $logFile
	sleep 120
	
	logger "Configuring Administrator user..." "${logFile}" "info"
	domainUserUppercase=$(echo $domainUsername | tr 'a-z' 'A-Z')
	if [[ $domainUserUppercase == "ADMINISTRATOR" ]] && [[ $domainPassword == "Administrator" ]]
	then
	logger "No Change required for Administrator user. We recommend to change domain password after the installation finishes." "${logFile}" "info"
	elif [[ $domainUserUppercase == "ADMINISTRATOR"  ]]
	then
		logger "Changing password for Administrator user..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh  resetPassword -dn $domainName -un $olddomainUser -pd $oldDomainPassword -ru $olddomainUser -rp $domainPassword &>> $logFile
	else
		logger "Creating new Administrator user - ${domainUsername}..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh createUser -dn $domainName -un $olddomainUser -pd $oldDomainPassword -nu $domainUsername -np $domainPassword -nf $domainUsername &>> $logFile
		
		logger "Assigning roles and groups to user - ${domainUsername}..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh assignRoleTouser -dn $domainName -un $olddomainUser -pd $oldDomainPassword -eu $domainUsername -rn Administrator -sn $domainName &>> $logFile
		sh ${infaHome}/isp/bin/infacmd.sh addUserToGroup -dn $domainName -un $olddomainUser -pd $oldDomainPassword -eu $domainUsername -gn Administrator &>> $logFile
		
		logger "Changing Administrator password to new password..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh resetPassword -dn $domainName -un $olddomainUser -pd $oldDomainPassword -ru $olddomainUser -rp $domainPassword &>> $logFile
	fi
}

addLicense()
{
	curl -o License.key "$licenseLocation"
	mv License.key $infaDownloads
	logger "Adding License to Domain..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh addLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -lf ${infaDownloads}/License.key &>> $logFile
	shred --remove ${infaDownloads}/License.key
}

createMRS()
{
	if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="mrsuser"
		MACString="jdbc:informatica:sqlserver://${dbServerAddress}:${dbServerPort};DatabaseName=mrsdb"
		db_schema="dbo"
	else
		dbusr="mrsuser"
		MACString="jdbc:informatica:oracle://${dbServerAddress}:${dbServerPort};ServiceName=${dbName}"
		db_schema=""
	fi
	
	logger "Configuring Model Repository Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh mrs updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn MRS -o "PERSISTENCE_DB.DatabaseSchema=${db_schema} PERSISTENCE_DB.Password=${dbServerPassword} PERSISTENCE_DB.JDBCConnectString=${MACString}" &>> $logFile
	
	logger "Applying License to Model Repository Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'MRS' &>> $logFile
	
	logger "Updating Model Repository Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh updateMonitoringOptions -dn $domainName -un $domainUsername -pd $domainPassword -rs MRS -rsun $domainUsername -rspd $domainPassword &>> $logFile
}

createDIS()
{
	logger "Applying License to Data Integration Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'DIS' &>> $logFile
	
	#hdpDisDir="${infaHome}/services/shared/hadoop/Dataproc_1.4"
	
	logger "Configuring Data Integration Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh dis updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn 'DIS' -o "RepositoryOptions.RepositoryUserName='${domainUsername}' RepositoryOptions.RepositoryPassword='${domainPassword}'" &>> $logFile
    
	logger "Configuring Data Integration Service to HTTPS Mode..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh dis updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn 'DIS' -o 'HttpConfigurationOptions.HTTPProtocolType=https' &>> $logFile
	
	logger "Configuring other Data Integration Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh dis UpdateServiceProcessOptions -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'DIS' -o "GeneralOptions.HttpsPort=18095 HttpConfigurationOptions.KeyStoreFile=${infaHome}/tomcat/conf/Default.keystore HttpConfigurationOptions.KeyStorePassword=changeit HttpConfigurationOptions.TrustStoreFile=${infaHome}/services/shared/security/infa_truststore.jks HttpConfigurationOptions.TrustStorePassword=pass2038@infaSSL" &>> $logFile
}

createMASS()
{
	logger "Creating Metadata Accesss Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh mas createService -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'MAS' -hp https -spt 7080 -kf ${infaHome}/tomcat/conf/Default.keystore -kp changeit -tf ${infaHome}/services/shared/security/infa_truststore.jks -tp pass2038@infaSSL &>> $logFile
	logger "Applying License to Metadata Accesss Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'MAS' &>> $logFile
}

createMASSHA()
{
	logger "Creating Metadata Accesss Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh mas createService -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -bn $haNodeName -sn 'MAS' -hp https -spt 7080 -kf ${infaHome}/tomcat/conf/Default.keystore -kp changeit -tf ${infaHome}/services/shared/security/infa_truststore.jks -tp pass2038@infaSSL &>> $logFile
	logger "Applying License to Metadata Accesss Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'MAS' &>> $logFile
}

createCMS()
{
	logger "Creating Content Management Service..." "${logFile}" "info"
	
	sh ${infaHome}/isp/bin/infacmd.sh cms createService -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'CMS' -ds DIS -HttpsPort 18105 -rs MRS -rdl StagingDBConnection -rsu $domainUsername -rsp $domainPassword -KeystoreFile ${infaHome}/tomcat/conf/Default.keystore -KeystorePassword changeit &>> $logFile


	logger "Applying License to Content Management Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'CMS' &>> $logFile
}

createIHS()
{
 	logger "Syncing NTP on Infa Domain node..." "${logFile}" "info"
	sudo service ntpd restart

	logger "Updating host entries of IHS nodes for Informatica EDC domain..." "${logFile}" "info"
	i=0
	fdns='.net'
	datanode=''
	if [[ $loadType == "low" ]]
		then
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			namenode=$fulldns
			datanode=$fulldns
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip0:/etc
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
	elif [[ $loadType == "medium" ]]
		then
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			dns1=$(ssh -o StrictHostKeyChecking=no root@$ihsip1 "hostname")
			fulldns1=$dns1$fdns
			echo $ihsip1 $fulldns1 $dns1 >> /etc/hosts
			dns2=$(ssh -o StrictHostKeyChecking=no root@$ihsip2 "hostname")
			fulldns2=$dns2$fdns
			echo $ihsip2 $fulldns2 $dns2 >> /etc/hosts
			namenode=$fulldns
			datanode=$fulldns,$fulldns1,$fulldns2
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip0:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip1:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip2:/etc
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip1:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip2:/opt
	else
			dns=$(ssh -o StrictHostKeyChecking=no root@$ihsip0 "hostname")
			fulldns=$dns$fdns
			echo $ihsip0 $fulldns $dns >> /etc/hosts
			dns1=$(ssh -o StrictHostKeyChecking=no root@$ihsip1 "hostname")
			fulldns1=$dns1$fdns
			echo $ihsip1 $fulldns1 $dns1 >> /etc/hosts
			dns2=$(ssh -o StrictHostKeyChecking=no root@$ihsip2 "hostname")
			fulldns2=$dns2$fdns
			echo $ihsip2 $fulldns2 $dns2 >> /etc/hosts
			dns3=$(ssh -o StrictHostKeyChecking=no root@$ihsip3 "hostname")
			fulldns3=$dns3$fdns
			echo $ihsip3 $fulldns3 $dns3 >> /etc/hosts
			dns4=$(ssh -o StrictHostKeyChecking=no root@$ihsip4 "hostname")
			fulldns4=$dns4$fdns
			echo $ihsip4 $fulldns4 $dns4 >> /etc/hosts
			dns5=$(ssh -o StrictHostKeyChecking=no root@$ihsip5 "hostname")
			fulldns5=$dns5$fdns
			echo $ihsip5 $fulldns5 $dns5 >> /etc/hosts
			namenode=$fulldns
			datanode=$fulldns,$fulldns1,$fulldns2,$fulldns3,$fulldns4,$fulldns5
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip0:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip1:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip2:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip3:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip4:/etc
			scp -o StrictHostKeyChecking=no /etc/hosts root@$ihsip5:/etc
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip1:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip2:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip3:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip4:/opt
			scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip5:/opt
	fi
	
	sleep 10

	logger "Creating Informatica Hadoop Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh ihs createservice -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'IHS' -tls true -sp 18205 -kf ${infaHome}/tomcat/conf/Default.keystore -kp changeit -hgh ${namenode} -hgp 8080 -hn ${datanode} -gu root -krb false -dssl -tf /opt/infa_truststore.jks -tp pass2038@infaSSL true -opwd false  &>> $logFile
	
	logger "Applying License to Informatica Hadoop Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'IHS' &>> $logFile
	
	logger "Updating Informatica Hadoop Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh ihs updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn 'IHS' -o AdvanceOptions.domainTrustStorePassword=pass2038@infaSSL &>> $logFile

}

createEDC()
{

	logger "Creating Catalog Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh LDM createService -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'EDC' -mrs 'MRS' -mrsun ${domainUsername} -mrspd ${domainPassword} -sp 9085 -tls true -kf ${infaHome}/tomcat/conf/Default.keystore -kp changeit -ise false -ihsn 'IHS' -cssl true -cne false -lt $loadType -ed false &>> $logFile
	
	logger "Applying License to Catalog Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'EDC' &>> $logFile

	logger "Updating Catalog Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh LDM updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn 'EDC' -o ProjectRepository.adminPassword=${domainPassword} &>> $logFile
}

createAT()
{

	logger "Creating Analyst Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh as createService -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'AS' -rs MRS -ds DIS -ffl /tmp -cs EDC -csau ${domainUsername} -csap ${domainPassword} -au ${domainUsername} -ap ${domainPassword} -bgefd /tmp -HttpPort 6805 &>> $logFile
	
	logger "Applying License to Analyst Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh assignLicense -dn $domainName -un $domainUsername -pd $domainPassword -ln License -sn 'AS' &>> $logFile
	
	logger "Modifying to Analyst Service properties..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh as updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn 'AS' -o "HumanTaskDataIntegrationService.humanTaskDsServiceName=DIS HumanTaskDataIntegrationService.exceptionDbName=exceptionAuditConnection" &>> $logFile
	
	logger "Modifying to Analyst Service properties..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh as updateServiceProcessOptions -dn $domainName -un $domainUsername -pd $domainPassword -nn $nodeName -sn 'AS' -o "GeneralOptions.HttpsPort=16805 GeneralOptions.KeystoreFile=${infaHome}/tomcat/conf/Default.keystore GeneralOptions.KeystorePassword=changeit" &>> $logFile

}

createProfilingWHConnection()
{
	if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="pwhuser"
		DACString="${dbServerAddress}@pwhdb"
		MACString="jdbc:informatica:sqlserver://${dbServerAddress}:${dbServerPort};DatabaseName=pwhdb"
		connType="SQLSERVER"
	else
		dbusr="pw_user"
		DACString="infadb"
		MACString="jdbc:informatica:oracle://${dbServerAddress}:${dbServerPort};ServiceName=${dbName}"
		connType="ORACLE"
	fi
	
	logger "Creating Profiling Warehouse Connection..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh UpdateConnection -dn $domainName -un $domainUsername -pd $domainPassword -cn 'ProfilingWarehouseConnection' -cun $dbusr -cpd $dbServerPassword -o "CodePage=UTF-8 MetadataAccessConnectString='${MACString}' DataAccessConnectString='${DACString}'" &>> $logFile
}

createStagingDBConnection()
{
if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="cmsuser"
		DACString="${dbServerAddress}@cmsdb"
		MACString="jdbc:informatica:sqlserver://${dbServerAddress}:${dbServerPort};DatabaseName=cmsdb"
		connType="SQLSERVER"
	else
		dbusr="cmsuser"
		DACString="infadb"
		MACString="jdbc:informatica:oracle://${dbServerAddress}:${dbServerPort};ServiceName=${dbName}"
		connType="ORACLE"
	fi
	
	logger "Creating Profiling Warehouse Connection..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh UpdateConnection -dn $domainName -un $domainUsername -pd $domainPassword -cn 'StagingDBConnection' -cun $dbusr -cpd $dbServerPassword -o "CodePage=UTF-8 MetadataAccessConnectString='${MACString}' DataAccessConnectString='${DACString}'" &>> $logFile
}

createExceptionAuditConnection()
{
if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="analystuser"
		DACString="${dbServerAddress}@analystdb"
		MACString="jdbc:informatica:sqlserver://${dbServerAddress}:${dbServerPort};DatabaseName=analystdb"
		connType="SQLSERVER"
	else
		dbusr="analystuser"
		DACString="infadb"
		MACString="jdbc:informatica:oracle://${dbServerAddress}:${dbServerPort};ServiceName=${dbName}"
		connType="ORACLE"
	fi
	
	logger "Creating Exception Audit Table Connection..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh createConnection -dn $domainName -un $domainUsername -pd $domainPassword -ct $connType -cn 'exceptionAuditConnection' -cun $dbusr -cpd $dbServerPassword -o "CodePage=UTF-8 MetadataAccessConnectString='${MACString}' DataAccessConnectString='${DACString}'" &>> $logFile
}

createWorkflowConnection()
{
	if [ $dbType = 'MSSQLServer' ]
	then
		dbusr="wfhuser"
		DACString="${dbServerAddress}@wfhdb"
		MACString="jdbc:informatica:sqlserver://${dbServerAddress}:${dbServerPort};DatabaseName=wfhdb"
		connType="SQLSERVER"
	else
		dbusr="wfhuser"
		DACString="infadb"
		MACString="jdbc:informatica:oracle://${dbServerAddress}:${dbServerPort};ServiceName=${dbName}"
		connType="ORACLE"
	fi
	
	logger "Creating Workflow Connection..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh UpdateConnection -dn $domainName -un $domainUsername -pd $domainPassword -cn 'WorkflowDBConnection' -cun $dbusr -cpd $dbServerPassword -o "CodePage=UTF-8 MetadataAccessConnectString='${MACString}' DataAccessConnectString='${DACString}'" &>> $logFile
}

enableMRS()
{
	logger "Enabling Model Repository Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn MRS &>> $logFile
}

enableDIS()
{
	logger "Enabling Data Integration Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn DIS &>> $logFile
}

enableMASS()
{
	logger "Enabling Metadata Accesss Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn MAS &>> $logFile
}

enableCMS()
{
	logger "Enabling Content Management Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn CMS &>> $logFile
}

enableIHS()
{
	logger "Enabling Informatica Hadoop Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn IHS &>> $logFile
}

cleanIHS()
{
	logger "Cleaning Informatica Hadoop Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh ihs cleanCluster -dn $domainName -un $domainUsername -pd $domainPassword -sn IHS &>> $logFile
	sleep 90
}

enableEDC()
{
	logger "Enabling Catalog Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn EDC &>> $logFile
}


checkAndReEnableIHS()
{
	logger "Checking Informatica Hadoop Service status..." "${logFile}" "info"
	ldmStatus=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -sn IHS)
	count=0
	while [[ $ldmStatus != *"Command ran successfully"* ]] || [[ $count -eq 60 ]]
	do
		logger "Disabling Informatica Hadoop Service Service..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh disableService -dn $domainName -un $domainUsername -pd $domainPassword -sn IHS -mo ABORT &>> $logFile
		sleep 10
		logger "Killing Informatica Hadoop Service..." "${logFile}" "info"
		kill $(ps aux | grep '[I]HS' | awk '{print $2}')
		cleanIHS
	    sleep 60
		logger "Re-enabling Informatica Hadoop Service..." "${logFile}" "info"
		sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn IHS &>> $logFile
		sleep 30
		count=`expr $count + 1`
		ldmStatus=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -sn IHS)
	done
}

checkAndReEnableLDM()
{
	logger "Checking Catalog Service status..." "${logFile}" "info"
	ldmStatus=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -sn EDC)
	while [[ $ldmStatus != *"Command ran successfully"* ]] || [[ $count -eq 60 ]]
	do
		#logger "Disabling Catalog Service..." "${logFile}" "info"
		#sh ${infaHome}/isp/bin/infacmd.sh disableService -dn $domainName -un $domainUsername -pd $domainPassword -sn EDC -mo ABORT &>> $logFile
		#sleep 10
		#logger "Killing Catalog Service..." "${logFile}" "info"
		#kill $(ps aux | grep '[E]DC' | awk '{print $2}')
		#echo $'for x in $(yarn application -list  | awk \'NR > 2 { print $1 }\'); do yarn application -kill $x; done' > ${infaDownloads}/ldmAppkill.sh
		#ssh root@${hdpGatewayNodePubDns} < ${infaDownloads}/ldmAppkill.sh
		#sleep 60
		#ssh root@${hdpGatewayNodePubDns} < ${infaDownloads}/ldmAppkill.sh
		#sleep 60
		#logger "Re-enabling Catalog Service..." "${logFile}" "info"
		#sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn EDC &>> $logFile
		sleep 30
		count=`expr $count + 1`
		ldmStatus=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -sn EDC)
	done
}

enableAT()
{	
	logger "Enabling Analyst Service..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh enableService -dn $domainName -un $domainUsername -pd $domainPassword -sn AS &>> $logFile
	
	logger "Creating Analyst Service Audit table contents..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh as createExceptionAuditTables -dn $domainName -un $domainUsername -pd $domainPassword -sn 'AS' &>> $logFile
}


createConnections()
{
	createWorkflowConnection
	createStagingDBConnection
	createProfilingWHConnection
	createExceptionAuditConnection
}

createServices()
{
	createMRS
	createDIS
	if [ $highavAilability = 'no' ]
	then
	createMASS
	fi
	createCMS
	createIHS
	createEDC
	createAT	
}

enableServices()
{
	enableMRS
	enableDIS
	enableMASS
	enableCMS
	enableIHS
	sleep 60
	checkAndReEnableIHS
	enableEDC
	sleep 60
	checkAndReEnableLDM
	sleep 60
	enableAT
}

configureHANode()
{
	logger "Configuring HA node for EDC..." "${logFile}" "info"
	rm -rf ${infaHome}/domains.infa ${infaHome}/isp/config/nodemeta.xml &>> $logFile
	
	sudo chown -R infa:infa $infaHome

	logger "Generating Encryption Key and Deleting temp files..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -genkey -alias infa_dflt1 -keyalg RSA -keypass changeit -storepass changeit -keystore ${infaHome}/tomcat/conf/Default.keystore -dname CN=$privateDnsName,OU=Informatica,O=Informatica,L=RedwoodCity,S=California,C=US -validity 365 &>> $logFile
	rm -rf ${infaHome}/tomcat/work/* &>> $logFile
	rm -rf ${infaHome}/tomcat/temp/* &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/ROOT &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/adminconsole &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/coreservices &>> $logFile
	rm -rf ${infaHome}/tomcat/webapps/csm &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/ROOT &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/adminconsole &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/adminhelp/  &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/administrator &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/monitoring &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/ows &>> $logFile
	rm -rf ${infaHome}/services/AdministratorConsole/webapps/passwordchange &>> $logFile
	rm -rf ${infaHome}/logs/
	
	logger "Exporting the keystore ..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -export -keystore ${infaHome}/tomcat/conf/Default.keystore -alias infa_dflt1 -storepass changeit -file ${infaHome}/tomcat/conf/infa_dflt.cert  &>> $logFile
	
	logger "Copying the truststore from Gateway node to this node ..." "${logFile}" "info"
	scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no root@${gatewayIp}:${infaHome}/services/shared/security/infa_truststore.jks ${infaHome}/services/shared/security/ &>> $logFile
	
	logger "Merging node keystore with Gateway truststore ..." "${logFile}" "info"
	${infaHome}/java/jre/bin/keytool -import -noprompt -file ${infaHome}/tomcat/conf/infa_dflt.cert -alias infa_dflt1 -keystore ${infaHome}/services/shared/security/infa_truststore.jks -storepass pass2038@infaSSL &>> $logFile
	
	logger "Copying the truststore from HA node to Gateway node ..." "${logFile}" "info"
	scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@${gatewayIp}:${infaHome}/services/shared/security/ &>> $logFile
	
	sudo ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${gatewayIp} "sudo chown -R infa:infa $infaHome" 
	
	logger "Configuring domains.infa file from Gateway node to this node..." "${logFile}" "info"
	scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no root@${gatewayIp}:${infaHome}/domains.infa ${infaHome}/ &>> $logFile

	sudo chown -R infa:infa $infaHome

	logger "Copying truststore to all the hadoop nodes..." "${logFile}" "info"
	if [[ $loadType == "low" ]]
		then
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
	elif [[ $loadType == "medium" ]]
		then
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip1:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip2:/opt
	else
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip0:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip1:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip2:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip3:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip4:/opt
			sudo scp -o StrictHostKeyChecking=no -o PasswordAuthentication=no ${infaHome}/services/shared/security/infa_truststore.jks root@$ihsip5:/opt
	fi


	logger "Defining worker node..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infasetup.sh defineWorkerNode -dn $domainName -un $domainUsername -pd $domainPassword -nn $haNodeName -na ${domainHostname}:6005 -dg ${gatewayIp}:6005 -rf ${infaHome}/isp/bin/nodeoptions.xml -bd ${infaHome}/server/infa_shared/Backup -tls true -kd ${infaHome}/isp/config/keys &>> $logFile
	logger "Checking Informatica Domain status..." "${logFile}" "info"
	status=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -dg ${gatewayIp}:6005)
	chkCount=0
	while [[ $status != *"Command ran successfully"* ]]
	do
		if [ $chkCount -eq 20 ]
		then
			logger "Domain is not up. Something went wrong. Exiting..." "${logFile}" "error"
			exit 1
		fi
		chkCount=`expr ${chkCount} + 1`
		sleep 10
		status=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -dg ${gatewayIp}:6005)
	done
	
	sudo chown -R infa:infa $infaHome
	logger "Adding HA node to Informatica Domain..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh addDomainNode -dn $domainName -un $domainUsername -pd $domainPassword -nn $haNodeName -hp ${gatewayIp}:6005 &>> $logFile

	logger "updating worker node..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infasetup.sh updateWorkerNode -dn $domainName -un $domainUsername -pd $domainPassword -nn $haNodeName -tls true -hs 8443 -kf ${infaHome}/tomcat/conf/Default.keystore -kp changeit   &>> $logFile
	
	sudo chown -R infa:infa $infaHome
	logger "Starting HA node..." "${logFile}" "info"
	sudo /etc/init.d/infaservice start
	sleep 60
	
	logger "Updating Informatica gateway node info..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh updategatewayinfo -dn $domainName -dg ${gatewayIp}:6005 &>> $logFile
	
	logger "Checking HA node status..." "${logFile}" "info"
	status=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -dg ${gatewayIp}:6005 -nn ${haNodeName} -re 300)
	chkCount=0
	while [[ $status != *"Command ran successfully"* ]]
	do
		if [ $chkCount -eq 20 ]
		then
			logger "Ha node is not responding. Exiting..." "${logFile}" "error"
			exit 1
		fi
		chkCount=`expr ${chkCount} + 1`
		sleep 10
		status=$(${infaHome}/isp/bin/infacmd.sh ping -dn $domainName -dg ${gatewayIp}:6005 -nn ${haNodeName} -re 300)
	done
	
	sudo chown -R infa:infa $infaHome
	logger "Switching HA to Gateway node..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh switchToGatewayNode -dn $domainName -un $domainUsername -pd $domainPassword -nn $haNodeName -ld ${infaHome}/isp/logs -saml false &>> $logFile
	
	sleep 60


	sudo chown -R infa:infa $infaHome
	logger "Adding back-up node to MRS..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh mrs updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn MRS -nn $nodeName -bn $haNodeName &>> $logFile
	
	logger "Adding back-up node to DIS..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh dis updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn DIS -nn $nodeName -bn $haNodeName &>> $logFile
	
	logger "Adding and Configuring Data Integration Service for SSL..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh dis UpdateServiceProcessOptions -dn $domainName -un $domainUsername -pd $domainPassword -nn $haNodeName -sn 'DIS' -o "GeneralOptions.HttpsPort=18095 HttpConfigurationOptions.KeyStoreFile=${infaHome}/tomcat/conf/Default.keystore HttpConfigurationOptions.KeyStorePassword=changeit HttpConfigurationOptions.TrustStoreFile=${infaHome}/services/shared/security/infa_truststore.jks HttpConfigurationOptions.TrustStorePassword=pass2038@infaSSL" &>> $logFile
	
	#logger "Adding back-up node to MASS..." "${logFile}" "info"
	#sh ${infaHome}/isp/bin/infacmd.sh mas updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn MAS -nn $nodeName -bn $haNodeName &>> $logFile

	logger "Adding back-up node to IHS..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh ihs updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn IHS -nn $nodeName -bn $haNodeName &>> $logFile

	logger "Adding back-up node to EDC..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh ldm updateServiceOptions -dn $domainName -un $domainUsername -pd $domainPassword -sn EDC -nn $nodeName -bn $haNodeName &>> $logFile
}

startServicesOnHANode()
{
	logger "Starting MRS service in back up node..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh EnableServiceProcess -dn $domainName -un $domainUsername -pd $domainPassword -sn MRS -nn $haNodeName &>> $logFile
	
	logger "Starting DIS service in back up node..." "${logFile}" "info"
	sh ${infaHome}/isp/bin/infacmd.sh EnableServiceProcess -dn $domainName -un $domainUsername -pd $domainPassword -sn DIS -nn $haNodeName &>> $logFile
}

ulimit -n 32000

logger "Number of parameters... $#" "${logFile}" "info"
	logger "Inputs are: $licenseLocation $dbServerPassword $dbServerAddress $domainUsername $domainPassword  $gatewayIp $highavAilability $isHAEnable $ihshostname $ihsip0 $ihsip1 $ihsip2 $ihsip3 $ihsip4 $ihsip5 $loadType" "${logFile}" "info"
  if [ $# -ne 16 ]
  then
	logger "silentlaunch.sh $licenseLocation $dbServerPassword $dbServerAddress $domainUsername $domainPassword  $gatewayIp $highavAilability $isHAEnable $ihshostname $ihsip0 $ihsip1 $ihsip2 $ihsip3 $ihsip4 $ihsip5 $loadType" "${logFile}" "info"
	exit -1
  fi

sed -i -e "s/DATABASE/$dbServerAddress/g" $infaHome/ODBC7.1/odbc.ini &>> $logFile



ulimit -n 50000
ulimit -u 50000

if [ $isHAEnable = 'no' ]
then
	logger "Staring Configuration for EDC on node ${nodeName}..." "${logFile}" "info"
	configureDatabase
	preparepasswordlessssh
	hostProcess
	export HOME=/home/infa
	configureDomain
	sh ${infaHome}/isp/bin/infacmd.sh removeService -dn $domainName -un $domainUsername -pd $domainPassword -sn PCRS
	addLicense
	createConnections
	createServices
	if [ $highavAilability = 'no' ]
	then
		enableServices
	fi
	
	logger "Configuration for EDC finished on node ${nodeName}..." "${logFile}" "info"
else
	logger "Staring Configuration for EDC on node ${haNodeName}..." "${logFile}" "info"
	
	if [ $dbType = 'MSSQLServer' ]
	then
		configureMSSQL
	else
		tnsOraHostUpdate
	fi
	
	hostProcessHA
	preparepasswordlessssh
	configureHANode
	createMASSHA
	enableServices
	startServicesOnHANode
	
	logger "Configuration for EDC finished on node ${haNodeName}..." "${logFile}" "info"
fi