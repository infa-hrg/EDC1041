Param(
  [string]$osUsername,
  [string]$osPassword,
  [string]$dbUsername,
  [string]$dbPassword,
  [string]$dbName
)
#Debug
#echo $osUsername $osPassword $dbUsername $dbPassword $dbName
Enable-PSRemoting -Force
$credential = New-Object System.Management.Automation.PSCredential @(($env:COMPUTERNAME + "\" + $osUsername), (ConvertTo-SecureString -String $osPassword -AsPlainText -Force))
Invoke-Command -Credential $credential -ComputerName $env:COMPUTERNAME -ArgumentList $dbUsername,$dbPassword,$dbName -ScriptBlock {
    Param 
    (
        [string]$dbUsername,
        [string]$dbPassword,
        [string]$dbName
    )
    function writeLog {
        Param([string] $log)
        $dateAndTime = Get-Date
        "$dateAndTime : $log" | Out-File -Append C:\database_configuration.log
    }
    function waitTillDatabaseIsAlive {
        Param([string] $dbName)
        $connectionString = "Data Source=localhost;Integrated Security=true;Initial Catalog=" + $dbName + ";Connect Timeout=3;"
        $sqlConn = new-object ("Data.SqlClient.SqlConnection") $connectionString
        $sqlConn.Open()
        $tryCount = 0
        while($sqlConn.State -ne "Open" -And $tryCount -lt 100) {
            $dateAndTime = Get-Date
            writeLog "Attempt $tryCount"
	        Start-Sleep -s 30
	        $sqlConn.Open()
	        $tryCount++
        }
        if ($sqlConn.State -eq 'Open') {
	        $sqlConn.Close();
	        writeLog "Connection to MSSQL Server succeeded"
        } else {
            writeLog "Connection to MSSQL Server failed"
            exit 255
        }
    }
	function alterUserPassword {
	Param([String] $dbPassword)
	    $hostnm = get-content env:computername
	    Invoke-Sqlcmd -Query "ALTER LOGIN domainuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'domainuser';" -ServerInstance "$hostnm"
	    Invoke-Sqlcmd -Query "ALTER LOGIN mrsuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'mrsuser';" -ServerInstance "$hostnm"
	    Invoke-Sqlcmd -Query "ALTER LOGIN wfhuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'wfhuser';" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "ALTER LOGIN pwhuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'pwhuser';" -ServerInstance "$hostnm"
	    Invoke-Sqlcmd -Query "ALTER LOGIN cmsuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'cmsuser';" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "ALTER LOGIN analystuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'analystuser';" -ServerInstance "$hostnm"
				Invoke-Sqlcmd -Query "ALTER LOGIN monitoruser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'monitoruser';" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "ALTER LOGIN dpsuser WITH PASSWORD = '$dbPassword'  OLD_PASSWORD = 'dpsuser';" -ServerInstance "$hostnm"
	    writeLog "Changed password for users -  domainuser, mrsuser, wfhuser, pwhuser, cmsuser, analystuser, monitoruser and dpsuser"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-domaindb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-mrsdb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-pcrsdb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-pwhdb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-wfhdb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-cmsdb];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-analystdb];" -ServerInstance "$hostnm"
		writeLog "Deleting the databases which are created for windows "
		Invoke-Sqlcmd -Query "DROP DATABASE [win-domainuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-mrsuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-pcrsuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-pwhuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-wfhuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-cmsuser];" -ServerInstance "$hostnm"
		Invoke-Sqlcmd -Query "DROP DATABASE [win-analystuser];" -ServerInstance "$hostnm"
		writeLog "Deleting the user logins which are created for windows "
	}
    $error.clear()
    netsh advfirewall firewall add rule name="Informatica_MSSQL" dir=in action=allow profile=any localport=1433 protocol=TCP
    mkdir -Path C:\Informatica\Archive\logs 2> $null
  	waitTillDatabaseIsAlive master
	alterUserPassword  $dbPassword
}