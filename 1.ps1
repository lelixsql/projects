#on clients
Enable-PSRemoting -Force ‑SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.2.33" -Force
Set-Item wsman:\localhost\client\trustedhosts *
Restart-Service WinRM

#on driver
#winrm quickconfig
#or
#winrm quickconfig -transport:HTTPS
& "winrm" set 'winrm/config/client' '@{TrustedHosts="192.168.0.*"}'

$password = "Sepultura911" | ConvertTo-SecureString -asPlainText -Force
$username = "sa"
$sacredential = New-Object System.Management.Automation.PSCredential($username,$password)

$password = "Pantera911" | ConvertTo-SecureString -asPlainText -Force
$username = "LAB\Administrator"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock { Get-ChildItem C:\ } -credential $credential
Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock { Get-ChildItem C:\ } -credential $credential



install-module dbatools
#install-module sqlserver
	
#You need to download and install 'Remote Server Administration Tools for Windows 10'. The download link is https://www.microsoft.com/en-au/download/details.aspx?id=45520
Get-WindowsCapability -Name RSAT* -Online | select-object Name, state
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
Update-Help

#install-module Rsat.ServerManager.tools

Enter-PSSession -Computername "192.168.0.105" –Credential $credential
Exit-PSHostProcess

Add-WindowsFeature -Name Failover-Clustering -ComputerName 192.168.0.105 -Credential $credential
import-module FailoverClusters
Enable-WSManCredSSP Client -DelegateComputer 192.168.0.105 -Force
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Enable-WSManCredSSP Server} -credential $credential
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {new-cluster clag -Node 192.168.0.105,192.168.0.106 -StaticAddress 192.168.0.110 -NoStorage} -Authentication Credssp -Credential $credential
new-cluster clag -Node 192.168.0.105,192.168.0.106 -StaticAddress 192.168.0.110 -NoStorage

Test-KdsRootKey -KeyId (Get-KdsRootKey).KeyId
Add-KdsRootKey -EffectiveImmediately 
Invoke-Command -ComputerName 192.168.0.104 -ScriptBlock {New-ADServiceAccount -Name msa01 -Enabled $true -Description "Managed Service Account for SQL Server SQL1" -DisplayName "MSA1 – SQL1" -RestrictToSingleComputer} -Credential $credential
Invoke-Command -ComputerName 192.168.0.104 -ScriptBlock {New-ADServiceAccount -Name msa02 -Enabled $true -Description "Managed Service Account for SQL Server SQL2" -DisplayName "MSA2 – SQL2" -RestrictToSingleComputer} -Credential $credential

Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Install-WindowsFeature RSAT-AD-PowerShell} -Credential $credential
Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock {Install-WindowsFeature RSAT-AD-PowerShell} -Credential $credential
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Install-ADServiceAccount -Identity msa01} -Credential $credential
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Update-Db} -Credential $credential
Import-Module dbatools
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Update-dbaServiceAccount -ServiceName MSSQLSERVER -Username "LAB\msa01$"}  -Credential $credential


Invoke-Command -ComputerName 192.168.0.104 -ScriptBlock {New-Item "C:\quorum" –type directory } -credential $credential
Invoke-Command -ComputerName 192.168.0.104 -ScriptBlock {New-SMBShare –Name "quorum" –Path "C:\quorum" `
 –ContinuouslyAvailable $True `
 –FullAccess "LAB.COM\Authenticated Users"  `
 -ChangeAccess "LAB.COM\Authenticated Users" `
 -ReadAccess "LAB.COM\Authenticated Users"} -credential $credential
Set-ClusterQuorum -NodeAndFileShareMajority \\DC\quorum

#
#PS SQLSERVER:\SQL\NODE1\DEFAULT\Databases\pubs> Backup-SqlDatabase -Database pubs
Enable-SqlAlwaysOn -ServerInstance 192.168.0.105 -force -Credential $credential
Enable-SqlAlwaysOn -ServerInstance 192.168.0.106 -force -Credential $credential -Verbose
Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock {Restart-Service MSSQLSERVER} -Credential $credential
Invoke-Sqlcmd -query "select SERVERPROPERTY('IsHadrEnabled') as Isenabled" -ServerInstance 192.168.0.105 -Username sa -Password "Sepultura911"
Invoke-Sqlcmd -query "select SERVERPROPERTY('IsHadrEnabled') as Isenabled" -ServerInstance 192.168.0.106 -Username sa -Password "Sepultura911"

#cd .\Endpoints
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {New-SqlHADREndpoint -Path SQLSERVER:\SQL\SQL1\DEFAULT\Endpoints -Name "hadr_endpoint" -Port 5022} -Credential $credential
Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock {New-SqlHADREndpoint -Path SQLSERVER:\SQL\SQL2\DEFAULT\Endpoints -Name "hadr_endpoint" -Port 5022} -Credential $credential
#!!check endpoints

Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock {Backup-SqlDatabase -ServerInstance 192.168.0.106 -Database db1 -BackupFile "\\DC\1\db1.trn" -BackupAction Log} -Credential $credential
Invoke-Command -ComputerName 192.168.0.106 -ScriptBlock {Backup-SqlDatabase -ServerInstance 192.168.0.106 -Database db2 -BackupFile "\\DC\1\db2.trn" -BackupAction Log} -Credential $credential

Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db1 -BackupFile "\\DC\1\db1.bak" -RestoreAction -NoRecovery} -Credential $credential
Invoke-Command -ComputerName 192.168.0.105 -ScriptBlock {Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db1 -BackupFile "\\DC\1\db1.trn" -RestoreAction -NoRecovery} -Credential $credential


Enter-PSSession -Computername "192.168.0.106" –Credential $credential
Exit-PSHostProcess
#$ServerObject = Get-Item "SQLSERVER:\Sql\SQL1\DEFAULT"
#install-module sqlserver
$ServerObject = Get-Item "SQLSERVER:\Sql\SQL2\DEFAULT" #-Credential $sacredential -ServerInstance SQL2
$ServerObject.Version
$replica1 = New-SqlAvailabilityReplica -Name SQL1 -EndpointURL "TCP://SQL1:5022" -AsTemplate -AvailabilityMode SynchronousCommit -FailoverMode Automatic -ConnectionModeInSecondaryRole AllowAllConnections -Version $ServerObject.Version
$replica2 = New-SqlAvailabilityReplica -Name SQL2 -EndpointURL "TCP://SQL2:5022" -AsTemplate -AvailabilityMode SynchronousCommit -FailoverMode Automatic -ConnectionModeInSecondaryRole AllowAllConnections -Version $ServerObject.Version
    Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db1 -BackupFile "\\DC\1\db1.bak" -NoRecovery
    Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db1 -BackupFile "\\DC\1\db1.trn" -NoRecovery
    Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db2 -BackupFile "\\DC\1\db2.bak" -NoRecovery
    Restore-SqlDatabase -ServerInstance 192.168.0.105 -Database db2 -BackupFile "\\DC\1\db2.trn" -NoRecovery
New-SqlAvailabilityGroup -Name aoag -InputObject $ServerObject -AvailabilityReplica ($replica2,$replica1) -Database @("db1","db2")

Enter-PSSession -Computername "192.168.0.105" –Credential $credential
import-module sqlserver
import-module sqlps
$ServerObject = Get-Item "SQLSERVER:\Sql\SQL1\DEFAULT" #-Credential $sacredential -ServerInstance SQL2
Join-SqlAvailabilityGroup -InputObject $ServerObject -Name aoag
cd SQLSERVER:\SQL\SQL2\DEFAULT
cd .\AvailabilityGroups
dir
dir | select -ExpandProperty AvailabilityReplicas | select name, ConnectionModeInPrimaryRole, ConnectionModeInSecondaryRole
New-SqlAvailabilityGroupListener -Name aoag_net -StaticIp 192.168.0.111/255.255.255.0 -path SQLSERVER:\SQL\SQL2\DEFAULT\AvailabilityGroups\aoag
Exit-PSSession


#https://theautomationguy.blog/2018/09/22/install-and-configure-sql-2016-aag-lab/
#https://blog.sqlauthority.com/2018/06/01/sql-server-always-on-replica-disconnected-after-changing-sql-server-service-account/

PS SQLSERVER:\SQL\NODE2\DEFAULT> Restore-SqlDatabase pubs \\NODE1\sqlrec\pubs.bak  -NoRecovery
PS SQLSERVER:\SQL\NODE2\DEFAULT> Restore-SqlDatabase pubs \\NODE1\sqlrec\pubs.trn  -RestoreAction "Log" -NoRecovery
PS SQLSERVER:\SQL\NODE2\DEFAULT> cd .\AvailabilityGroups
PS SQLSERVER:\SQL\NODE2\DEFAULT\AvailabilityGroups> dir | Add-SqlAvailabilityDatabase -Database pubs


gc -module sqlserver -name test-*
SQLSERVER:\SQL\NODE1\DEFAULT> cd .\AvailabilityGroups
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups> dir | Test-SqlAvailabilityGroup
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups> dir .\AVGPubs\AvailabilityReplicas | Test-SqlAvailabilityReplica
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups> dir .\AVGPubs\DatabaseReplicaStates | Test-SqlDatabaseReplicaState

PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups>cd AVGPubs
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs> Switch-SqlAvailabilityGroup


PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs> pushd
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs> cd SQLSERVER:\SQL\NODE2\DEFAULT\AvailabilityGroups\AVGPubs
PS SQLSERVER:\SQL\NODE2\DEFAULT\AvailabilityGroups\AVGPubs> Switch-SqlAvailabilityGroup
PS SQLSERVER:\SQL\NODE2\DEFAULT\AvailabilityGroups\AVGPubs> popd
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs> Switch-SqlAvailabilityGroup

PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs> cd .\AvailabilityDatabases
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs\AvailabilityDatabases> dir | Suspend-SqlAvailabilityDatabase
PS SQLSERVER:\SQL\NODE1\DEFAULT\AvailabilityGroups\AVGPubs\AvailabilityDatabases> dir | Resume-SqlAvailabilityDatabase

https://www.ericcsinger.com/powershell-scripting-installing-sql-setting-up-alwayson-availability-groups/
