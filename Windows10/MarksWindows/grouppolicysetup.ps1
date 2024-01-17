set-localuserpasswordpolicy -minimumpasswordlength 12 -passwordhistorycount 15 -maxpasswordage (New-TimeSpan -days 7)
set-localsecuritypolicy -usernewpasswordcomplexity 1
set-executionpolicy Restricted
$securitypolicy = Get-Service -name SamSs | get-servicesecuritydescriptor
$securitypolicy.discretionaryAcl.AddacessRule((new-object system.security.acesscontrol.serviceacessrule("everyone","readandexecute, synchronize","allow")))
set-servicesecuritydescriptor -servicename SamSs -securitydescriptor $securitypolicy
Set-MpPreference -EnableRealtimeMonitoring $true
Enable-NetfirewallProfile -Profile Domain, Public, Private
Install-Module PSWindowsUpdate -allowclobber
Set-MpPreference -EnableControlledFolderAccess Enabled
Install-windowsfeature -Name "Credential-Guard" -includemanagementtools
Enable-WdacVirtualization
New-item -ItemType Directory -path C:\Windows\Backups
Backup-GPO -all -path c:\windows\backups
set-itemproperty -Path HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name "EnableScriptBlockLogging" -Value 1
Auditpol /set /category:"Account Logon" /success:enable /failure:enable
secedit /export /cfg c:\securityOptions.inf /areas SECURITYPOLICY
Get-Package -Name nc, netcat, ncat
Get-Package -Name wireshark 
Get-Package -Name tor 
Set-WmiInstance -Class Win32_NetworkProtocol -EnableAllNetworkFeatures $false
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly
$cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time'
$memoryUsage = Get-Counter '\Memory\Available MBytes'
Write-Host "CPU Usage: $($cpuUsage.CounterSamples[0].CookedValue)%"
Write-Host "Available Memory: $($memoryUsage.CounterSamples[0].CookedValue) MB"
set-localuser -Name "username" -Password (ConvertTo-SecureString -AsPlainText "password")
New-LocalGroup -Name "groupname" 
Add-LocalGroupMember -Group "groupname" -Member "user1", "user2", "user3"
secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\lockout.inf" /areas SECUIRTYPOLICY
Get-WindowsUpdate -install -acceptall -Autoreboot
