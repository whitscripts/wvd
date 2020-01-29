
$tenant = "Tenant Name"
$Hostpool = "Host Pool name"


## Remove Desktop Host Pool##
Remove-RdsSessionHost $tenant $Hostpool win10desktop-0.domain.com -Force
Remove-RdsSessionHost $tenant $Hostpool win10desktop-1.domain.com -Force
Remove-RdsAppGroup $tenant $Hostpool "Desktop Application Group"
Remove-RdsHostPool $tenant $Hostpool

## Remove Application Host Pool##
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Server Manager" 
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Wordpad" 
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Remote Desktop Connection"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "System Information"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Calculator"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Outlook"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Excel"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "PowerPoint"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Skype"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "PowerBi"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "NotePad++"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "WinZip"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "MS Paint"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Chrome"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Firefox"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "MS Paint"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Firefox"
Remove-RdsRemoteApp $tenant $Hostpool1 Applications "Server Manager"

Remove-RdsAppGroup $tenant $Hostpool1 Applications
Remove-RdsAppGroup $tenant $Hostpool1 "Desktop Application Group"

Remove-RdsSessionHost $tenant $Hostpool1 win10app-0.domain.com
Remove-RdsSessionHost $tenant $Hostpool1 win10app-1.domain.com
Remove-RdsHostPool $tenant $Hostpool1

## Check System Groups ##

Get-RdsHostPool $tenant


