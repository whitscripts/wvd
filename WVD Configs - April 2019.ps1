####################################################################################################################################################
# WINDOWS VIRTUAL DESKTOPS POWERSHELL BREAKDOWN
# Originally Created by JOHN JENNER  JOHN.JENNER@MICROSOFT.COM 
# Modified by Adam Whitlatch - adam.whitlatch@microsoft.com
# 
# URLS SUPPLIED BY PG FOR THIS SERVICE
# RDWEB FOR CONSENT 
# RDWeb              : https://rdweb.wvd.microsoft.com
# RDBroker           : http://rdbroker.wvd.microsoft.com/
# RDWebClient        : https://rdweb.wvd.microsoft.com/webclient
#
#
# win 10 multi session image, must search in marketplace for windows virtual desktop - provision a host pool
# Windows Virtual Desktop - Provision a host pool (Staged)
#
# Or use the template from GitHub => https://github.com/Azure/RDS-Templates/tree/master/wvd-templates/Create%20and%20provision%20WVD%20host%20pool
#
# Accounts needed: 
# 1-Global Admin account to your AAD Tenant which is used for setting the WVD context
# 1-WVD Account that was provided for the onboarding "internal MS Alias account"
# 1-Domain account with rights to join computers to the domain and has been assigned owner rights in the WVD Tenant
# X-Various domain user accounts to login and demo different scenarios
#
# HKLM:\SOFTWARE\FSLogix\Profiles "Enabled"=dword:00000001 
####################################################################################################################################################


# STEP 0 Download Modules

#Download RDS Powershell Modules - Do Not Extract yes - https://github.com/awhit22/rds 
#Before you unzip the file: Right click and select properties:  Click the box for Unblock, then click OK or apply.
#Unzip the files to an Easy Directory.  I like to use c:\temp\RDPowershell
#Open PowerShell (ISE): 
#changes#1

We will run these Run Commands during our testing – Use the login above:  

# STEP 1 CHANGE PS DIRECTORY - ***Only use change directory and run Import Modeul Commands if you haven't set profile veriables***
Run Command:   cd c:\temp\RDPowershell
Run Command:  Import-module .\Microsoft.RDInfra.RDPowershell.dll -Verbose

# STEP 2 Set Security Protocol
# This has to be run everytime you login

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


# STEP 3 LOGIN TO THE TENANT
# login global admin of AAD tenant - user@AADTenant.onmicrosoft.com
Add-RDSAccount -DeploymentUrl https://rdbroker.wvd.microsoft.com

# Step 4 Set the context and RDS TenantID - Tenant Group Name
Set-RdsContext -TenantGroupName "Default Tenant Group"

Set-RdsTenant -Name "<tenantname>"

# Step 5 Review Assigned Security Roles
get-RdsRoleAssignment

# Optional Set and Remove Commands for User COntrol. Must be Tenant Owner
# New-RdsRoleAssignment -SignInName wvdadminuser@domain.com -RoleDefinitionName "RDS Contributor" -TenantName "<tenantname>"
# Remove-RdsRoleAssignment -TenantName <tenantname> -SignInName wvdadminuser@domain.com -RoleDefinitionName "RDS Owner

# Step 5 Set Environment variables
$tenant = "<tenant>"
$Hostpool = "<Test User>"    #example:  "wvduser"


# STEP 6 Create new host pools for desktop sharing and applications - You Must set Persistence here if you want that type of pool
New-RdsHostPool -TenantName $tenant -Name $Hostpool -FriendlyName "Default Desktop"


# STEP 7 Optional - Only if creating Host Manually - Create token key to be used on session hosts to register them to the pool
New-RdsRegistrationInfo -TenantName $tenant -HostPoolName $Hostpool -ExpirationHours 120 | Select-Object -ExpandProperty Token
Export-RdsRegistrationInfo -TenantName $tenant -HostPoolName $Hostpool

#Keep these for later use


##   http


###########################
##                       ##
##  Stop - Deploy Hosts  ##
##                       ##
###########################

# STEP 8 Optional - Show Default Groups
Get-RdsAppGroup -TenantName $tenant -HostPoolName $Hostpool    #Notice the ResourceType


# STEP 9 - Create New App Groups assign User to group(s)
# "Desktop Application Group" Already Exists - This will be used for Desktop Connections
New-RdsAppGroup $tenant wvduser14 applications -ResourceType “RemoteApp”   #Create an App Group of type RemoteApp in Hostpool


# Optional  Syntaxt to Remove the AppGroup
# Remove-RdsAppGroup -TenantName $tenant -HostPoolName $Hostpool1 -AppGroupName "applications"

# STEP 10 - Assign User to the App group(s)
Add-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “Desktop Application Group” -UserPrincipalName wvduser14@awcdemo.cloud
Remove-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “Desktop Application Group” -UserPrincipalName wvduser14@awcdemo.cloud

Add-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “applications” -UserPrincipalName wvduser14@awcdemo.cloud   #note Users cannon be assined to a desktop & a remoteApp group inside same Host pool
remove-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “applications” -UserPrincipalName wvduser14@awcdemo.cloud   #note Users cannon be assined to a desktop & a remoteApp group inside same Host pool


##################################
##                              ##
##  STOP - Log into Web Client  ##
##                              ##
##################################


#logout of web client when done testing Dekstop


# STEP 11 - Assign User to the App group(s)
Remove-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “Desktop Application Group” -UserPrincipalName <user account>
Add-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “applications” -UserPrincipalName <user account>   #note Users cannon be assined to a desktop & a remoteApp group inside same Host pool

# STEP 12 - Get List of Apps from HostPool Hosts
Get-RdsHostPoolAvailableApp $tenant $Hostpool > c:\listofapps.txt

# STEP 13 - Publish Applications
New-RdsRemoteApp $tenant $Hostpool applications "Wordpad" -Filepath "C:\Program Files\Windows NT\Accessories\wordpad.exe" -IconPath "C:\Program Files\Windows NT\Accessories\wordpad.exe" -IconIndex 0
New-RdsRemoteApp $tenant $Hostpool applications "Calculator" -Filepath "C:\Windows\System32\calc.exe" -IconPath "C:\Windows\System32\calc.exe" -IconIndex 1
New-RdsRemoteApp $tenant $Hostpool applications "MS Paint" -Filepath "c:\windows\system32\mspaint.exe" -IconPath "c:\windows\system32\mspaint.exe" -IconIndex 2


##################################
##                              ##
##  STOP - Log into Web Client  ##
##                              ##
##################################


# Step 14 - Optional Config Parameters


# Setting up User Profile Disks - Optioanl Way of doing it outside FSLogix
Set-RdsHostPool $tenant $Hostpool -EnableUserProfileDisk
#Set-RDsHostPool $tenant $Hostpool -DisableUserProfileDisk
Set-RdsHostPool -TenantName $tenant -Name $Hostpool -DiskPath \\<Server>\<Profilepath> -EnableUserProfileDisk 

# Diagnostics
Get-RdsDiagnosticActivities -TenantName $tenant -Detailed
Get-RdsDiagnosticActivities -TenantName $tenant -ActivityId 37e20106-7c9a-431b-9327-1b3c0245f350
Get-RdsDiagnosticActivities -TenantName $tenant  -UserName <UserUPN> 
Get-RdsDiagnosticActivities -TenantName $tenant  -ActivityType Management




