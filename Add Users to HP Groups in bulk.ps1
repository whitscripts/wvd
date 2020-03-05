Connect-AzAccount   #log into Azure
Add-RDSAccount -DeploymentUrl https://rdbroker.wvd.microsoft.com   # Log into WVD Tenant

$tenant = "myWVDTenantName"   #your WVD Tenant Name
$Hostpool = "MyHostPool"      #Security Group You would like to add
$users = Get-azadgroupmember -GroupDisplayName <AAD Security Group Name> # Get User Names from the group

#Add each user to the correct Host Pool Group
foreach ($user in $users){

Add-RdsAppGroupUser -TenantName $tenant -HostPoolName $Hostpool -AppGroupName “Desktop Application Group” -UserPrincipalName $user.UserPrincipalName
}
