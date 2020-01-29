############################################
##  AIRS Vnet SETUP
##  Only complete steps in this section if you don't already have a VNET in AIRS
############################################

Connect-AzAccount
    #. Login with an account that has Owner or at least Network Contriubuter rights to AIRS Sub

#set the context of where to create resources
Set-AzContext <your AIRS Subscription ID here>
    #Example: Set-AzContext abc1234-343e-a2b3-8ced-ae5xyz123456


# Create a resource group.
New-AzResourceGroup `
  -Name <resource Group name>`
  -Location centralus

# Create virtual network A.
$vNetA = New-AzVirtualNetwork `
  -ResourceGroupName <resource Group name>` `
  -Name 'myVnetA' `
  -AddressPrefix '10.0.0.0/16' `
  -Location centralus

# Assign UserB permissions to myVnetA.
New-AzRoleAssignment `
  -SignInName "someone@somewhere.com" `
  -RoleDefinitionName "Network Contributor" `
  -Scope /subscriptions/<uour AIRS Sub>/resourceGroups/<AIRS RG>/providers/Microsoft.Network/VirtualNetworks/<AIRS Vnet Name>

  #Example:  -Scope /subscriptions/abc1234-343e-a2b3-8ced-ae5xyz123456/resourceGroups/rg-cu-vnetRG/providers/Microsoft.Network/VirtualNetworks/myVnetA



############################################
##  MSDN VNET Setup
##  Only complete steps in this section if you DON'T already have a VNET in MSDN
############################################

Connect-AzAccount
    # Login with an account that has Owner or at least Network Contriubuter rights to MSDN Sub

#set the context of where to create resources
Set-AzContext <your AIRS Subscription ID here>
    #Example: Set-AzContext abc1234-343e-a2b3-8ced-ae5xyz123456


  # Create a resource group.
New-AzResourceGroup `
  -Name rg-cu-msdncore `
  -Location centralus

# Create virtual network A.
$vNetB = New-AzVirtualNetwork `
  -ResourceGroupName <Resource Group> `
  -Name 'myVnetB' `
  -AddressPrefix '10.1.0.0/16' `
  -Location centralus

# Assign UserB permissions to myVnetA.
New-AzRoleAssignment `
  -SignInName "someone@somewhere" `
  -RoleDefinitionName "Network Contributor" `
  -Scope /subscriptions/bcrt1234-343e-a2b3-8ced-ae5bc123456/resourceGroups/rg-cu-msdncore/providers/Microsoft.Network/VirtualNetworks/myVnetB


#----------------------------------------------------------


############################################
##  MSDN Peering Setup
############################################

# Peer MSDN to AIRS.
$vNetB=Get-AzVirtualNetwork -Name vn-cu-msdn -ResourceGroupName rg-cu-CoreServices
Add-AzVirtualNetworkPeering `
  -Name 'Sub1_to_sub2' `
  -VirtualNetwork $vNetB `
  -RemoteVirtualNetworkId "/subscriptions/<AIRS Subscriptuon ID>/resourceGroups/<AIRS Vnet RG>/providers/Microsoft.Network/virtualNetworks/<AIRS VNET>"


Example: -RemoteVirtualNetworkId "/subscriptions/abc1234-343e-a2b3-8ced-ae5xyz123456/resourceGroups/rg-cu-corenetworking/providers/Microsoft.Network/virtualNetworks/vn-cu-hub"


############################################
##  AIRS Peering Setup
############################################

Connect-AzAccount
Set-AzContext <AIRS Subscription ID>


# Peer MSDN to AIRS.
$vNetA=Get-AzVirtualNetwork -Name vn-cu-hub -ResourceGroupName rg-cu-corenetworking
Add-AzVirtualNetworkPeering `
  -Name 'Sub2_to_sub1' `
  -VirtualNetwork $vNetA `
  -RemoteVirtualNetworkId "/subscriptions/<AIRS Subscriptuon ID>/resourceGroups/<AIRS Vnet RG>/providers/Microsoft.Network/virtualNetworks/<AIRS VNET>"

Example: -RemoteVirtualNetworkId "/subscriptions/bcrt1234-343e-a2b3-8ced-ae5bc123456/resourceGroups/rg-cu-CoreServices/providers/Microsoft.Network/virtualNetworks/vn-cu-msdn"



############################################
##  Check Peering Setup
##  Expected Result = Connected
############################################

Get-AzVirtualNetworkPeering `
  -ResourceGroupName rg-cu-corenetworking`
  -VirtualNetworkName vn-cu-hub `
  | Format-Table VirtualNetworkName, PeeringState
