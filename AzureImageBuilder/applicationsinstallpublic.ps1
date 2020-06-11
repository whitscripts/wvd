#    Script created by Adam Whitlatch - adam.whitlatch@microsoft.com
#    
#    Updated 06/04/2020
#

mkdir c:\buildArtifacts
echo Azure-Image-Builder-Was-Here  > c:\buildArtifacts\azureImageBuilder.txt


# Workshop install apps demo example
### Download Application Packages
New-Item -Path 'C:\temp' -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri "https://awclabsimagebuilder.blob.core.windows.net/applications/AppInstallers2.zip" -OutFile "c:\temp\apps.zip"
Expand-Archive -Path 'C:\temp\apps.zip' -DestinationPath 'C:\temp' -Force

Start-Process "C:\temp\apps2\apps\ITPC-LogAnalyticsAgent\Azure Monitor for WVD\ITPC-LogAnalyticsAgent.exe" -Wait -ArgumentList '-install'

#Install Applications for Azure Image Builder script
Write-Host "Install Microsoft Edge"
Start-Process msiexec.exe -ArgumentList "/I c:\temp\files\MicrosoftEdgeEnterpriseX64.msi /quiet"
Write-Host "Install Notepad++"
Start-Process "C:\temp\apps2\apps\npp.7.7.1.Installer.x64.exe" -Wait -ArgumentList '/S'
Write-Host "Install FSLogix Agent"
Start-Process "C:\temp\apps2\apps\FSLogix_Apps_2.9.7237.48865\x64\Release\FSLogixAppsSetup.exe" -Wait -ArgumentList '/install /quiet'
Write-Host "Install FSLogix Rule Editor"
Start-Process "C:\temp\apps2\apps\FSLogix_Apps_2.9.7237.48865\x64\Release\FSLogixAppsRuleEditorSetup.exe" -Wait -ArgumentList '/install /quiet'
Write-Host "Install FSLogix Java Editor"
Start-Process "C:\temp\apps2\apps\FSLogix_Apps_2.9.7237.48865\x64\Release\FSLogixAppsJavaRuleEditorSetup.exe" -Wait -ArgumentList '/install /quiet'
#Write-Host "Install Office"
#Start-Process "C:\temp\apps2\apps\files\Setup.exe" -Wait -ArgumentList '/configure C:\temp\apps2\files\configurationwvd.xml'
#Write-Host "Install OneDrive"
#Start-Process "C:\temp\apps2\apps\files\OneDriveSetup.exe" -Wait -ArgumentList '/allusers'
Write-Host "Install Sepago"
Start-Process "C:\temp\apps2\apps\ITPC-LogAnalyticsAgent\Azure Monitor for WVD\ITPC-LogAnalyticsAgent.exe" -Wait -ArgumentList '-install'
Write-Host "Install Service Map"
Start-Process "C:\temp\apps2\apps\InstallDependencyAgent-Windows.exe" -Wait -ArgumentList '/S'

#--------------------------------Sysprep---------------------------#


# The following steps are from: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image
# https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /t REG_SZ /d "C:\temp\apps2\apps\BGInfo\bginfo.bat" /f

# Set this variable to your FSLogix profile directory
$FSLUNC = "\\wu2awclabsfiles1.file.core.windows.net\profiles"

Write-Host "This script will prepare your image for capture and eventual upload to Azure."

Write-Host "Disabling Automatic Updates..."
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f

# Configure session timeout policies
Write-Host "Configuring session timeout policies..."
#one minute = 60000  https://www.sevenforums.com/tutorials/118886-remote-desktop-set-time-limit-active-sessions.html
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v RemoteAppLogoffTimeLimit /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fResetBroken /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxConnectionTime /t REG_DWORD /d 28800000 /f  # 8 Hours
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v RemoteAppLogoffTimeLimit /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxDisconnectionTime /t REG_DWORD /d 14400000 /f  #4 hours
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxIdleTime /t REG_DWORD /d 7200000 /f  #2 hours


# Enable timezone redirection
Write-Host "Enabling time zone redirection..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f

# Disable Storage Sense
Write-Host "Disabling Storage Sense..."
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy /v 01 /t REG_DWORD /d 0 /f

# Remove the WinHTTP proxy
netsh winhttp reset proxy

# Set Coordinated Universal Time (UTC) time for Windows and the startup type of the Windows Time (w32time) service to Automatically
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -name "RealTimeIsUniversal" -Value 1 -Type DWord -force
Set-Service -Name w32time -StartupType Automatic

# Set the power profile to the High Performance
powercfg /setactive SCHEME_MIN

# Make sure that the environmental variables TEMP and TMP are set to their default values
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "TEMP" -Value "%SystemRoot%\TEMP" -Type ExpandString -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "TMP" -Value "%SystemRoot%\TEMP" -Type ExpandString -force

# Set Windows services to defaults - This typically fails due to a permissions error, need to investigate why. May be due to differences in client vs Server os
Set-Service -Name dhcp -StartupType Automatic
Set-Service -Name IKEEXT -StartupType Automatic
Set-Service -Name iphlpsvc -StartupType Automatic
Set-Service -Name netlogon -StartupType Manual
Set-Service -Name netman -StartupType Manual
Set-Service -Name nsi -StartupType Automatic
Set-Service -Name termService -StartupType Manual
Set-Service -Name RemoteRegistry -StartupType Automatic
Set-Service -Name Winrm -startuptype Automatic

# Ensure RDP is enabled
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "fDenyTSConnections" -Value 0 -Type DWord -force

# Set RDP Port to 3389 - Unnecessary for WVD due to reverse connect, but helpful for backdoor administration with a jump box 
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "PortNumber" -Value 3389 -Type DWord -force

# Listener is listening on every network interface
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "LanAdapter" -Value 0 -Type DWord -force

# Configure NLA
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "SecurityLayer" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "fAllowSecProtocolNegotiation" -Value 1 -Type DWord -force

# Set keep-alive value
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "KeepAliveEnable" -Value 1  -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "KeepAliveInterval" -Value 1  -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "KeepAliveTimeout" -Value 1 -Type DWord -force

# Reconnect
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -name "fDisableAutoReconnect" -Value 0 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "fInheritReconnectSame" -Value 1 -Type DWord -force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "fReconnectSame" -Value 0 -Type DWord -force

# Limit number of concurrent sessions
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -name "MaxInstanceCount" -Value 4294967295 -Type DWord -force

# Turn on Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Allow RDP
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True

# Enable File and Printer sharing for ping
Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True

#For feedback hub collection of telemetry data on Windows 10 Enterprise multi-session, run this command
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f


# Fix Watson crashes:
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\CorporateWerServer*"

# Enter the following commands into the registry editor to fix 5k resolution support
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxYResolution /t REG_DWORD /d 2880 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxYResolution /t REG_DWORD /d 2880 /f

#workaround for win10 BiSrv issue
schtasks /change /tn "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /disable



#Add FSLogix settings
New-Item -Path HKLM:\Software\FSLogix\ -Name Profiles -Force
New-Item -Path HKLM:\Software\FSLogix\Profiles\ -Name Apps -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type "Dword" -Value "1"
New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VHDLocations" -Value $FSLUNC -PropertyType MultiString -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SizeInMBs" -Type "Dword" -Value "10240"  #10GB in MB - always better to oversize - FSlogix Overwrites deleted blocks first then new blocks. Should be hire if not using OneDrive 
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhdx"  # NOTE:  this should be set to "vhd" for Win 7 and Sever 2102R2
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ProfileType" -Type "Dword" -Value "3"  # Machine should try to take the RW role and if it can't, it should fall back to a RO role.
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "FlipFlopProfileDirectoryName" -Type "Dword" -Value "1"  #Cosmetic change the way each user folder is created

# Optional FSLogix Settings
#Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ConcurrentUserSessions" -Type "Dword" -Value "1"   # Concurrent sessions if you want to use the same profile for published apps & Desktop Should log into Desktop session first
#Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ProfileType" -Type "Dword" -Value "3"     #this should only be used if Concurrent User Settings is set  # Machine should try to take the RW role and if it can't, it should fall back to a RO role.

#New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles\Apps -Name "RoamSearch" -Type "Dword" -Value "2"  # Only for Server 2012R2 and Server 2016 Leave Defaul to 0
#Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type "Dword" -Value "2"  # Only for Server 2012R2 and Server 2016 Leave Defaul to 0
#Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "DeleteLocalProfileWhenVHDShouldApply"  -Type "Dword" -Value "0"   # OPTIONAL 0 = no deleton - 1 = deletion - This will deliete existing profiles


#set FSX Office Container
New-Item -Path HKLM:\SOFTWARE\Policies\FSLogix\ -Name ODFC -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "Enabled" -Type "Dword" -Value "1"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "VHDLocations" -Value $FSLUNC -PropertyType MultiString -Force
new-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "SizeInMBs" -Type "Dword" -Value "25600"  # 25GBin MB - always better to oversize - FSlogix Overwrites deleted blocks first then new blocks 
new-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "VolumeType" -Type String -Value "vhdx"  #this shoudl be set to "vhd" for Win 7 and Sever 2102R2
new-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "FlipFlopProfileDirectoryName" -Type "Dword" -Value "1" 
#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "DeleteLocalProfileWhenVHDShouldApply"  -Type "Dword" -Value "0" #nodeleton - 1 yes deletion



# Some settings taken from https://www.robinhobo.com/how-to-start-onedrive-and-automatically-sign-in-when-using-a-remoteapp-in-windows-virtual-desktop-wvd/
#Write-Host "Setting OneDrive for Business policies" Run this after you install One Drive
#Configure OneDrive to start at sign-in for all users
#REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f
#Silently configure user accounts
#REG ADD "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /f
#REG ADD "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" /v "FilesOnDemandEnabled" /t REG_DWORD /d 1 /f
#REG ADD "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" /v "EnableADAL" /t REG_DWORD /d 2 /f
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name RailRunonce -Force
#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RailRunonce\" -Name "OneDrive" -Force
#Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server\RailRunonce\" -Name "OneDrive" -Value "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" -Type String
#REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMSilentOptIn" /t REG_SZ /d "YOUR AAD ID GOES HERE" /f 


# Desktop Icons and Small Icons, Remove Search/cortana
Try
{
new-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type "Dword" -Value "0" 
}




Try
{
new-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type "Dword" -Value "0" 
}






Try
{
new-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarSmallIcons" -Type "Dword" -Value "1" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarSmallIcons" -Type "Dword" -Value "1" 
}

Try
{
new-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarSmallIcons" -Type "Dword" -Value "1" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarSmallIcons" -Type "Dword" -Value "1" 
}





Try
{
new-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Search -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Search -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0" 
}




Try{
new-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "ShowCortanaButton" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "ShowCortanaButton" -Type "Dword" -Value "0" 
}

Try
{
new-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "ShowCortanaButton" -Type "Dword" -Value "0" -ErrorAction Stop
}
Catch
{
set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "ShowCortanaButton" -Type "Dword" -Value "0" 
}


