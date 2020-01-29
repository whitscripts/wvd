# This section is for OneDrive Configuration.
# Master Script for WVD Image Prep
# Script authors: Chris Nylen <Chris.Nylen@microsoft.com>; John Jenner <John.Jenner@microsoft.com>, Adam Whitlatch <adam.whitlatch.microsoft.com>
# Compliled as an example to prep a windows 10 image for user in Windows virtual desktop
# Please use and test at your own descretion. Please note there are values specific to your environment that need to be updated
# This is an example script not intended to be production redy without testing and configuration  
#

##Process

#  Install all Apps
#  Install FSX Agent
#  Install Monitoring Agent
#      Choose to Connect to Workspace
#  Install Dependency Agent
#  Install Sepago Agent - ITPC-LogAnalyticsAgent2
#      <add key="CustomerId" value="Workspace ID"/>
#      <add key="SharedKey" value="SharedKey"/>
#      Create Sepago WS
#     Copy Folder to Program Files Directory
#      Modify Manifest File
#      Run ITPC-LogAnalyticsAgent.exe -test
#      ITPC-LogAnalyticsAgent.exe
#      Check it connected to LA Workspace
#      Run ITPC-LogAnalyticsAgent.exe -install
#      Install Views
#  Install and Configure BGinfo
#  Run Sripts for Desktop Icon
#  Run Sript for task bar Icons


# Set this variable to your FSLogix profile directory
$FSLUNC = "\\fs01\UserProfiles"

#If needed - Set-ExecutionPolicy -ExecutionPolicy Unrestricted

#Desktop Icons and Small Icons, Remove Search/cortana

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0

REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSmallIcons /T REG_DWORD /D 1 /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V SearchboxTaskbarMode /T REG_DWORD /D 0 /F
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSmallIcons /T REG_DWORD /D 1 /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /V SearchboxTaskbarMode /T REG_DWORD /D 1 /F

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowCortanaButton /T REG_DWORD /D 0 /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowCortanaButton /T REG_DWORD /D 0 /F
taskkill /f /im explorer.exe
start explorer.exe



#If using Marketplace image Resinstall One Drive 

# Uninstall OneDrive - download latest OneDrive exe and paste to location 
Run C:\temp\apps\OneDriveSetup.exe /uninstall

REG ADD "HKLM\Software\Microsoft\OneDrive" /v "AllUsersInstall" /t REG_DWORD /d 1 /reg:64

#Install OneDrive
Run C:\temp\apps\OneDriveSetup.exe /allusers

REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /f

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMSilentOptIn" /t REG_SZ /d "abc1234-343e-a2b3-8ced-ae5xyz123456" /f



<------------------------------Once the above is run continue to run the rest of the script---------------------------------->

#Install Office - I prefer to re-install Office as well for multi-user environments
#https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
C:\temp\apps\Office\Setup.exe /configure "C:\temp\apps\Office\configuration-Office365-x64.xml"
C:\temp\apps\Office\OfficeUpdates.bat

#disable Windows Defender Scanning of VHD
https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/configure-extension-file-exclusions-windows-defender-antivirus
    Change Group Policy Management Editor >> Administrative templates >> Windows components >> Windows Defender Antivirus >> Exclusions
        Extension Exclusions:  .vhd, .vhdx
        Turn Off Auto Exclusion: Disabled

#Add Registry Entry to BGinfo
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /t REG_SZ /d "C:\temp\apps\BGInfo\bginfo.bat" /f


# The following steps are from: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image
# Set-ExecutionPolicy -ExecutionPolicy Unrestricted

Write-Host "This script will prepare your image for capture and eventual upload to Azure."

Write-Host "Disabling Automatic Updates..."
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f

Write-Host "Setting OneDrive for Business policies"
#Configure OneDrive to start at sign-in for all users
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f
#Silently configure user accounts
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /f
#Redirect and move Windows known folders to OneDrive - Make sure to change the AAD ID to match your own AAD!!!! 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMSilentOptIn" /t REG_SZ /d "abc1234-343e-a2b3-8ced-ae5xyz123456" /f

# Skiprearm for windows activation after sysprepping
#Now open Regedit and go to the following key:

#REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\SL" /v ""

# Configure session timeout policies
Write-Host "Configuring session timeout policies..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v RemoteAppLogoffTimeLimit /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fResetBroken /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxConnectionTime /t REG_DWORD /d 28800000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v RemoteAppLogoffTimeLimit /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxDisconnectionTime /t REG_DWORD /d 14400000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxIdleTime /t REG_DWORD /d 7600000 /f

# Enable timezone redirection
Write-Host "Enabling time zone redirection..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f

# Disable Storage Sense
Write-Host "Disabling Storage Sense..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f

# The following steps are from: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image
Write-Host "Preparing image for upload to Azure..."

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
Set-Service -Name bfe -StartupType Automatic
Set-Service -Name dhcp -StartupType Automatic
Set-Service -Name dnscache -StartupType Automatic
Set-Service -Name IKEEXT -StartupType Automatic
Set-Service -Name iphlpsvc -StartupType Automatic
Set-Service -Name netlogon -StartupType Manual
Set-Service -Name netman -StartupType Manual
Set-Service -Name nsi -StartupType Automatic
Set-Service -Name termService -StartupType Manual
Set-Service -Name MpsSvc -StartupType Automatic
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

# Remove any self signed certs
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "SSLCertificateSHA1Hash" -force

# Turn on Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Allow WinRM
REG add "HKLM\SYSTEM\CurrentControlSet\services\WinRM" /v Start /t REG_DWORD /d 2 /f
net start WinRM
Enable-PSRemoting -force
Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Enabled True

# Allow RDP
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True

# Enable File and Printer sharing for ping
Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True

# Add Defender exclusion for FSLogix
Add-MpPreference -ExclusionPath $FSLUNC

#Add FSLogix settings

$FSLUNC = "\\fs01\UserProfiles"
New-Item -Path HKLM:\Software\FSLogix\ -Name Profiles -Force
New-Item -Path HKLM:\Software\FSLogix\Profiles\ -Name Apps -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type "Dword" -Value "1"
New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VHDLocations" -Value $FSLUNC -PropertyType MultiString -Force
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SizeInMBs" -Type "Dword" -Value "15360"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "IsDynamic" -Type "Dword" -Value "1"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhd"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "LockedRetryCount" -Type "Dword" -Value "12"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "LockedRetryInterval" -Type "Dword" -Value "5"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ProfileType" -Type "Dword" -Value "3"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "ConcurrentUserSessions" -Type "Dword" -Value "1"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type "Dword" -Value "2" 
New-ItemProperty -Path HKLM:\Software\FSLogix\Profiles\Apps -Name "RoamSearch" -Type "Dword" -Value "2"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type "Dword" -Value "2"

Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhd"

Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "FlipFlopProfileDirectoryName" -Type "Dword" -Value "1" 
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SIDDirNamePattern" -Type String -Value "%username%%sid%"
Set-ItemProperty -Path HKLM:\Software\FSLogix\Profiles -Name "SIDDirNameMatch" -Type String -Value "%username%%sid%"




# Launch Sysprep
# Write-Host "We'll now launch Sysprep."
# C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown

<------------------------------------------------------------------------------------------->

# Windows Store disable setting
# Start the registry editor (regedit.exe).
# New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\ -Name "DisableStoreApps" -Type "Dword" -Value "1"

# WVD CLient 
# REG ADD HKLM\Software\Microsoft\MSRDC\Policies /t REG_SZ /v ReleaseRing /d insider /f

#Specify Start Layout for Win 10
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SpecialRoamingOverrideAllowed /t REG_DWORD /d 1 /f

#For feedback hub collection of telemetry data on Windows 10 Enterprise multi-session, run this command
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f


#Run the following command to fix Watson crashes:
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\CorporateWerServer*"

#Enter the following commands into the registry editor to fix 5k resolution support
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxYResolution /t REG_DWORD /d 2880 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxYResolution /t REG_DWORD /d 2880 /f

#workaround for win10 BiSrv issue
schtasks /change /tn "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /disable