#####################################################################
# Master Script for WVD Image Prep                                  #
# Script authors:   Adam Whitlatch <adam.whitlatch.microsoft.com>   #   
#                   Chris Nylen <Chris.Nylen@microsoft.com>         #
#                   John Jenner <John.Jenner@microsoft.com>         #
#                                                                   #
# Most Recent Update Date: 04/06/2020                               #
# Last Updated By: Adam Whitlatch                                   #
#####################################################################



##############################################################################################################################################################
# Below is the process I use to build my master image manually. NOTE, there are many ways to do this. You CAN use tools like SCCM, Azure Image Builder ect to build this. Azure Image builder being the most automated
# NOTE: Windows 10 has a 8 times sysprep limit. Therefore, if you are building a master image in Azure follow this process to maintain a master image file wilout running into the sysprep limit
# 1)  Deploy Win 10 base image from Azure Image Gallery, 
# 2)  Make modifications, app installs, ect to image, 
#       Re-Install Install One drive for all Users
#       Install Office
#       Install all Apps
#       Run BGInfo Script
# 3)  Reboot
# 4)  Install FSX Agent, Azure Monitor Agent, Dependency Agents, and Sepago Agent
#       Install FSX Agent
#       Install Monitoring Agent - Do not connect to workspace
#           Run Once Code at first login
#            #MMDS
#                $workspaceKey = "your workspace Key"
#                $workspaceId = "Your Workspace ID"
#                $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
#                $mma.AddCloudWorkspace($workspaceId, $workspaceKey)
#                $mma.ReloadConfiguration()
#       Install Dependency Agent
#       Create Sepago LogAnalytics WS - search for sepago in marketplace - Only needs to be done the first time. Point all other Workspces to the same LA.
#           Download Sepago views from github
#           Install Views
#           Get Workspace Id and Key info
#       Install Sepago Agent - ITPC-LogAnalyticsAgent2
#           Download the Sepago agent from website
#           Extract files
#           Copy ITPC-LogAnalyticsAgent2 Folder to Program Files Directory
#           Modify Manifest File
#              <add key="CustomerId" value="Your LA WokspaceID"/>
#              <add key="SharedKey" value="youre workspace Key"/>
#           Open Powershell or Command Prompt 
#               Run ITPC-LogAnalyticsAgent.exe -test
#           Verfy no errors
#           Run ITPC-LogAnalyticsAgent.exe -install
# 5)  Run Set small Icons Scripts & Desktop Icons Scripts
# 6)  Run rest of this script to set common best practices for Master Images
# 7)  Set any run at first book commands
# 8)  Take Azure Disk Snapshot
# 9) sysprep - gnealize and shutdown
# 10) Updating Image - mount previous snapshot to a VM, power on, Make changes, re-install Monitoring, dependency & Sepago Agents, reboot, take a azure disk snapshot, sysprep, shutdown
##############################################################################################################################################################


$FSLUNC = "\\server\share"  # Path to your FSlogix SMB share
$AADTenant = "az1343be-343e-1234-acfr-ab5fdf6fabcd"  #your AAD Tenant ID

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

################   Re-install One Drive    ########################
#  By Default One-drive installs for single users
# Uninstall OneDrive 
# Download the latest OneDriveSetup.exe from Micrsoft's site https://products.office.com/en-us/onedrive/download
# Place in a temp folder - NOTE:  Change the folder path to your copy of OneDriveSetup.exe
# you can use the downloaded exe as the uninstall path. 
###################################################################

#update #19 

# Uninsall One Drive
Run C:\temp\apps\OneDriveSetup.exe /uninstall
REG ADD "HKLM\Software\Microsoft\OneDrive" /v "AllUsersInstall" /t REG_DWORD /d 1 /reg:64
REG ADD "HKLM\Software\Microsoft\OneDrive" /v "AllUsersInstall" /t REG_DWORD /d 1 /reg:32
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f    #Configure OneDrive to start at sign-in for all users

# Re- Install OneDrive
Run C:\temp\apps\OneDriveSetup.exe /allusers
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" /f

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMSilentOptIn" /t REG_SZ /d $AADTenant /f  #uses the AADTenent variable above #Redirect and move Windows known folders to OneDrive - Make sure to change the AAD ID to match your own AAD!!!! 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /f   #Silently configure user accounts


#Install Office
#https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
C:\temp\apps\Office\Setup.exe /configure "C:\temp\apps\Office\configuration-Office365-x64.xml"  # use a customize Image to control which office apps are installed
C:\temp\apps\Office\OfficeUpdates.bat
    # rem Mount the default user registry hive
    # reg load HKU\TempDefault C:\Users\Default\NTUSER.DAT    # rem Must be executed with default registry hive mounted

    # rem Set Outlook's Cached Exchange Mode behavior
    # reg add HKU\TempDefault\SOFTWARE\Policies\Microsoft\office\16.0\common /v InsiderSlabBehavior /t REG_DWORD /d 2 /f
    # reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v enable /t REG_DWORD /d 1 /f
    # reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v syncwindowsetting /t REG_DWORD /d 1 /f
    # reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSetting /t REG_DWORD /d 1 /f
    # reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSettingMonths  /t REG_DWORD /d 1 /f
 
    # Set default HKCU Icons settings    
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 0
    # reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSmallIcons /T REG_DWORD /D 1 /F
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V SearchboxTaskbarMode /T REG_DWORD /D 0 /F
    # reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowCortanaButton /T REG_DWORD /D 0 /F
    
    # rem Unmount the default user registry hive
    # reg unload HKU\TempDefault

    # rem Set the Office Update UI behavior.
    # reg add HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate /v hideupdatenotifications /t REG_DWORD /d 1 /f
    # reg add HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate /v hideenabledisableupdates /t REG_DWORD /d 1 /f


#Add Registry Entry to BGinfo
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /t REG_SZ /d "C:\temp\apps\BGInfo\bginfo.bat" /f


#          <<<----------------------------   Proceed Below after all app installs and configs  ---------------------------->>>


#disable Windows Defender Scanning of VHD
https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/configure-extension-file-exclusions-windows-defender-antivirus
    Change Group Policy Management Editor >> Administrative templates >> Windows components >> Windows Defender Antivirus >> Exclusions
        Extension Exclusions:  .vhd, .vhdx
        Turn Off Auto Exclusion: Disabled


Write-Host "This script will prepare your image for capture and eventual upload to Azure."

Write-Host "Disabling Automatic Updates..."
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f


# Skiprearm for windows activation after sysprepping
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\SL" /v ""


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
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f

# Disable Storage Sense
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f

# The following steps are from: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image

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


########################################
#      FSLogix Profile Settings        #
########################################
# be sure to set the FSLogix Variable above
# $FSLUNC = "\\server\share"  # Path to your FSlogix SMB share Link to share/directory permissions   https://docs.microsoft.com/en-us/fslogix/fslogix-storage-config-ht
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
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "Enabled" -Type "Dword" -Value "1"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "VHDLocations" -Value $FSLUNC -PropertyType MultiString -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "SizeInMBs" -Type "Dword" -Value "25600"  # 25GBin MB - always better to oversize - FSlogix Overwrites deleted blocks first then new blocks 
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "VolumeType" -Type String -Value "vhdx"  #this shoudl be set to "vhd" for Win 7 and Sever 2102R2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "FlipFlopProfileDirectoryName" -Type "Dword" -Value "1" 
#Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\FSLogix\ODFC -Name "DeleteLocalProfileWhenVHDShouldApply"  -Type "Dword" -Value "0" #nodeleton - 1 yes deletion


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



# Cosmetic Only for my environment

# Desktop Icons and Small Icons, Remove Search/cortana

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

#Specify Start Layout for Win 10
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SpecialRoamingOverrideAllowed /t REG_DWORD /d 1 /f


# Launch Sysprep
# Write-Host "We'll now launch Sysprep."
# C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown

<------------------------------------------------------------------------------------------->






