$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_reg_new_path ($path) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
  }
}

function bh_scheduledtask_disable() {
  foreach ($name in $args) {
    Invoke-Expression $bh_log_func" "$name
    Disable-ScheduledTask -TaskName $name | Out-null
  }
}

function bh_service_disable($name) {
  foreach ($name in $args) {
    Invoke-Expression $bh_log_func" "$name
    Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
    Get-Service -Name $ame | Set-Service -StartupType Disabled -ea 0
  }
}


function bh_winpackage_disable_like() {
  Invoke-Expression $bh_log_func
  foreach ($name in $args) {
    $pkgs = Get-WindowsPackage -Online | Where-Object PackageState -like Installed | Where-Object PackageName -like $name
    if ($pkgs) {
      Invoke-Expression $bh_log_func" "$name
      $pkgs | ForEach-Object { Remove-WindowsPackage -Online -NoRestart $_ }
    }
  }
}

function bh_feature_disable($featurename) {
  Invoke-Expression "$bh_log_func $featurename"
  dism.exe /online /quiet /disable-feature /featurename:$featurename /norestart
}

function bh_optimize_explorer() {
  Invoke-Expression "$bh_log_func"

  # Remove * from This PC
  # ----------------------------------------
  bh_log "Remove user folders under This PC "
  # Remove Desktop from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -ea 0
  # Remove Documents from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -ea 0
  # Remove Downloads from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -ea 0
  # Remove Music from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ea 0
  # Remove Pictures from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ea 0
  # Remove Videos from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ea 0
  # Remove 3D Objects from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ea 0
  
  # Set explorer how file extensions
  bh_log "Set explorer show file extensions"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0

  # 'Share with'
  # ----------------------------------------
  bh_log "Share with"
  Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ea 0
  # for gitg
  bh_log "gitg"
  Remove-Item "HKCR:\Directory\shell\gitg" -Recurse -ea 0
  # for add/play with vlc
  bh_log "Add/play with vlc"
  Remove-Item "HKCR:\Directory\shell\AddToPlaylistVLC" -Recurse -ea 0
  Remove-Item "HKCR:\Directory\shell\PlayWithVLC" -Recurse -ea 0
  # for git bash
  bh_log "Git bash"
  Remove-Item "HKCR:\Directory\shell\git_gui" -Recurse -ea 0
  Remove-Item "HKCR:\Directory\shell\git_shell" -Recurse -ea 0
  # "Open With"
  bh_log "Open With "
  Remove-Item -LiteralPath 'HKCR:\*\shellex\OpenWithList' -ea 0
  # Pin To Start
  bh_log "Pin To Start "
  Remove-Item -LiteralPath 'HKCR:\*\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}' -ea 0
  Remove-Item -LiteralPath 'HKCR:\*\shellex\ContextMenuHandlers\{a2a9545d-a0c2-42b4-9708-a0b2badd77c8}' -ea 0
  Remove-Item 'HKCR:\Folder\shellex\ContextMenuHandlers\PintoStartScreen' -ea 0
  # 'Include in library'
  bh_log "Include in library"
  Remove-Item "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ea 0
  Remove-Item "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ea 0
  # 'Send to'
  bh_log "Send to"
  Remove-Item -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -Recurse -ea 0
  
  # create some regs
  # ------------------
  bh_reg_new_path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  bh_reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
  
  # 'Hide Recently used Apps in Start Menu'
  bh_log 'Hide Recently used Apps in Start Menu'
  Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Explorer' -Name 'HideRecentlyAddedApps' -Value 1

  # Disable file delete confirmation dialog
  bh_log "Disable file delete confirmation dialog"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Value 0
  
  # Disable action center
  bh_log "Hide action center button "
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableNotificationCenter" -Value 1
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
  
  # restart explorer
  Stop-Process -ProcessName explorer
}

function bh_optimize_windows() {
  Invoke-Expression $bh_log_func

  # Remove Lock screen
  bh_log "Remove Lockscreen "
  bh_reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1

  # Disable drives Autoplay
  bh_log "Disable new drives Autoplay"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1

  # Disable offering of Malicious Software Removal Tool through Windows Update
  bh_log "Disable Malicious Software Removal Tool offering"
  New-Item -Path "HKLM:\Software\Policies\Microsoft\MRT" -ea 0
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1

  # Disable Remote Assistance
  bh_log "Disable Remote Assistance"
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

  # Disable Autorun for all drives
  bh_log "Disable Autorun for all drives"
  bh_reg_new_path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

  # Disable error reporting
  bh_log "Disable error reporting "
  reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f | Out-Null

  # Disable license checking
  bh_log "Disable license checking "
  reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f | Out-Null

  # Disable tips
  bh_log "Disable tips "
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f | Out-Null

  # 'Disable Accessibility Keys Prompts
  bh_log 'Disable Accessibility Keys Prompts '
  $path = 'HKCU:\Control Panel\Accessibility\'
  Set-ItemProperty -Path "$path\StickyKeys" -Name 'Flags' -Type String -Value '506'
  Set-ItemProperty -Path "$path\ToggleKeys" -Name 'Flags' -Type String -Value '58'
  Set-ItemProperty -Path "$path\Keyboard Response" -Name 'Flags' -Type String -Value '122'

  # "Disable Windows Timeline
  bh_log "Disable Windows Timeline "
  Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0

  # Disable Bing
  bh_log "Disable Bing search "
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /d "0" /t REG_DWORD /f  | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /d "0" /t REG_DWORD /f | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /d "0" /t REG_DWORD /f | Out-null
  reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /d "0" /t REG_DWORD /f | Out-null
  
  # Disable Cortana
  bh_log "Disable Cortana"

  bh_reg_new_path "HKCU:\Software\Microsoft\Personalization\Settings"
  bh_reg_new_path "HKCU:\Software\Microsoft\InputPersonalization"
  bh_reg_new_path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
  bh_reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search"

  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0

  # disable beep
  net stop beep
  
  # Disable Windows Defender'
  bh_log "Windows Defender "
  Set-Item "HKCR:\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" "" -ea 0
  
  # Disable unused services
  bh_log "Disable unused services "
  $services = @("*diagnosticshub.standardcollector.service*" # Diagnostics Hub
    "*diagsvc*" # Diagnostic Execution Service
    "*dmwappushservice*" # Device Management WAP Push message Routing Service
    "*DiagTrack*" # Connected User Experiences and Telemetry
    "*lfsvc*" # Geolocation Service
    "*MapsBroker*" # Downloaded Maps Manager
    "*RetailDemo*" # Retail Demo Service
    "*RemoteRegistry*" # Remote Registry
    "*FoxitReaderUpdateService*" # Remote Registry
    "*RemoteAccess*" # Routing and Remote Access (routing services to businesses in LAN)
    "*TrkWks*" # Distributed Link Tracking Client
    "*XblAuthManager*" # Xbox Live Auth Manager
    "*XboxNetApiSvc*" # Xbox Live Networking Service
    "*XblGameSave*" # Xbox Live Game Save
    "*wisvc*" # Windows Insider Service
  )
  bh_service_disable $services

  # XPS Services
  bh_log "Disable XPS "
  bh_feature_disable Printing-XPSServices-Features

  # Work Folders
  bh_log "Disable Work Folders "
  bh_feature_disable WorkFolders-Client
  
  # Disable scheduled tasks
  bh_log "Disable scheduled tasks "
  $tasks = @(
    'CCleaner Update'
    'CCleanerSkipUAC'
  )
  bh_scheduledtask_disable @tasks
}

function bh_optimize_password_policy {
  Invoke-Expression $bh_log_func
  $tmpfile = New-TemporaryFile
  secedit /export /cfg $tmpfile /quiet
  (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
  secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
  Remove-Item -Path $tmpfile
}

# ---------------------------------------
# setup_win_adm
# ---------------------------------------

bh_log "bh_setup_win_adm"
# install winget
if (!(Get-Command "winget.exe" -ea 0)) {
  bh_log "INFO: winget is not installed, installing..."
  bh_win_install_winget
} 
# install gsudo
if (!(Get-Command "gsudo.exe" -ea 0)) {
  bh_log "INFO: gsudo is not installed, installing..."
  bh_install_gsudo
} 
bh_optimize_password_policy_disabled
bh_optimize_windows
bh_optimize_explorer