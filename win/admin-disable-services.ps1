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

function bh_win_disable_services() {
  Invoke-Expression $bh_log_func

  # Remove Lock screen
  bh_log "Remove Lockscreen "
  bh_reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1

  # Disable offering of Malicious Software Removal Tool through Windows Update
  bh_log "Disable Malicious Software Removal Tool offering"
  New-Item -Path "HKLM:\Software\Policies\Microsoft\MRT" -ea 0
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Value 1

  # Disable Autorun for all drives
  bh_log "Disable Autorun for all drives"
  bh_reg_new_path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

  # Disable tips
  bh_log "Disable tips "
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f | Out-Null
  reg add "HKCU\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f | Out-Null

  # "Disable Windows Timeline
  bh_log "Disable Windows Timeline "
  Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0

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
  bh_appx_uninstall
}

# ---------------------------------------
# bh_win_disable_services
# ---------------------------------------
bh_win_disable_services