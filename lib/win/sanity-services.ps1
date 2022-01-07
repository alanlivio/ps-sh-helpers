$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_reg_new_path ($path) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
  }
}

function bh_win_service_disable($name) {
  bh_log "disabling service $name"
  Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
  Get-Service -Name $name | Set-Service -StartupType Disabled -ea 0
}

function bh_win_feature_disable($featurename) {
  bh_log "disabling feature $featurename"
  dism.exe /online /quiet /disable-feature /featurename:$featurename /norestart
}

function bh_win_disable_unused_services_features() {
  Invoke-Expression $bh_log_func

  bh_log "disabling Lockscreen "
  bh_reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1

  bh_log "disabling Autorun for all drives"
  bh_reg_new_path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

  bh_log "disabling Windows Timeline "
  Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0

  bh_win_feature_disable Printing-XPSServices-Features
  bh_win_feature_disable WorkFolders-Client
  
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
  foreach ($item in $services) {
    bh_win_service_disable $item
  }
}

bh_win_disable_unused_services_features