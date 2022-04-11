function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_2nd() { Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ") }

function reg_new_path ($path) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
  }
}

function service_disable($name) {
  log "disabling service $name"
  Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
  Get-Service -Name $name | Set-Service -StartupType Disabled -ea 0
}

function feature_disable($featurename) {
  log "disabling feature $featurename"
  dism.exe /online /quiet /disable-feature /featurename:$featurename /norestart
}

function sanity_services() {
  log "sanity_services"

  log_2nd "disabling Lockscreen "
  reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLogonBackgroundImage" -Value 1

  log_2nd "disabling Autorun for all drives"
  reg_new_path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

  log_2nd "disabling Windows Timeline "
  Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0

  feature_disable Printing-XPSServices-Features
  feature_disable WorkFolders-Client
  
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
    service_disable $item
  }
}

sanity_services