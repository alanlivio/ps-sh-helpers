function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_msg_2nd() { Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ") }

function reg_new_path ($path) {
  if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force | Out-Null
  }
}

function service_disable($name) {
  log_msg "disabling service $name"
  Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
  Get-Service -Name $name | Set-Service -StartupType Disabled -ea 0
}

function feature_disable($featurename) {
  log_msg "disabling feature $featurename"
  dism.exe /online /quiet /disable-feature /featurename:$featurename /norestart
}

log_msg "sanity_services"

log_msg_2nd "disabling Lockscreen "
reg_new_path "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLog_msgonBackgroundImage" -Value 1

log_msg_2nd "disabling Autorun for all drives"
reg_new_path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

log_msg_2nd "disabling Windows Timeline "
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