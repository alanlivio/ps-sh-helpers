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

feature_disable Printing-XPSServices-Features

$services = @("*diagnosticshub.standardcollector.service*" # Diagnostics Hub
  "*MapsBroker*" # Downloaded Maps Manager
  "*TrkWks*" # Distributed Link Tracking Client
  "*XblAuthManager*" # Xbox Live Auth Manager
  "*XboxNetApiSvc*" # Xbox Live Networking Service
  "*XblGameSave*" # Xbox Live Game Save
)
foreach ($item in $services) {
  service_disable $item
}