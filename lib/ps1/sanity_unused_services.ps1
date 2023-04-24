# based on https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/disable-services.ps1

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

#########################
# features
#########################

function feature_disable($featurename) {
  log_msg "disabling feature $featurename"
  dism.exe /online /quiet /disable-feature /featurename:$featurename /norestart
}

$features = @(
  "Printing-XPSServices-Features"
)
foreach ($item in $features) {
  feature_disable $item
}

#########################
# services
#########################

function service_disable($name) {
  log_msg "disabling service $name"
  Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
  Get-Service -Name $name | Set-Service -StartupType Disabled -Confirm:$false
}

$services = @(
  "diagnosticshub.standardcollector.service" # Diagnostics Hub
  "DiagTrack"                                # Diagnostics Tracking Service
  "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
  "lfsvc"                                    # Geolocation Service
  "MapsBroker"                               # Downloaded Maps Manager
  "RemoteAccess"                             # Routing and Remote Access
  "RemoteRegistry"                           # Remote Registry
  "TrkWks"                                   # Distributed Link Tracking Client
  "WSearch"                                  # Windows Search
  "XblAuthManager"                           # Xbox Live Auth Manager
  "XblGameSave"                              # Xbox Live Game Save Service
  "XboxNetApiSvc"                            # Xbox Live Networking Service
  "ndu"                                      # Windows Network Data Usage Monitor
)
foreach ($item in $services) {
  service_disable $item
}