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
  "lfsvc"                                    # Geolocation Service
  "MapsBroker"                               # Downloaded Maps Manager
  "RemoteAccess"                             # Routing and Remote Access
  "RemoteRegistry"                           # Remote Registry
  "TrkWks"                                   # Distributed Link Tracking Client
  "XblAuthManager"                           # Xbox Live Auth Manager
  "XblGameSave"                              # Xbox Live Game Save Service
  "XboxNetApiSvc"                            # Xbox Live Networking Service
)
foreach ($item in $services) {
  service_disable $item
}

#########################
# apps
#########################
function appx_uninstall() {
  foreach ($name in $args) {
    if (Get-AppxPackage -Name $name) {
      log_msg "appx_uninstall $name"
      Get-AppxPackage $name | Remove-AppxPackage
    }
  }
}

$apps = @(
  'MicrosoftTeams'
  'Microsoft.3DBuilder'
  'Microsoft.Appconnector'
  'Microsoft.BingNews'
  'Microsoft.BingSports'
  'Microsoft.BingWeather'
  'Microsoft.CommsPhone'
  'Microsoft.ConnectivityStore'
  'Microsoft.GamingApp'
  'Microsoft.MSPaint'
  'Microsoft.Microsoft3DViewer'
  'Microsoft.MicrosoftOfficeHub'
  'Microsoft.MicrosoftSolitaireCollection'
  'Microsoft.MicrosoftStickyNotes'
  'Microsoft.MixedReality.Portal'
  'Microsoft.Office.Desktop'
  'Microsoft.Office.Sway'
  'Microsoft.OneConnect'
  'Microsoft.People'
  'Microsoft.PowerAutomateDesktop'
  'Microsoft.Print3D'
  'Microsoft.SkypeApp'
  'Microsoft.StorePurchaseApp'
  'Microsoft.Todos'
  'Microsoft.Wallet'
  'Microsoft.WindowsMaps'
  'Microsoft.Xbox.TCUI'
  'Microsoft.XboxApp'
  'Microsoft.XboxGameOverlay'
  'Microsoft.XboxGamingOverlay'
  'Microsoft.XboxIdentityProvider'
  'Microsoft.XboxSpeechToTextOverlay'
  'Microsoft.YourPhone'
  'Microsoft.ZuneMusic'
  'Microsoft.windowscommunicationsapps'
)
log_msg_2nd "uninstall startmenu unused apps "
appx_uninstall @apps