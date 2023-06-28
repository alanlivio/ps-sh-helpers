function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

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
  'Microsoft.OneConnect'
  'Microsoft.People'
  'Microsoft.PowerAutomateDesktop'
  'Microsoft.Print3D'
  'Microsoft.SkypeApp'
  'Microsoft.StorePurchaseApp'
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
)
appx_uninstall @apps