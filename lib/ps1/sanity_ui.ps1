function log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_msg_2nd () { Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ") }

function appx_uninstall() {
  foreach ($name in $args) {
    if (Get-AppxPackage -Name $name) {
      log_msg "appx_uninstall $name"
      Get-AppxPackage $name | Remove-AppxPackage
    }
  }
}
  
# sanity_taskbar
log_msg "sanity_taskbar"
$pkgs = @(
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
appx_uninstall @pkgs

New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -ea 0 | Out-Null 
New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER  -ea 0 | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT   -ea 0 | Out-Null

log_msg_2nd "disable taskbar search button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0
log_msg_2nd "disable taskbar button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Value 0
log_msg_2nd "disable widgets"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarDa" -Value 0

# sanity_dark_no_effects
log_msg "sanity_dark_no_effects"

log_msg_2nd "set ui to performace"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name 'VisualFXSetting' -Value 2
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name 'EnableTransparency' -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0
log_msg_2nd "enable dark mode"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 00000000 /f | Out-Null
log_msg_2nd "disable system sounds"
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"

# sanity_file_explorer
log_msg "sanity_file_explorer"

log_msg_2nd "hide user dir from desktop"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0

log_msg_2nd "disable new drives autoplay"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1

log_msg_2nd "enable file explorer show extensions"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
log_msg_2nd "disable file explorer recent files "
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0

# sanity_keyboard
log_msg "sanity_keyboard"

log_msg_2nd "disable Accessibility Keys Prompts"

New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name 'Flags' -Type String -Value '506'
New-Item -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name 'Flags' -Type String -Value '58'
New-Item -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name 'Flags' -Type String -Value '122'

log_msg_2nd "disable AutoRotation Hotkeys"
reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null

log_msg_2nd "disable shortcut lang"
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3

# explorer_restart
log_msg "explorer_restart"
Stop-Process -ProcessName explorer -ea 0 | Out-Null