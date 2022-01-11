$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_log_2nd() {
  Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ")
}

function bh_win_appx_uninstall() {
  foreach ($name in $args) {
    if (Get-AppxPackage -Name $name) {
      Invoke-Expression "$bh_log_func $name"
      Get-AppxPackage $name | Remove-AppxPackage
    }
  }
}

# ---------------------------------------
# setup_win
# ---------------------------------------

function bh_win_sanity_start_menu() {
  Invoke-Expression $bh_log_func
  $pkgs = @(
    # microsoft
    'MicrosoftTeams'
    'Microsoft.3DBuilder'
    'Microsoft.Appconnector'
    'Microsoft.BingNews'
    'Microsoft.BingSports'
    'Microsoft.BingWeather'
    'Microsoft.CommsPhone'
    'Microsoft.ConnectivityStore'
    'Microsoft.GamingApp'
    'Microsoft.Getstarted'
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
    'Microsoft.WindowsAlarms'
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
    # other
    '7EE7776C.LinkedInforWindows'
    '9E2F88E3.Twitter'
    'A278AB0D.DisneyMagicKingdoms'
    'A278AB0D.MarchofEmpires'
    'Facebook.Facebook'
    'king.com.BubbleWitch3Saga'
    'Disney.37853FC22B2CE'
    'king.com.BubbleWitch3Saga'
    'king.com.CandyCrushFriends'
    'king.com.CandyCrushSaga'
    'king.com.CandyCrushSodaSaga'
    'king.com.FarmHeroesSaga_5.34.8.0_x86__kgqvnymyfvs32'
    'king.com.FarmHeroesSaga'
    'NORDCURRENT.COOKINGFEVER'
    'SpotifyAB.SpotifyMusic'
    'Facebook.InstagramBeta'
    'BytedancePte.Ltd.TikTok'
    'Microsoft.MicrosoftEdge.Stable'
  )
  bh_win_appx_uninstall @pkgs
  
  bh_log_2nd "disable Bing search "
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /d "0" /t REG_DWORD /f  | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /d "0" /t REG_DWORD /f | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /d "0" /t REG_DWORD /f | Out-null
  
  bh_log_2nd "hide recent shortcuts"
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

function bh_win_sanity_taskbar() {
  Invoke-Expression $bh_log_func

  bh_log_2nd "enable small app icons"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarSmallIcons -Value 1
  # wiw 11
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarSi -Value 0

  bh_log_2nd "disable search button"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0

  bh_log_2nd "disable task view button"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Value 0
}

function bh_win_sanity_explorer() {
  Invoke-Expression $bh_log_func
  
  bh_log_2nd "set visuals to performace"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name 'VisualFXSetting' -Value 2
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name 'EnableTransparency' -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144, 18, 3, 128, 16, 0, 0, 0))
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0

  bh_log_2nd "enable dark mode"
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 00000000 /f | Out-Null

  bh_log_2nd "hide user folder from desktop"
  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0
  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0

  bh_log_2nd "enable show file extensions"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
  
  bh_log_2nd "disable system sounds"
  Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"
  
  bh_log_2nd "disable icons in desktop"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

  bh_log_2nd "disable recent files "
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0
  
  bh_log_2nd "disable new drives autoplay"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
  
  bh_log_2nd "set explorer open in This PC"
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

function bh_win_sanity_keyboard() {
  Invoke-Expression $bh_log_func

  bh_log_2nd "disable Accessibility Keys Prompts"
  New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name 'Flags' -Type String -Value '506'
  New-Item -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name 'Flags' -Type String -Value '58'
  New-Item -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Force | Out-Null
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name 'Flags' -Type String -Value '122'

  bh_log_2nd "disable AutoRotation Hotkeys"
  reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null
  
  bh_log_2nd "disable shortcut lang"
  Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
  Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3
}

function bh_win_explorer_restart() {
  Invoke-Expression $bh_log_func
  Stop-Process -ProcessName explorer -ea 0 | Out-Null
}

bh_log "bh_win_sanity"
bh_win_sanity_start_menu
bh_win_sanity_taskbar
bh_win_sanity_explorer
bh_win_sanity_keyboard
bh_win_explorer_restart