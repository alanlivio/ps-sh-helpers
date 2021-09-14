$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_log_2nd() {
  Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ")
}

function bh_appx_uninstall() {
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

function bh_sanity_start_menu() {
  Invoke-Expression $bh_log_func
  $pkgs = @(
    # microsoft
    'Microsoft.3DBuilder'
    'Microsoft.Appconnector'
    'Microsoft.BingNews'
    'Microsoft.MSPaint'
    'Microsoft.BingSports'
    'Microsoft.BingWeather'
    'Microsoft.CommsPhone'
    'Microsoft.SkypeApp'
    'Microsoft.ConnectivityStore'
    'Microsoft.Getstarted'
    'Microsoft.Microsoft3DViewer'
    'Microsoft.MicrosoftOfficeHub'
    'Microsoft.MicrosoftSolitaireCollection'
    'Microsoft.MicrosoftStickyNotes'
    'Microsoft.windowscommunicationsapps'
    'Microsoft.MixedReality.Portal'
    'Microsoft.Office.Desktop'
    'Microsoft.Office.Sway'
    'Microsoft.OneConnect'
    'Microsoft.Print3D'
    'Microsoft.People'
    'Microsoft.StorePurchaseApp'
    'Microsoft.Wallet'
    'Microsoft.WindowsAlarms'
    'Microsoft.WindowsMaps'
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxApp'
    'Microsoft.XboxGameOverlay'
    'Microsoft.XboxGamingOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
    'Microsoft.ZuneMusic'
    # other
    '7EE7776C.LinkedInforWindows'
    '9E2F88E3.Twitter'
    'A278AB0D.DisneyMagicKingdoms'
    'A278AB0D.MarchofEmpires'
    'Facebook.Facebook'
    'king.com.BubbleWitch3Saga'
    'king.com.BubbleWitch3Saga'
    'king.com.CandyCrushFriends'
    'king.com.CandyCrushSaga'
    'king.com.CandyCrushSodaSaga'
    'king.com.FarmHeroesSaga_5.34.8.0_x86__kgqvnymyfvs32'
    'king.com.FarmHeroesSaga'
    'NORDCURRENT.COOKINGFEVER'
    'SpotifyAB.SpotifyMusic'
  )
  bh_appx_uninstall @pkgs
  
  bh_log_2nd "disable Bing search "
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /d "0" /t REG_DWORD /f  | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /d "0" /t REG_DWORD /f | Out-null
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /d "0" /t REG_DWORD /f | Out-null
}

function bh_sanity_taskbar() {
  Invoke-Expression $bh_log_func

  bh_log_2nd "enable small app icons"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarSmallIcons -Value 1

  bh_log_2nd "disable search button"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0

  bh_log_2nd "disable task view button"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Value 0
}

function bh_sanity_explorer() {
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

  bh_log_2nd "enable show file extensions"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0
  
  bh_log_2nd "disable system sounds"
  Set-ItemProperty -Path HKCU:\AppEvents\Schemes -Name "(Default)" -Value ".None"
  
  bh_log_2nd "disable icons in desktop"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

  bh_log_2nd "disable recent files "
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0
  
  bh_log_2nd "disable new drives autoplay"
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1

  bh_log_2nd "disable user folders under This PC "
  # Remove Desktop from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -ea 0
  # Remove Documents from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -ea 0
  # Remove Downloads from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -ea 0
  # Remove Music from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ea 0
  # Remove Pictures from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ea 0
  # Remove Videos from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ea 0
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ea 0
  # Remove 3D Objects from This PC
  Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ea 0
  Remove-Item "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ea 0

  bh_log_2nd "disable submenu Share with"
  Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ea 0
  Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ea 0
  bh_log_2nd "disable submenu Gitg"
  Remove-Item "HKCR:\Directory\shell\gitg" -Recurse -ea 0
  
  bh_log_2nd "disable submenu Add/play with vlc"
  Remove-Item "HKCR:\Directory\shell\AddToPlaylistVLC" -Recurse -ea 0
  Remove-Item "HKCR:\Directory\shell\PlayWithVLC" -Recurse -ea 0
  
  bh_log_2nd "disable submenu Git bash"
  Remove-Item "HKCR:\Directory\shell\git_gui" -Recurse -ea 0
  Remove-Item "HKCR:\Directory\shell\git_shell" -Recurse -ea 0
  
  bh_log_2nd "disable submenu Open With "
  Remove-Item -LiteralPath 'HKCR:\*\shellex\OpenWithList' -ea 0
  
  bh_log_2nd "disable submenu Pin To Start "
  Remove-Item -LiteralPath 'HKCR:\*\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}' -ea 0
  Remove-Item -LiteralPath 'HKCR:\*\shellex\ContextMenuHandlers\{a2a9545d-a0c2-42b4-9708-a0b2badd77c8}' -ea 0
  Remove-Item 'HKCR:\Folder\shellex\ContextMenuHandlers\PintoStartScreen' -ea 0
  
  bh_log_2nd "disable submenu Include in library"
  Remove-Item "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ea 0
  Remove-Item "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ea 0
  
  bh_log_2nd "disable submenu Send to"
  Remove-Item -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -Recurse -ea 0
}

function bh_sanity_keyboard() {
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

function bh_explorer_restart() {
  Invoke-Expression $bh_log_func
  Stop-Process -ProcessName explorer -ea 0 | Out-Null
}

bh_log "bh_win_sanity"
bh_sanity_start_menu
bh_sanity_taskbar
bh_sanity_explorer
bh_sanity_keyboard
bh_explorer_restart