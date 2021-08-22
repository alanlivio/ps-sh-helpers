$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_env_win_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function bh_path_win_add($addPath) {
  if (Test-Path $addPath) {
    $currentpath = [System.Environment]::GetEnvironmentVariable('PATH', 'user')
    $regexAddPath = [regex]::Escape($addPath)
    $arrPath = $currentpath -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
    $newpath = ($arrPath + $addPath) -join ';'
    bh_env_win_add 'PATH' $newpath
  }
  else {
    Throw "$addPath' is not a valid path."
  }
}

function bh_winget_installed() {
  $tmpfile = New-TemporaryFile
  winget export $tmpfile | Out-null
  $pkgs = ((Get-Content $tmpfile | ConvertFrom-Json).Sources.Packages | ForEach-Object { $_.PackageIdentifier }) -join " "
  return $pkgs
}

function bh_winget_install() {
  Invoke-Expression $bh_log_func
  $pkgs_to_install = ""
  # get installed pkgs
  $pkgs = $(bh_winget_installed)
  # select to install
  foreach ($name in $args) {
    if (-not ([string]::IsNullOrEmpty("$name")) -and (-not $pkgs.Contains("$name") )) {
      $pkgs_to_install = "$pkgs_to_install $name"
    }
  }
  if ($pkgs_to_install) {
    bh_log "pkgs_to_install=$pkgs_to_install"
    foreach ($pkg in $pkgs_to_install) {
      Invoke-Expression "gsudo winget install --silent $pkg"
    }
  }
}

function bh_winget_uninstall() {
  Invoke-Expression $bh_log_func
  $pkgs_to_uninstall = ""
  # get installed pkgs
  $pkgs = $(bh_winget_installed)
  # select to uninstall
  foreach ($name in $args) {
    if (-not ([string]::IsNullOrEmpty("$name")) -and ($pkgs.Contains("$name") )) {
      $pkgs_to_uninstall = "$pkgs_to_uninstall $name"
    }
  }
  if ($pkgs_to_uninstall) {
    bh_log "pkgs_to_uninstall=$pkgs_to_uninstall"
    foreach ($pkg in $pkgs_to_uninstall) {
      Invoke-Expression "winget uninstall --silent $pkg"
    }
  }
}

function bh_install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

function bh_install_win_python() {
  # path depends if your winget settings uses "scope": "user" or "m }hine"
  $py_exe_1 = "${env:UserProfile}\AppData\Local\Programs\Python\Python39\python.exe"
  $py_exe_2 = "C:\Program Files\Python39\python.exe"
  if (!(Test-Path $py_exe_1) -and !(Test-Path $py_exe_2)) {
    winget install Python.Python.3 --scope=user -i
  }
  # Remove windows alias. See https://superuser.com/questions/1437590/typing-python-on-windows-10-version-1903-command-prompt-opens-microsoft-stor
  Remove-Item $env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\python*.exe
  if (Test-Path $py_exe_1) { 
    bh_path_win_add "$(Split-Path $py_exe_1)"
    bh_path_win_add "$(Split-Path $py_exe_1)\Scripts"
  }
  elseif (Test-Path $py_exe_2) {
    bh_path_win_add "$(Split-Path $py_exe_2)" 
    bh_path_win_add "$(Split-Path $py_exe_2)\Scripts"
  }
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

function bh_setup_start_menu_sanity() {
  Invoke-Expression $bh_log_func
  # microsoft
  $pkgs = @(
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
}

function bh_setup_explorer_sanity() {
  Invoke-Expression $bh_log_func

  # Use small icons
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarSmallIcons -Value 1

  # Hide search button
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0

  # Hide task view button
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Value 0

  # Hide taskbar people icon
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0

  # Visual to performace
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

  # Enable dark mode
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 00000000 /f | Out-Null

  # Disable system sounds
  Set-ItemProperty -Path HKCU:\AppEvents\Schemes -Name "(Default)" -Value ".None"

  # Disable AutoRotation Hotkeys
  reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null
  
  # Hide icons in desktop
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

  # Hide recently explorer shortcut
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0

  # Set explorer to open to 'This PC'
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Value 1

  # disable shortcut lang
  Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
  Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3
  
  # restart explorer
  Stop-Process -ProcessName explorer -ea 0 | Out-Null
}

bh_log "bh_setup_win"
# install winget
bh_install_win_winget
# install wt
if (!(Get-Command 'wt' -ea 0)) {
  bh_winget_install Microsoft.WindowsTerminal
}
# install vscode
if (!(Get-Command 'code' -ea 0)) {
  bh_winget_install Microsoft.VisualStudioCode
}
bh_setup_explorer_sanity
bh_setup_start_menu_sanity