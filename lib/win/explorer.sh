# ---------------------------------------
# explorer
# ---------------------------------------

function bh_win_explorer_open_trash() {
  ps_call 'Start-Process explorer shell:recyclebinfolder'
}

function bh_win_explorer_open_appdata_local_programns() {
  ps_call 'Start-Process explorer "${env:localappdata}\Programs"'
}

function bh_win_explorer_open_appdata() {
  ps_call 'Start-Process explorer "${env:appdata}"'
}

function bh_win_explorer_open_tmp() {
  ps_call 'Start-Process explorer "${env:localappdata}\temp"'
}

function bh_win_explorer_open_start_menu_dir() {
  ps_call 'Start-Process explorer "${env:appdata}\Microsoft\Windows\Start Menu\Programs"'
}

function bh_win_explorer_open_start_menu_dir_allusers() {
  ps_call 'Start-Process explorer "${env:allusersprofile}\Microsoft\Windows\Start Menu\Programs"'
}

function bh_win_explorer_restart() {
  ps_call 'taskkill /f /im explorer.exe | Out-Null'
  ps_call 'Start-Process explorer.exe'
}

function bh_win_explorer_home_restore_desktop() {
  ps_call '
    if (Test-Path "${env:userprofile}\Desktop") { return}
    mkdir "${env:userprofile}\Desktop"
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "${env:userprofile}\Desktop" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
  '
}

function bh_win_explorer_hide_home_dotfiles() {
  bh_log_func
  powershell.exe -c 'Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}
