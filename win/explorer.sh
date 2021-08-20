# ---------------------------------------
# explorer
# ---------------------------------------

function bh_explorer_open_trash() {
  ps_call 'Start-Process explorer shell:recyclebinfolder'
}

function bh_explorer_restart() {
  ps_call 'taskkill /f /im explorer.exe | Out-Null'
  ps_call 'Start-Process explorer.exe'
}

function bh_explorer_restore_desktop() {
  ps_call '
    if (Test-Path "${env:userprofile}\Desktop") { return}
    mkdir "${env:userprofile}\Desktop"
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "C:\Users\${env:username}\Desktop" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
  '
}

function bh_explorer_hide_home_dotfiles() {
  bh_log_func
  powershell -c 'Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}
