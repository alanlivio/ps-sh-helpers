function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "installing msys"
install_win_gsudo
install_win_winget

if (!(Get-Command 'winget.exe' -ea 0)) {
  log_msg "winget is required"
  return
}

if (!(Get-Command 'gsudo.exe' -ea 0)) {
  log_msg "install_win_gsudo"
  path_add 'C:\Program Files (x86)\gsudo'
  Set-Alias gsudo 'C:\Program Files (x86)\gsudo\gsudo'
}

$MSYS_HOME = "C:\msys64"
if (-not (Test-Path $MSYS_HOME)) {
  gsudo winget install --scope=machine msys2.msys2
}
else{
  log_msg "$MSYS_HOME already exist"
}