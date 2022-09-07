function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    log_msg "install_win_winget"
    $repoName = "microsoft/winget-cli"
    $releasesUri = "https://api.github.com/repos/$repoName/releases/latest"
    $url = (Invoke-WebRequest $releasesUri | ConvertFrom-Json).assets | Where-Object name -like *.msixbundle | Select-Object -ExpandProperty browser_download_url
    Invoke-WebRequest $url -OutFile "${env:tmp}\tmp.msixbundle"
    Add-AppPackage -path "${env:tmp}\tmp.msixbundle"
  }
}
function install_win_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    log_msg "install_win_gsudo"
    path_add 'C:\Program Files (x86)\gsudo'
  }
}
Set-Alias gsudo 'C:\Program Files (x86)\gsudo\gsudo'

log_msg "install_msys"
install_win_gsudo
install_win_winget

$MSYS_HOME = "C:\msys64"
if (-not (Test-Path $MSYS_HOME)) {
  gsudo winget install --scope=machine msys2.msys2
}
else{
  log_msg "$MSYS_HOME already exist"
}