function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function env_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function path_add($addPath) {
  $currentpath = [System.Environment]::GetEnvironmentVariable('PATH', 'user')
  $regexAddPath = [regex]::Escape($addPath)
  $arrPath = $currentpath -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
  $newpath = ($arrPath + $addPath) -join ';'
  env_add 'PATH' $newpath
}

function install_win_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    log "install_win_gsudo"
    winget install --scope=machine gsudo
    path_add 'C:\Program Files (x86)\gsudo'
  }
}

function install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    log "install_win_winget"
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

log "install_msys"
$MSYS_HOME = "C:\msys64"
install_win_gsudo
install_win_winget
if (-not (Test-Path $MSYS_HOME)) {
  gsudo winget install --scope=machine msys2.msys2
  path_add "$MSYS_HOME\usr\bin"
  path_add "$MSYS_HOME\mingw64\bin"
}