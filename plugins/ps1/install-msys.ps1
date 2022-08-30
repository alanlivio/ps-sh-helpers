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

function msys_use_same_home() {
  Set-Alias -Name msysbash -Value C:\msys64\usr\bin\bash.exe
  msysbash -c 'if ! test -d /mnt/; then mkdir /mnt/; fi'
  msysbash -c 'echo none / cygdrive binary,posix=0,noacl,user 0 0 > /etc/fstab'
  # mount /Users to use in both windows and WSL
  msysbash -c 'echo C:/Users/ /Users ntfs binary,noacl,auto 1 1 >>  /etc/fstab'
  # mount /mnt/c/ like in WSL
  msysbash -c ' echo /c /mnt/c none bind >> /etc/fstab'
  # set home as /mnt/c/Users/user-name
  # msysbash -c "sed -i 's|db_home: cygwin desc|db_home: windows|g' /etc/nsswitch.conf"
  msysbash -c ' echo db_home: windows >> /etc/nsswitch.conf'
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

function install_msys() {
  log "install_msys"
  $MSYS_HOME = "C:\msys64"
  install_win_gsudo
  install_win_winget
  if (-not (Test-Path $MSYS_HOME)) {
    gsudo winget install --scope=machine msys2.msys2
    path_add "$MSYS_HOME\usr\bin"
    path_add "$MSYS_HOME\mingw64\bin"
  }
}
install_msys
msys_use_same_home