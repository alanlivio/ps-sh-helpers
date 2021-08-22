$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_win_env_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function bh_win_path_add($addPath) {
  if (Test-Path $addPath) {
    $currentpath = [System.Environment]::GetEnvironmentVariable('PATH', 'user')
    $regexAddPath = [regex]::Escape($addPath)
    $arrPath = $currentpath -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
    $newpath = ($arrPath + $addPath) -join ';'
    bh_win_env_add 'PATH' $newpath
  }
  else {
    Throw "$addPath' is not a valid path."
  }
}

function bh_msys_sanity() {
  Set-Alias -Name msysbash -Value C:\msys64\usr\bin\bash.exe # TODO: replace by $MSYS_BASH 
  msysbash -c 'echo none / cygdrive binary,posix=0,noacl,user 0 0 > /etc/fstab'
  # mount /Users to use in both windows and WSL
  msysbash -c 'echo C:/Users/ /Users ntfs binary,noacl,auto 1 1 >>  /etc/fstab'
  # mount /Users/user-name
  msysbash -c 'echo C:/Users/$env:UserName /home/$env:UserName ntfs binary,noacl,auto 1 1 >> /etc/fstab'
  # mount /mnt/c/ like in WSL
  msysbash -c ' echo /c /mnt/c none bind >> /etc/fstab'
  # set home as /mnt/c/Users/user-name
  # msysbash -c "sed -i 's|db_home: cygwin desc|db_home: windows|g' /etc/nsswitch.conf"
  msysbash -c ' echo db_home: windows >> /etc/nsswitch.conf'
}

$MSYS_HOME = "C:\msys64"
function bh_msys_add_to_path() {
  bh_win_path_add "$MSYS_HOME\usr\bin"
  bh_win_path_add "$MSYS_HOME\mingw64\bin"
}

function bh_install_win_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    winget install --scope=machine gsudo
    bh_win_path_add 'C:\Program Files (x86)\gsudo'
  }
}

function bh_install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

# ---------------------------------------
# setup_msys
# ---------------------------------------
bh_log "bh_setup_msys"
$MSYS_HOME = "C:\msys64"

# install winget
if (!(Get-Command "winget.exe" -ea 0)) {
  bh_log "INFO: winget is not installed, installing..."
  bh_install_win_winget
} 
# install gsudo
if (!(Get-Command "gsudo.exe" -ea 0)) {
  bh_log "INFO: gsudo is not installed, installing..."
  bh_install_win_gsudo
} 
if (-not (Test-Path $MSYS_HOME)) {
  Invoke-Expression $bh_log_func
  winget install --scope=machine msys2.msys2
}