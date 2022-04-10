$log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function sysfeature_enable($featurename) {
  Invoke-Expression "$log_func $featurename"
  gsudo dism.exe /online /quiet /enable-feature /featurename:$featurename /all/norestart
}

function env_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function path_add($addPath) {
  if (Test-Path $addPath) {
    $currentpath = [System.Environment]::GetEnvironmentVariable('PATH', 'user')
    $regexAddPath = [regex]::Escape($addPath)
    $arrPath = $currentpath -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
    $newpath = ($arrPath + $addPath) -join ';'
    env_add 'PATH' $newpath
  }
  else {
    Throw "$addPath' is not a valid path."
  }
}

function wsl_get_default() {
  [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
    if ($_.Contains('(')) {
      return $_.Split(' ')[0]
    }
  }
}

function wsl_get_default_version() {
  Foreach ($i in (wsl -l -v)) {
    if ($i.Contains('*')) {
      return $i.Split(' ')[-1]
    }
  }
}

function wsl_terminate() {
  wsl -t (wsl_get_default)
}

function wsl_set_version2() {
  wsl --set-version (wsl_get_default) 2
}

function install_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    Invoke-Expression $log_func
    winget install --scope=machine gsudo
    path_add 'C:\Program Files (x86)\gsudo'
  }
}

function install_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $log_func
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

function wsl_fix_home() {
  Invoke-Expression $log_func
  # fix file metadata
  # https://docs.microsoft.com/en-us/windows/wsl/wsl-config
  # https://github.com/Microsoft/WSL/issues/3138
  # https://devblogs.microsoft.com/commandline/chmod-chown-wsl-improvements/
  wsl -u root bash -c 'echo "[automount]" > /etc/wsl.conf'
  wsl -u root bash -c 'echo "enabled=true" >> /etc/wsl.conf'
  wsl -u root bash -c 'echo "root=/mnt" >> /etc/wsl.conf'
  wsl -u root bash -c 'echo "mountFsTab=false" >> /etc/wsl.conf'
  wsl -u root bash -c 'echo "options=\"metadata,uid=1000,gid=1000,umask=0022,fmask=11\"" >> /etc/wsl.conf'
  # useful links /Users and /c
  wsl -u root bash -c 'if ! test -d /Users; then sudo ln -s /mnt/c/Users /Users; fi'
  wsl -u root bash -c 'if ! test -d /c; then sudo ln -s /mnt/c/ /c; fi'

  wsl_terminate

  # enable sudoer
  wsl -u root usermod -aG sudo "$env:UserName"
  wsl -u root usermod -aG root "$env:UserName"

  # change default dir to /mnt/c/Users/
  wsl -u root skill -KILL -u $env:UserName
  wsl -u root usermod -d /mnt/c/Users/$env:UserName $env:UserName
  
  # delete the dir at /home/ and create a link to one at /mnt/c/Users/
  wsl -u root rm -rf  /home/$env:UserName
  wsl -u root ln -s /mnt/c/Users/$env:UserName /home/$env:UserName

  # changing file permissions
  log "Changing file permissions "
  wsl -u root chown $env:UserName:$env:UserName /mnt/c/Users/$env:UserName/*
}


function install_wsl() {
  # this helper automate the process describred in :
  # - https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
  # - https://ubuntu.com/wsl
  Invoke-Expression $log_func

  install_winget
  install_gsudo
  
  # enable wsl feature (require restart)
  if (!(Get-Command 'wsl.exe' -ea 0)) {
    log "INFO: Windows features for WSL not enabled, enabling..."
    sysfeature_enable Microsoft-Windows-Subsystem-Linux
    log "INFO: restart windows and run setup_ubu again"
    return
  }
  # enable wsl 2
  wsl -l -v | Out-null # -v is only avaliable in wsl 2
  if ($LastExitCode -eq -1) {
    wsl --install
  }
  # install ubuntu
  if (!(Get-Command "ubuntu*.exe" -ea 0)) {
    log "INFO: Ubuntu is not installed, installing..."
    winget install Canonical.Ubuntu
  } 
  # configure ubuntu distro
  wsl -l | Out-null
  if ($LastExitCode -eq -1) {
    log "INFO: Ubuntu is not configured, running it..."
    log "INFO: You should configure username and passwd, after that exit Ubuntu by invoke 'exit'."
    Invoke-Expression (Get-Command "ubuntu*.exe").Source
  }
  # set to version 2
  if ((wsl_get_default_version) -eq 1) {
    log "INFO: Ubuntu distro is in wsl version 1, converting it to version 2..."
    wsl_set_version2 wsl_get_default
  }
  # fix home user to \Users
  if (!(wsl echo '$HOME').Contains("Users")) {
    log "INFO: Configuring to same home dir as windows..."
    wsl_fix_home
  }
}

install_wsl