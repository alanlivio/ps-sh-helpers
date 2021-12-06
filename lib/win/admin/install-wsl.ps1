$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_syswin_feature_enable($featurename) {
  Invoke-Expression "$bh_log_func $featurename"
  gsudo dism.exe /online /quiet /enable-feature /featurename:$featurename /all/norestart
}

function bh_win_env_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function bh_path_win_add($addPath) {
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

function bh_wsl_get_default() {
  [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
    if ($_.Contains('(')) {
      return $_.Split(' ')[0]
    }
  }
}

function bh_wsl_get_default_version() {
  Foreach ($i in (wsl -l -v)) {
    if ($i.Contains('*')) {
      return $i.Split(' ')[-1]
    }
  }
}

function bh_wsl_terminate() {
  wsl -t (bh_wsl_get_default)
}

function bh_wsl_set_version2() {
  wsl --set-version (bh_wsl_get_default) 2
}

function bh_install_win_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    winget install --scope=machine gsudo
    bh_path_win_add 'C:\Program Files (x86)\gsudo'
  }
}

function bh_install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

function bh_wsl_fix_home() {
  Invoke-Expression $bh_log_func
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

  bh_wsl_terminate

  # enable sudoer
  wsl -u root usermod -aG sudo "$env:UserName"
  wsl -u root usermod -aG root "$env:UserName"

  # change default folder to /mnt/c/Users/
  wsl -u root skill -KILL -u $env:UserName
  wsl -u root usermod -d /mnt/c/Users/$env:UserName $env:UserName
  
  # delete the folder at /home/ and create a link to one at /mnt/c/Users/
  wsl -u root rm -rf  /home/$env:UserName
  wsl -u root ln -s /mnt/c/Users/$env:UserName /home/$env:UserName

  # changing file permissions
  bh_log "Changing file permissions "
  wsl -u root chown $env:UserName:$env:UserName /mnt/c/Users/$env:UserName/*
}


function bh_install_win_wsl() {
  # this helper automate the process describred in :
  # - https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
  # - https://ubuntu.com/wsl
  Invoke-Expression $bh_log_func

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
  # enable wsl feature (require restart)
  if (!(Get-Command 'wsl.exe' -ea 0)) {
    bh_log "INFO: Windows features for WSL not enabled, enabling..."
    bh_syswin_feature_enable /featurename:VirtualMachinePlatform 
    bh_syswin_feature_enable Microsoft-Windows-Subsystem-Linux
    bh_log "INFO: restart windows and run bh_setup_ubu again"
    return
  }
  # install ubuntu
  if (!(Get-Command "ubuntu*.exe" -ea 0)) {
    bh_log "INFO: Ubuntu is not installed, installing..."
    winget install Canonical.Ubuntu
  } 
  # configure ubuntu distro
  wsl -l | Out-null
  if ($LastExitCode -eq -1) {
    bh_log "INFO: Ubuntu is not configured, running it..."
    bh_log "INFO: You should configure username and passwd, after that exit Ubuntu by invoke 'exit'."
    Invoke-Expression (Get-Command "ubuntu*.exe").Source
  }
  # enable wsl 2
  wsl -l -v | Out-null # -v is only avaliable in wsl 2
  if ($LastExitCode -eq -1) {
    bh_log "INFO: WSL 2 kernel update is not installed, installing..."
    Invoke-WebRequest -Uri "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi" -Outfile $env:TEMP\wsl_update_x64.msi
    msiexec.exe /I "$env:TEMP\wsl_update_x64.msi"
  }
  # set to version 2
  if ((bh_wsl_get_default_version) -eq 1) {
    bh_log "INFO: Ubuntu distro is in wsl version 1, converting it to version 2..."
    bh_wsl_set_version2 bh_wsl_get_default
  }
  # fix home user to \Users
  if (!(wsl echo '$HOME').Contains("Users")) {
    bh_log "INFO: Configuring to same home folder as windows..."
    bh_wsl_fix_home
  }
}

bh_install_win_wsl