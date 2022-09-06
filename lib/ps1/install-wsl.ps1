function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function sysfeature_enable($featurename) {
  log "sysfeature_enable"
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

function install_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    log "install_winget"
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

function wsl_same_home() {
  log "wsl_same_home"

}

# this automate the process describred in :
# - https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
# - https://ubuntu.com/wsl

log "install_wsl"
$target_distro="Canonical.Ubuntu.2204"
$target_cmd="ubuntu2204.exe"



install_winget
  
# enable wsl feature (require restart)
if (!(Get-Command 'wsl.exe' -ea 0)) {
  log "Windows features for WSL not enabled, enabling..."
  sysfeature_enable Microsoft-Windows-Subsystem-Linux
  log "restart windows and run win_install_wsl again"
  return
}

# enable wsl 2
wsl -l -v | Out-null # -v is only avaliable in wsl 2
if ($LastExitCode -eq -1) {
  wsl --install
}

# install ubuntu
if (!(Get-Command $target_cmd -ea 0)) {
  log "Ubuntu is not installed, installing..."
  winget install $target_distro
} 

if (!(wsl echo '$HOME').Contains("Users")) {
  log "WSL does not use windows UserProfile as home."
  log "First run it and configure username and passwd."
  log "then run wsl-fix-home.ps1"
  return
}

log "done. listing..."
wsl --list --verbose
log "location is " (Get-Command $target_cmd).Source