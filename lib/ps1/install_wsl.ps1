function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    log "install_win_winget"
    $repoName = "microsoft/winget-cli"
    $releasesUri = "https://api.github.com/repos/$repoName/releases/latest"
    $url = (Invoke-WebRequest $releasesUri | ConvertFrom-Json).assets | Where-Object name -like *.msixbundle | Select-Object -ExpandProperty browser_download_url
    Invoke-WebRequest $url -OutFile "${env:tmp}\tmp.msixbundle"
    Add-AppPackage -path "${env:tmp}\tmp.msixbundle"
  }
}
function install_win_gsudo() {
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    log "install_win_gsudo"
    path_add 'C:\Program Files (x86)\gsudo'
  }
}
Set-Alias gsudo 'C:\Program Files (x86)\gsudo\gsudo'
function wsl_get_default() {
  [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
    if ($_.Contains('(')) {
      return $_.Split(' ')[0]
    }
  }
}


# this automate the process describred in :
# - https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
log "install_wsl"
$target_distro = "Canonical.Ubuntu.2204"
$target_cmd = "ubuntu2204.exe"

install_winget
  
# enable wsl feature (require restart)
if (!(Get-Command 'wsl.exe' -ea 0)) {
  log "Windows features for WSL not enabled, enabling..."
  gsudo dism.exe /online /quiet /enable-feature /featurename:$featurename /all/norestart Microsoft-Windows-Subsystem-Linux
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