# this scropt automate the process from  https://docs.microsoft.com/en-us/windows/wsl/wsl2-install

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function wsl_get_default() {
  [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
    if ($_.Contains('(')) {
      return $_.Split(' ')[0]
    }
  }
}

if (!(Get-Command 'winget.exe' -ea 0)) {
  log_msg "winget is required"
  return
}

$target_distro = "Ubuntu"
$target_winget = "Canonical.Ubuntu"
$target_cmd = "ubuntu.exe"

log_msg "(1/2) installing $target_distro"

# enable wsl feature (require restart)
if (!(Get-Command 'wsl.exe' -ea 0)) {
  log_msg "Windows features for WSL not enabled, enabling..."
  if (!(Get-Command 'gsudo.exe' -ea 0)) {
    log_msg "install_win_gsudo"
    winget install gsudo
    Set-Alias gsudo 'C:\Program Files (x86)\gsudo\gsudo'
  }
  log_msg "Windows features for WSL not enabled, enabling..."
  gsudo dism.exe /online /quiet /enable-feature /featurename:$featurename /all/norestart Microsoft-Windows-Subsystem-Linux
  log_msg "restart windows and run win_install_wsl again"
  return
}

# install ubuntu
if (!(Get-Command $target_cmd -ea 0)) {
  log_msg "$target_distro is not installed, installing from winget..."
  winget install $target_winget
}
else {
  log_msg "$target_distro already installed."
}
log_msg "$target_distro is located on " (Get-Command $target_cmd).Source

# setup ubuntu
if (!(wsl_get_default).Contains("Ubuntu") || !(wsl cat /etc/wsl.conf).Contains($env:username)) {
  log_msg "$target_distro is not configured, running it and setup your user as win ($env:username)..."
  Invoke-Expression "$target_cmd"
  wsl --set-default $target_distro
}  
