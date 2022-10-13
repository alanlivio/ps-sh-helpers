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

if (!(Get-Command 'gsudo.exe' -ea 0)) {
  log_msg "install_win_gsudo"
  winget install gsudo
  Set-Alias gsudo 'C:\Program Files (x86)\gsudo\gsudo'
}

# this automate the process describred in :
# - https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
log_msg "install_wsl"
$target_distro = "Canonical.Ubuntu.2204"
$target_cmd = "ubuntu2204.exe"
  
# enable wsl feature (require restart)
if (!(Get-Command 'wsl.exe' -ea 0)) {
  log_msg "Windows features for WSL not enabled, enabling..."
  gsudo dism.exe /online /quiet /enable-feature /featurename:$featurename /all/norestart Microsoft-Windows-Subsystem-Linux
  log_msg "restart windows and run win_install_wsl again"
  return
}

# enable wsl 2
wsl -l -v | Out-null # -v is only avaliable in wsl 2
if ($LastExitCode -eq -1) {
  wsl --install
}

# install ubuntu
if (!(Get-Command $target_cmd -ea 0)) {
  log_msg "Ubuntu is not installed, installing..."
  winget install $target_distro
} 

if (!(wsl echo '$HOME').Contains("Users")) {
  log_msg "WSL does not use windows UserProfile as home."
  log_msg "First run it and configure username and passwd."
  log_msg "then run wsl-fix-home.ps1"
  return
}

log_msg "done. listing..."
wsl --list --verbose
log_msg "location is " (Get-Command $target_cmd).Source