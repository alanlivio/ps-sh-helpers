function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}
function bh_install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $bh_log_func
    Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  }
}

function bh_install_win_wt() {
  if (!(Get-Command 'wt' -ea 0)) {
    winget install Microsoft.WindowsTerminal
  }
}

function bh_install_win_gitbash() {
  if (!(Get-Command 'git.exe' -ea 0)) {
    bh_log "GitBash not installed. installing.."
    bh_log "make sure to check 'Add GitBash Profile To Windows Terminal'"
    winget install Git.Git -i
    # gitbash do not use your home folder by default, to fix that run in powershell:
    [Environment]::SetEnvironmentVariable("HOME", "${env:userprofile}")
  }
}

bh_log "bh-on-win"
# install winget
bh_install_win_winget
# install wt
bh_install_win_wt
# install git
bh_install_win_gitbash

if (!(Test-Path $("${env:userprofile}\.bh"))) {
  # clone bh
  git clone https://github.com/alanlivio/bash-helpers.git $("${env:userprofile}\.bh")
  # load bh in gitbash console
  Write-Output 'source $HOME/.bh/rc.sh' | Out-File -FilePath "${env:userprofile}\.bashrc" -Append -Encoding ascii
  # hide MSYSM in gitbash console
  & "$(Split-Path  (Get-Command "git.exe").Source)\..\bin\bash.exe"  -c "sed '/show\sMSYSTEM/d' -i /etc/profile.d/git-prompt.sh"
}