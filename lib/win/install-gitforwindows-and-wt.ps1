$log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'

function log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    Invoke-Expression $log_func
    $filename = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $url = "https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/$filename"
    Invoke-WebRequest $url -OutFile "${env:tmp}\$filename"
    Add-AppPackage -path "${env:tmp}\$filename"
  }
}

function install_win_wt() {
  if (!(Get-Command 'wt' -ea 0)) {
    winget install Microsoft.WindowsTerminal
  }
}

function install_win_gitbash() {
  if (!(Get-Command 'git.exe' -ea 0)) {
    log "GitBash not installed. installing.."
    log "make sure to check 'Add GitBash Profile To Windows Terminal'"
    winget install Git.Git -i
    # gitbash do not use your home folder by default, to fix that run in powershell:
    [Environment]::SetEnvironmentVariable("HOME", "${env:userprofile}")
  }
}

install_win_winget
install_win_wt
install_win_gitbash