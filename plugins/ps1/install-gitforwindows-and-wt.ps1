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
    # gitbash do not use your home dir by default, to fix that run in powershell:
    [Environment]::SetEnvironmentVariable("HOME", "${env:userprofile}")
  }
}

install_win_winget
install_win_wt
install_win_gitbash