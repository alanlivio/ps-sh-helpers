function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function install_win_winget() {
  if (!(Get-Command 'winget.exe' -ea 0)) {
    log_msg "install_win_winget"
    $repoName = "microsoft/winget-cli"
    $releasesUri = "https://api.github.com/repos/$repoName/releases/latest"
    $url = (Invoke-WebRequest $releasesUri | ConvertFrom-Json).assets | Where-Object name -like *.msixbundle | Select-Object -ExpandProperty browser_download_url
    Invoke-WebRequest $url -OutFile "${env:tmp}\tmp.msixbundle"
    Add-AppPackage -path "${env:tmp}\tmp.msixbundle"
  }
}

install_win_winget

if (!(Get-Command 'git.exe' -ea 0)) {
  log_msg "GitBash not installed. installing.."
  log_msg "make sure to check 'Add GitBash Profile To Windows Terminal'"
  winget install Git.Git -i
  # gitbash do not use your home dir by default, to fix that run in powershell:
  [Environment]::SetEnvironmentVariable("HOME", "${env:userprofile}")
}