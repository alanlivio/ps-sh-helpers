function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
log_msg "installing winget latest"

$repoName = "microsoft/winget-cli"
$releasesUri = "https://api.github.com/repos/$repoName/releases/latest"
$url = (Invoke-WebRequest $releasesUri | ConvertFrom-Json).assets | Where-Object name -like *.msixbundle | Select-Object -ExpandProperty browser_download_url
Invoke-WebRequest $url -OutFile "${env:tmp}\tmp.msixbundle"
Add-AppPackage -path "${env:tmp}\tmp.msixbundle"