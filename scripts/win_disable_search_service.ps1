function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "disable Windows Search"
gsudo cmd.exe /c 'sc stop "wsearch"'
gsudo cmd.exe /c 'sc config "wsearch" start=disabled'