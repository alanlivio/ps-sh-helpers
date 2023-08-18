function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "disable Windows Search"
cmd.exe /c 'sc stop "wsearch"'
cmd.exe /c 'sc config "wsearch" start=disabled'