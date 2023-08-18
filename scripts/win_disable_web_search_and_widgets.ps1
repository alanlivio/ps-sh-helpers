function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "disable Web Search and Web Widgets"
winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy
