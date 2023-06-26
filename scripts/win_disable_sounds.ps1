function log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
log_msg "disable system sounds"
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"