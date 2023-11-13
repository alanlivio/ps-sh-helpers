function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }


log_msg "disable Web Search"
New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER  -ea 0 | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name 'BingSearchEnabled' -Type DWORD -Value '0'
New-Item -Path "HKCU:HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name 'DisableSearchBoxSuggestions' -Type DWORD -Value '1'

log_msg "disable Web Widgets"
winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy