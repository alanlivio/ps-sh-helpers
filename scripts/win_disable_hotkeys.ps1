function log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER  -ea 0 | Out-Null

log_msg "disable hotkeys Accessibility"
New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name 'Flags' -Type String -Value '506'
New-Item -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name 'Flags' -Type String -Value '58'
New-Item -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name 'Flags' -Type String -Value '122'

log_msg "disable hotkeys AutoRotation"
reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null

log_msg "disable hotkeys language"
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3

# explorer restart
log_msg "explorer restart"
Stop-Process -ProcessName explorer -ea 0 | Out-Null