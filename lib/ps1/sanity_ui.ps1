function log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_msg_2nd () { Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ") }
New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -ea 0 | Out-Null
New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER  -ea 0 | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT   -ea 0 | Out-Null

#########################
# taskbar
#########################
log_msg "sanity_taskbar"
log_msg_2nd "disable taskbar search button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0
log_msg_2nd "disable taskbar button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Value 0
log_msg_2nd "disable widgets"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "TaskbarDa" -Value 0

#########################
# dark mode and no effects
#########################
log_msg "dark and no effects"

log_msg_2nd "enable dark mode"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 00000000 /f | Out-Null

log_msg_2nd "disable system sounds"
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"

log_msg_2nd "set ui to performace"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name 'VisualFXSetting' -Value 2
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name 'EnableTransparency' -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0

#########################
# sanity keyboard
#########################
log_msg "sanity keyboard"

log_msg_2nd "disable Accessibility Keys Prompts"
New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name 'Flags' -Type String -Value '506'
New-Item -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name 'Flags' -Type String -Value '58'
New-Item -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name 'Flags' -Type String -Value '122'

log_msg_2nd "disable AutoRotation Hotkeys"
reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null

log_msg_2nd "disable shortcut lang"
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3

#########################
# explorer restart
#########################
log_msg "explorer restart"
Stop-Process -ProcessName explorer -ea 0 | Out-Null