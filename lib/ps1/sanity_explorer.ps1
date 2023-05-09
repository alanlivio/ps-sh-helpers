function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_msg_2nd () { Write-Host -ForegroundColor DarkYellow "-- >" ($args -join " ") }
New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -ea 0 | Out-Null
New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER  -ea 0 | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT   -ea 0 | Out-Null

log_msg "sanity file explorer"

#########################
# explorer behaviour
#########################
log_msg_2nd "explorer behaviour"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ea 0

log_msg_2nd "disable new drives autoplay"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1

log_msg_2nd "enable file explorer show extensions"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Value 0

log_msg_2nd "disable file explorer recent files "
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0


#########################
# sanity this PC
#########################
log_msg_2nd "sanity This PC"
$regs = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" # Documents
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" # Pictures
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" # Videos
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" # Downloads
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" # Music
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" # Desktop
)
foreach ($name in $regs) {
  if (Test-Path $name) {
    Set-ItemProperty -Path $name -Name "ThisPCPolicy " -Value "Hide"
  }
}

#########################
# explorer_restart
#########################
Stop-Process -ProcessName explorer -ea 0 | Out-Null