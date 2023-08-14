function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -ea 0 | Out-Null

log_msg "disable This PC folders"
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

# explorer_restart
Stop-Process -ProcessName explorer -ea 0 | Out-Null