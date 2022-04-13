function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function explorer_restart() {
  log "explorer_restart"
  taskkill /f /im explorer.exe | Out-Null
  Start-Process explorer.exe
}

function disable_ctx_menu_unused () {
  log "disable_ctx_menu_unused"
  if (!(Test-Path "HKCR:")) { 
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null 
  }
  $regs = @(
    # git
    "HKCR:\Directory\shell\git_gui"
    "HKCR:\Directory\shell\git_shell"
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\git_gui"
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\git_shell"
    # VLC
    "HKCR:\Directory\shell\AddToPlaylistVLC"
    "HKCR:\Directory\shell\PlayWithVLC"
    # include to library
    "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location"
    # Send to
    "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo"
    # Share with
    "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Sharing"
    "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing"
    "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing"
    "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing"
    # restore previous
    "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    "HKCR:\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{ 596AB062-B4D2-4215-9F74-E9109B0A8153}"
    "HKCR:\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    "HKCR:\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}"
    # pin to start
    "HKCR:\Folder\shellex\ContextMenuHandlers\PintoStartScreen"
    "HKCR:\exefile\shellex\ContextMenuHandlers\PintoStartScreen"
    "HKCR:\Microsoft.Website\ShellEx\ContextMenuHandlers\PintoStartScreen"
    "HKCR:\mscfile\shellex\ContextMenuHandlers\PintoStartScreen"
  )
  foreach ($name in $regs) {
    if (Test-Path $name) { Remove-Item -Path $name -Recurse }
  }
  explorer_restart
}

disable_ctx_menu_unused