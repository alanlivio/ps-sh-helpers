$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# load os_<name>.ps1 files

$scriptToLoad = Join-Path -Path $HELPERS_DIR -ChildPath "os_win.ps1"
. $scriptToLoad