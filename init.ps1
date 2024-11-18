$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# load os/<name>.ps1 files

$scriptToLoad = Join-Path -Path $HELPERS_DIR -ChildPath "os/win.ps1"
. $scriptToLoad

# -- load <program>.bash files --

# TODO


# -- load funcs from init.sh as aliases --

# TODO
# skip if exists