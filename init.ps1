$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# -- powershell basic --

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_error() { Write-Host -ForegroundColor DarkRed "--" ($args -join " ") }
function passwd_generate() {
    $length = 12
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!?'
    $password = -join (1..$length | ForEach-Object { Get-Random -Maximum $characters.length | ForEach-Object { $characters[$_] } })
    Write-Output $password
}

# -- load os/<name>.ps1 files -- 

$scriptToLoad = Join-Path -Path $HELPERS_DIR -ChildPath "os/win.ps1"
. $scriptToLoad

# -- load <program>.bash files --

# TODO

# -- load funcs from init.sh as aliases --

# TODO
# skip if exists