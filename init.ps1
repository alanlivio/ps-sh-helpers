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

# TODO: redo this code to load .bash if program exist. 
# make sure to create aliases for the windows .exe. Maybe do it at _sh_aliases_to_funcs_at_bash_file
# for file in "$HELPERS_DIR/programs/"*.bash; do
# program=$(basename ${file%.*})
# if type $program &>/dev/null; then
#     source $file
# fi
# end

# TODO
# skip if exists