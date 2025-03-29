# -- any OS --

$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_error() { Write-Host -ForegroundColor DarkRed "--" ($args -join " ") }
function passwd_generate { -join (1..12 | ForEach-Object { 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!?' | Get-Random }) }

# -- load os/<name>.ps1 files -- 

. "$HELPERS_DIR/os/win.ps1"

# -- load <program>.bash files --

# TODO: redo this code to load .bash if program exist. 
# make sure to create aliases for the windows .exe. Maybe do it at _sh_aliases_to_funcs_at_bash_file
# for file in "$HELPERS_DIR/programs/"*.bash; do
# program=$(basename ${file%.*})
# if type $program &>/dev/null; then
#     source $file
# fi
# end