# -- basic --

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_error() { Write-Host -ForegroundColor DarkRed "--" ($args -join " ") }
function passwd_generate { -join (1..12 | ForEach-Object { [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!?' | Get-Random }) }

# -- ps --

function ps_profile_reload() {
    # TODO: this does not work properly
    . $PROFILE.CurrentUserAllHosts
}

function ps_is_running_as_sudo { 
    ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ps_func_show($name) {
    Get-Content Function:\$name
}
