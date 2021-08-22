# ---------------------------------------
# user
# ---------------------------------------

# usage if [ "$(bh_user_win_check_admin)" == "True" ]; then <commands>; fi
function bh_user_win_check_admin() {
  powershell.exe -c '
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $group = "Administrators"
    (Get-LocalGroupMember $group).Name -contains $user
  '
}

function bh_user_win_check_eleveated_shell() {
  powershell.exe -c '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}

# ---------------------------------------
# path
# ---------------------------------------

function bh_path_win_show() {
  powershell.exe -c '[Environment]::GetEnvironmentVariable("path", "user")'
}

function bh_env_win_add() {
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function bh_path_win_add() {
  local dir=$(winpath $1)
  ps_call ' 
    function bh_path_win_add($addPath) {
      if (Test-Path $addPath) {
        $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
        $regexAddPath = [regex]::Escape($addPath)
        $arrPath = $currentpath -split ";" | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
        $newpath = ($arrPath + $addPath) -join ";" + ";"
        [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
      }
      else {
        Throw "$addPath is not a valid path."
      }
    }; bh_path_win_add '" $dir"
}

function bh_path_win_settings() {
  rundll32 sysdm.cpl,EditEnvironmentVariables
}
