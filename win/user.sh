# ---------------------------------------
# user
# ---------------------------------------

# usage if [ "$(bh_win_user_check_admin)" == "True" ]; then <commands>; fi
function bh_win_user_check_admin() {
  powershell -c '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}

# ---------------------------------------
# path helpers
# ---------------------------------------

function bh_win_path_show() {
  powershell -c '[Environment]::GetEnvironmentVariable("path", "user")'
}

function bh_win_env_add() {
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function bh_win_path_add() {
  local dir=$(winpath $1)
  ps_call ' 
    function bh_win_path_add($addPath) {
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
    }; bh_win_path_add '" $dir"
}

function bh_win_path_settings(){
  rundll32 sysdm.cpl,EditEnvironmentVariables
}
