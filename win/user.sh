# ---------------------------------------
# win_user
# ---------------------------------------

# usage if [ "$(bh_win_user_check_admin)" == "True" ]; then <commands>; fi
function bh_win_user_check_admin() {
  powershell -c '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}
