# ---------------------------------------
# sysupdate helpers
# ---------------------------------------

bh_ps_def_func_admin bh_win_sysupdate

function bh_win_sysupdate_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}
