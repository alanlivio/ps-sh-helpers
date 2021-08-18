# ---------------------------------------
# winget helpers
# ---------------------------------------

function bh_win_get_list_installed() {
  ps_lib_call '$(bh_win_get_installed).Split()'
}

function bh_win_get_list_installed_verbose() {
  winget list
}

function bh_win_get_settings() {
  winget settings
}

function bh_win_get_upgrade() {
  winget upgrade --all --silent
}
