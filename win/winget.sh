# ---------------------------------------
# winget
# ---------------------------------------

function bh_winget_list_installed() {
  ps_lib_call '$(bh_winget_installed).Split()'
}

function bh_winget_list_installed_verbose() {
  winget list
}

function bh_winget_settings() {
  winget settings
}

function bh_winget_upgrade() {
  winget upgrade --all --silent
}
