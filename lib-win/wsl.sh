# ---------------------------------------
# outside wsl helpers
# ---------------------------------------

function bh_wsl_root() {
  wsl -u root
}

function bh_wsl_list() {
  wsl -l -v
}

function bh_wsl_list_running() {
  wsl -l -v --running
}

bh_ps_def_func_admin bh_wsl_get_default
bh_ps_def_func_admin bh_wsl_terminate