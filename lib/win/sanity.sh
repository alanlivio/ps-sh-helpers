# ---------------------------------------
# sanity
# ---------------------------------------

function bh_win_sanity() {
  ps_call_script $(unixpath -w $BH_DIR/lib/win/sanity.ps1)
}

function bh_win_sanity_ctx_menu() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/win/sanity-cxt-menu.ps1)
}

function bh_win_sanity_services() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/win/sanity-services.ps1)
}

function bh_win_sanity_password_policy() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/win/sanity-password-policy.ps1)
}

function bh_win_sanity_this_pc() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/win/sanity-this-pc.ps1)
}

function bh_win_sanity_all() {
  bh_win_sanity
  bh_win_sanity_ctx_menu
  bh_win_sanity_this_pc
  bh_win_sanity_password_policy
  bh_win_sanity_services
}
