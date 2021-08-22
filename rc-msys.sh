# ---------------------------------------
# update_clean helper
# ---------------------------------------

function bh_update_clean_msys() {
  bh_log_func
  # essentials
  local pkgs="pacman pacman-mirrors msys2-runtime $BH_PKGS_ESSENTIALS"
  # python
  pkgs+="python-pip "
  bh_msys_install $pkgs
  # python
  bh_python_install $PKGS_PYTHON_MSYS
  bh_msys_upgrade
  # python
  bh_python_upgrade
  bh_python_install $PKGS_PYTHON_MSYS
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
}
