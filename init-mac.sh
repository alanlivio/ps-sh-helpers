# ---------------------------------------
# mac aliases
# ---------------------------------------

function bh_open {
  local node="${1:-.}" # . is default value
  open $node
}

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_mac() {
  bh_log_func
  # update bh
  bh_bh_update_if_needed
  # brew
  bh_install_mac_brew
  local pkgs="git bash vim diffutils curl "
  pkgs+="python3 python-pip "
  bh_brew_upgrade
  bh_brew_install $pkgs $BH_MAC_BREW
  # py
  $HAS_PY && bh_py_install $BH_MAC_PY
  $HAS_PY && bh_py_upgrade
  # vscode
  brew install --cask visual-studio-code
  $HAS_VSCODE && bh_vscode_install $BH_MAC_VSCODE
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# brew
# ---------------------------------------

function bh_mac_install_brew() {
  bh_log_func
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function bh_mac_brew_install() {
  brew install "$@"
}

function bh_mac_brew_upgrade() {
  brew update
  sudo brew upgrade
}
