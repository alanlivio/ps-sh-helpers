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
  # essentials
  bh_install_mac_brew
  local pkgs="git bash vim diffutils curl "
  # python
  pkgs+="python python-pip "
  bh_brew_install $pkgs
  # brew
  bh_brew_upgrade
  bh_brew_install $BH_PKGS_BREW
  # python
  bh_py_install $BH_PKGS_PY
  # vscode
  if type code &>/dev/null; then
    brew install --cask visual-studio-code
  fi
  bh_vscode_install $BH_PKGS_VSCODE
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
