# ---------------------------------------
# setup/update_clean
# ---------------------------------------

function bh_update_clean_mac() {
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
  bh_python_install $BH_PKGS_PYTHON
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

function bh_install_mac_brew() {
  bh_log_func
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function bh_brew_install() {
  brew install "$@"
}

function bh_brew_upgrade() {
  brew update
  sudo brew upgrade
}
