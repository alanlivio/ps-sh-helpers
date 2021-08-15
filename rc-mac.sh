# ---------------------------------------
# setup/update_clean functions
# ---------------------------------------

function bh_mac_setup() {
  bh_log_func
  bh_user_permissions_sudo_nopasswd
  bh_mac_install_brew
  bh_brew_upgrade
  # essentials
  PKGS="git bash $PKGS_ESSENTIALS "
  # python
  PKGS+="python python-pip "
  bh_brew_install $PKGS
  # install vscode
  sudo brew install --cask visual-studio-code
}

function bh_mac_update_clean() {
  # brew
  bh_brew_upgrade
  bh_brew_install $PKGS_BREW
  # python
  bh_python_install $PKGS_PYTHON
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# brew functions
# ---------------------------------------

function bh_mac_install_brew() {
  bh_log_func
  sudo /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function bh_brew_install() {
  sudo brew install "$@"
}

function bh_brew_upgrade() {
  sudo brew update
  sudo brew upgrade
}
