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
