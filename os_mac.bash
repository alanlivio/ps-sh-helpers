#########################
# basic
#########################

function mac_install_brew() {
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_brew_install() {
  brew install "$@"
}

function mac_brew_upgrade() {
  brew update
  sudo brew upgrade
}
