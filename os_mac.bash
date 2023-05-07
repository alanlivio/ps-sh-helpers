#########################
# basic
#########################

function mac_install_brew() {
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_update() {
  brew update
  sudo brew upgrade
}
