#########################
# basic
#########################

function mac_install_brew() {
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_update() {
  # update brew packages
  if type brew &>/dev/null && test -n "$BH_PKGS_MAC_BREW"; then
    log_msg "update brew packages: $BH_PKGS_MAC_BREW"
    brew install $BH_PKGS_MAC_BREW
    brew update
    sudo brew upgrade
  fi
  # update os packages
  log_msg "update mac packages"
  sudo softwareupdate -i -a
}
