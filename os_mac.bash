#########################
# basic
#########################

function mac_install_brew() {
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_update() {
  # update brew packages
  if type brew &>/dev/null && test -n "$BH_PKGS_MAC_BREW"; then
    log_msg "brew check installed BH_PKGS_MSYS2: $BH_PKGS_MSYS2"
    brew install $BH_PKGS_MAC_BREW
    log_msg "brew upgrade all"
    brew update
    sudo brew upgrade
  fi
  # update os packages
  log_msg "mac os upgrade"
  sudo softwareupdate -i -a
}
