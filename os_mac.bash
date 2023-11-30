# -- essentials --

function mac_install_brew() {
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_pkgs_install() {
    log_msg "brew install pkgs from var BH_PKGS_WINGET: $BH_PKGS_MAC_BREW"
    log_msg "brew install pkgs from var BH_PKGS_MAC_BREW: $BH_PKGS_MAC_BREW"
    brew install $BH_PKGS_MAC_BREW
}

function mac_update() {
    log_msg "brew upgrade all"
    brew update
    sudo brew upgrade
    log_msg "mac os upgrade"
    sudo softwareupdate -i -a
}
