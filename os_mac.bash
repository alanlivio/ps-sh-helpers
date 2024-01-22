# -- essentials --


function mac_install_brew() {
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function mac_update() {
    _log_msg "brew upgrade all"
    brew update
    sudo brew upgrade
    _log_msg "mac os upgrade"
    sudo softwareupdate -i -a
}
