function bh_setup_mac() {
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

function bh_update_clean_mac() {
  # brew
  bh_brew_install $PKGS_BREW
  bh_brew_upgrade
  # python
  bh_python_install $PKGS_PYTHON
  # vscode
  bh_vscode_install $PKGS_VSCODE
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

# ---------------------------------------
# ubuntu-on-mac helpers
# ---------------------------------------

function bh_mac_ubuntu_keyboard_fixes() {
  bh_log_func

  # enable fn keys
  echo -e 2 | sudo tee -a /sys/module/hid_apple/parameters/fnmode

  # configure layout
  # alternative: setxkbmap -layout us -variant intl
  gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'us+intl')]"

  grep -q cedilla /etc/environment
  if test $? != 0; then
    # fix cedilla
    echo -e "GTK_IM_MODULE=cedilla" | sudo tee -a /etc/environment
    echo -e "QT_IM_MODULE=cedilla" | sudo tee -a /etc/environment
    # enable fnmode
    echo -e "options hid_apple fnmode=2" | sudo tee -a /etc/modprobe.d/hid_apple.conf
    sudo update-setupramfs -u
  fi
}

function bh_mac_ubuntu_enable_wifi() {
  bh_log_func
  dpkg --status bcmwl-kernel-source &>/dev/null
  if test $? != 0; then
    sudo apt install -y bcmwl-kernel-source
    sudo modprobe -r b43 ssb wl brcmfmac brcmsmac bcma
    sudo modprobe wl
  fi
}
