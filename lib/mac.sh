function hf_setup_mac() {
  hf_log_func
  hf_user_permissions_sudo_nopasswd
  hf_mac_install_brew
  hf_brew_upgrade
  # essentials
  PKGS="git bash $PKGS_ESSENTIALS "
  # python
  PKGS+="python python-pip "
  hf_brew_install $PKGS
  # install vscode
  sudo brew install --cask visual-studio-code
}

function hf_update_clean_mac() {
  # brew
  hf_brew_install $PKGS_BREW
  hf_brew_upgrade
  # python
  hf_python_install $PKGS_PYTHON
  # vscode
  hf_vscode_install $PKGS_VSCODE
}

# ---------------------------------------
# brew functions
# ---------------------------------------

function hf_mac_install_brew() {
  hf_log_func
  sudo /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
}

function hf_brew_install() {
  sudo brew install "$@"
}

function hf_brew_upgrade() {
  sudo brew update
  sudo brew upgrade
}

# ---------------------------------------
# ubuntu-on-mac funcs
# ---------------------------------------

function hf_mac_ubuntu_keyboard_fixes() {
  hf_log_func

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

function hf_mac_ubuntu_enable_wifi() {
  hf_log_func
  dpkg --status bcmwl-kernel-source &>/dev/null
  if test $? != 0; then
    sudo apt install -y bcmwl-kernel-source
    sudo modprobe -r b43 ssb wl brcmfmac brcmsmac bcma
    sudo modprobe wl
  fi
}
