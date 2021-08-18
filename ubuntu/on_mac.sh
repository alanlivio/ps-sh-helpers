# ---------------------------------------
# ubuntu_on_mac helpers
# ---------------------------------------

function bh_ubuntu_on_mac_keyboard_fixes() {
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

function bh_ubuntu_on_mac_enable_wifi() {
  bh_log_func
  dpkg --status bcmwl-kernel-source &>/dev/null
  if test $? != 0; then
    sudo apt install -y bcmwl-kernel-source
    sudo modprobe -r b43 ssb wl brcmfmac brcmsmac bcma
    sudo modprobe wl
  fi
}
