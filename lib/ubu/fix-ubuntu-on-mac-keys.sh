function fix_ubuntu_on_mac_keys() {

  # enable fn keys
  echo -e 2 | sudo tee -a /sys/module/hid_apple/parameters/fnmode

  # configure layout
  # alternative: setxkbmap -layout us -variant intl
  gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'us+intl')]"

  # fix cedilla
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
