# ---------------------------------------
# user
# ---------------------------------------

function bh_user_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then bh_test_and_create_folder /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function bh_user_passwd_disable_len_restriction() {
  sudo sed -i 's/sha512/minlen=1 sha512/g' /etc/pam.d/common-password
}

function bh_user_permissions_opt() {
  bh_log_func
  sudo chown -R root:root /opt
  sudo chmod -R 775 /opt/
  grep root /etc/group | grep $USER >/dev/null
  newgrp root
}

function bh_user_lang_set_en() {
  local line='export LANG="en_US.UTF-8"'
  if ! grep -Fxq "$line" $HOME/.bashrc; then
    echo -e 'export LANG="en_US.UTF-8"' >>$HOME/.bashrc
    echo -e 'export LC_ALL="en_US.UTF-8"' >>$HOME/.bashrc
  fi
}
